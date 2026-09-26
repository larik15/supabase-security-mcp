// Policy audit. Two layers:
//   - analyze*() are pure functions over plain rows (unit-testable, no DB)
//   - auditPolicies() runs the SQL against Postgres via `pg` and feeds analyze*()

import { readFileSync } from "node:fs";

// Every relation PostgREST can expose from public: tables, partitioned tables, views,
// materialized views, foreign tables. Privileges come from has_*_privilege (which
// resolves role membership and PUBLIC grants) rather than information_schema, which
// only lists direct grants and hides column-level ones.
const SQL_TABLES = `
select n.nspname as schema, c.relname as table, c.relkind as relkind,
       c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced,
       coalesce((select lower(o.option_value) in ('true','on','1','yes')
                 from pg_options_to_table(c.reloptions) o where o.option_name = 'security_invoker'), false) as security_invoker,
       has_table_privilege('anon', c.oid, 'SELECT') as anon_select,
       has_table_privilege('anon', c.oid, 'INSERT,UPDATE,DELETE') as anon_write,
       has_table_privilege('authenticated', c.oid, 'SELECT') as auth_select,
       has_table_privilege('authenticated', c.oid, 'INSERT,UPDATE,DELETE') as auth_write,
       has_any_column_privilege('anon', c.oid, 'SELECT,INSERT,UPDATE') as anon_any_column,
       has_any_column_privilege('authenticated', c.oid, 'SELECT,INSERT,UPDATE') as auth_any_column
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p','v','m','f') and n.nspname = 'public'
order by c.relname;`;

const SQL_POLICIES = `
select schemaname as schema, tablename as table, policyname as policy, permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public' or (schemaname = 'storage' and tablename = 'objects')
order by schemaname, tablename, policyname;`;

// Plain functions only: procedures, aggregates and trigger functions can't be called
// through PostgREST's /rpc, so their SECURITY DEFINER status isn't an API exposure.
const SQL_FUNCTIONS = `
select p.proname as name,
       pg_get_function_identity_arguments(p.oid) as args,
       p.prokind as prokind,
       (p.prorettype = 'trigger'::regtype) as returns_trigger,
       p.prosecdef as security_definer,
       p.proconfig as proconfig,
       has_function_privilege('anon', p.oid, 'EXECUTE') as anon_can_execute,
       has_function_privilege('authenticated', p.oid, 'EXECUTE') as authenticated_can_execute
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.prokind = 'f' and p.prorettype <> 'trigger'::regtype
order by p.proname;`;

const SQL_HAS_STORAGE = `select to_regclass('storage.buckets') is not null as has_storage;`;
const SQL_BUCKETS = `select id, name, public from storage.buckets order by name;`;

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function normRoles(roles) {
  if (Array.isArray(roles)) return roles.map(String);
  if (typeof roles === "string") return roles.replace(/[{}]/g, "").split(",").map((s) => s.trim()).filter(Boolean);
  return [];
}

/** Strip one pair of parentheses only if they wrap the whole expression. */
function stripOuterParens(s) {
  for (;;) {
    if (!s.startsWith("(") || !s.endsWith(")")) return s;
    let depth = 0;
    for (let i = 0; i < s.length; i++) {
      if (s[i] === "(") depth++;
      else if (s[i] === ")") depth--;
      if (depth === 0 && i < s.length - 1) return s; // closes before the end: not a wrapper
    }
    s = s.slice(1, -1).trim();
  }
}

/** Lowercase, collapse whitespace, tidy parens, drop wrapping parens. */
export function normExpr(expr) {
  if (expr == null) return null;
  const s = String(expr).toLowerCase().replace(/\s+/g, " ").replace(/\(\s+/g, "(").replace(/\s+\)/g, ")").trim();
  return stripOuterParens(s);
}

// pg_policies deparses (select true) as "( SELECT true AS bool)".
const OPEN_EXACT = [/^true$/, /^1 ?= ?1$/, /^select true(?: as \w+)?$/];
const AUTH_CALL = String.raw`\(?(?:select )?auth\.(?:uid|jwt|email)\(\)(?: as \w+)?\)?`;
const AUTH_NOT_NULL = new RegExp(`${AUTH_CALL} is not null`, "g");
const AUTH_ONLY_EXACT = [
  new RegExp(`^${AUTH_CALL} is not null$`),
  /^\(?(?:select )?auth\.role\(\)(?: as \w+)?\)? = 'authenticated'(?:::text)?$/,
];

/** Does the expression reference the caller's identity (auth.uid/jwt/email, request.jwt claims)? */
export function hasAuthRef(expr) {
  if (expr == null) return false;
  const s = String(expr).toLowerCase();
  return /auth\.(uid|jwt|email)\(\)/.test(s) || /current_setting\(\s*'request\.jwt/.test(s);
}

/**
 * Classify a policy expression:
 *   "none"               null (clause absent)
 *   "open"               true, (true), 1=1, (select true), anything `or true`
 *   "authenticated_only" auth.uid() is not null, auth.role() = 'authenticated', auth.jwt() is not null
 *   "ownership"          references the caller's identity beyond an `is not null` test
 *   "other"              anything else (a status filter, a membership function, ...)
 */
export function classifyExpr(expr) {
  const s = normExpr(expr);
  if (s == null) return "none";
  if (OPEN_EXACT.some((re) => re.test(s)) || /\bor \(*true\)*(?=$|\)| or | and )/.test(s)) return "open";
  if (AUTH_ONLY_EXACT.some((re) => re.test(s))) return "authenticated_only";
  // `auth.uid() is not null` only proves the caller is logged in; it isn't ownership.
  if (hasAuthRef(s.replace(AUTH_NOT_NULL, ""))) return "ownership";
  return "other";
}

function isRestrictive(p) {
  return p.permissive === false || String(p.permissive).toUpperCase() === "RESTRICTIVE";
}

function relLabel(schema, table) {
  return `${schema || "public"}.${table}`;
}

/**
 * @param {Array<{schema?:string,table:string,relkind?:string,rls_enabled:boolean,security_invoker?:boolean,
 *   anon_select?:boolean,anon_write?:boolean,auth_select?:boolean,auth_write?:boolean,
 *   anon_any_column?:boolean,auth_any_column?:boolean}>} tables
 */
export function analyzeTables(tables) {
  const findings = [];
  for (const t of tables) {
    const kind = t.relkind || "r";
    const name = relLabel(t.schema, t.table);
    const readers = [
      (t.anon_select || t.anon_any_column) && "anon",
      (t.auth_select || t.auth_any_column) && "authenticated",
    ].filter(Boolean);
    const exposed = readers.length > 0 || t.anon_write || t.auth_write;

    if (kind === "r" || kind === "p") {
      if (!t.rls_enabled && exposed) {
        findings.push({
          severity: "critical", kind: "rls_disabled", table: t.table,
          message: `RLS is disabled on ${name} and anon/authenticated have privileges on it — every row is readable/writable through the API.`,
          fix: `alter table ${name} enable row level security; then add policies.`,
        });
      } else if (!t.rls_enabled) {
        findings.push({
          severity: "info", kind: "rls_disabled_unexposed", table: t.table,
          message: `RLS is disabled on ${name} but anon/authenticated have no privileges on it; not reachable via the API today, still worth enabling.`,
          fix: `alter table ${name} enable row level security;`,
        });
      }
    } else if (kind === "v" && readers.length && !t.security_invoker) {
      findings.push({
        severity: "high", kind: "view_without_security_invoker", table: t.table,
        message: `View ${name} is readable by [${readers.join(", ")}] and has no security_invoker, so it runs with its owner's privileges — RLS on the underlying tables is checked as the owner (usually postgres, which bypasses it), not the caller.`,
        fix: `alter view ${name} set (security_invoker = true); (Postgres 15+), or revoke select on ${name} from ${readers.join(", ")}.`,
      });
    } else if (kind === "m" && exposed) {
      findings.push({
        severity: "high", kind: "materialized_view_exposed", table: t.table,
        message: `Materialized view ${name} is accessible to [${readers.join(", ") || "anon/authenticated"}]. Materialized views don't support RLS, so every row in it is visible.`,
        fix: `revoke all on ${name} from anon, authenticated; expose it through a security_invoker view or a function with its own checks.`,
      });
    } else if (kind === "f" && exposed) {
      findings.push({
        severity: "high", kind: "foreign_table_exposed", table: t.table,
        message: `Foreign table ${name} is accessible to [${readers.join(", ") || "anon/authenticated"}]. Foreign tables don't support RLS, so the remote data is readable through the API.`,
        fix: `revoke all on ${name} from anon, authenticated; or move it out of an exposed schema.`,
      });
    }
  }
  return findings;
}

/**
 * All issues found on one policy. Each issue: { kind, severity, text, fix }.
 * Restrictive policies can only narrow access, so they're never "open"; the caller
 * lists them separately instead.
 */
function policyIssues(p) {
  const roles = normRoles(p.roles);
  const isPublicRole = roles.length === 0 || roles.includes("public");
  const appliesToClients = isPublicRole || roles.includes("anon") || roles.includes("authenticated");
  if (!appliesToClients) return []; // e.g. TO service_role: bypasses RLS anyway, harmless

  const isStorage = p.schema === "storage";
  const cmd = String(p.cmd || "ALL").toUpperCase();
  const reads = cmd === "SELECT" || cmd === "ALL";
  const writes = cmd === "UPDATE" || cmd === "DELETE" || cmd === "ALL";
  const inserts = cmd === "INSERT" || cmd === "ALL";
  const qual = classifyExpr(p.qual);
  // For UPDATE/ALL, a missing with check means Postgres reuses using.
  const check = classifyExpr(p.with_check ?? ((cmd === "UPDATE" || cmd === "ALL") ? p.qual : null));
  const who = isPublicRole ? "PUBLIC (including anon)" : roles.join(", ");
  const issues = [];
  const openKind = (k) => (isStorage ? "storage_policy_open" : k);

  if (reads && qual === "open") {
    issues.push({
      kind: openKind("policy_open_read"), severity: "high",
      text: isStorage ? `anyone in ${who} can list and download objects in every bucket` : `every row is readable by ${who}`,
      fix: isStorage ? "Scope the select policy, e.g. using (bucket_id = 'public-assets') or using (owner = auth.uid())." : "Replace using (true) with an ownership check, e.g. using (auth.uid() = user_id).",
    });
  }
  if (writes && qual === "open") {
    issues.push({
      kind: openKind("policy_open_write"), severity: "critical",
      text: `any row can be ${cmd === "DELETE" ? "deleted" : cmd === "UPDATE" ? "modified" : "modified or deleted"} by ${who}`,
      fix: isStorage ? "Scope using to the object owner, e.g. using (owner = auth.uid())." : "Use using (auth.uid() = user_id) (and a matching with check for UPDATE).",
    });
  }
  if (inserts && check === "open") {
    issues.push({
      kind: openKind("policy_open_insert"), severity: "high",
      text: isStorage ? `${who} can upload anything into any bucket` : `${who} can insert arbitrary rows, including rows owned by someone else`,
      fix: isStorage
        ? "Scope with check, e.g. with check (bucket_id = 'uploads' and owner = auth.uid())."
        : "Use with check (auth.uid() = user_id) so users can only insert rows they own — unless this table is meant for anonymous submissions (contact forms, waitlists).",
    });
  }
  if ((reads && qual === "authenticated_only") || (writes && qual === "authenticated_only") || (inserts && check === "authenticated_only")) {
    const what = [
      reads && qual === "authenticated_only" && "read",
      writes && qual === "authenticated_only" && (cmd === "DELETE" ? "delete" : cmd === "UPDATE" ? "update" : "update/delete"),
      inserts && check === "authenticated_only" && "insert",
    ].filter(Boolean);
    issues.push({
      kind: "policy_open_to_all_authenticated",
      severity: writes && qual === "authenticated_only" ? "critical" : "high",
      text: `any logged-in user can ${what.join(" and ")} every row — "is logged in" is checked, ownership isn't`,
      fix: "Compare the caller to the row, e.g. auth.uid() = user_id, instead of auth.uid() is not null / auth.role() = 'authenticated'.",
    });
  }
  if ((cmd === "UPDATE" || cmd === "ALL") && p.with_check != null && classifyExpr(p.with_check) === "open" && qual === "ownership") {
    issues.push({
      kind: "policy_check_broader_than_using", severity: "high",
      text: "using checks ownership but with check is open, so an owner can rewrite a row to belong to someone else",
      fix: "Make with check match using, e.g. with check (auth.uid() = user_id).",
    });
  }
  if (isPublicRole) {
    const relevant = [reads || writes ? qual : null, inserts ? check : null].filter((c) => c && c !== "none");
    const anyOpen = relevant.includes("open");
    const allSafe = relevant.length > 0 && relevant.every((c) => c === "ownership" || c === "authenticated_only");
    issues.push(
      anyOpen
        ? { kind: "policy_no_to_clause", severity: "high", text: "has no TO clause, so it applies to PUBLIC — including anon", fix: 'Recreate it with an explicit "to authenticated" (or "to anon" if anonymous access is intended).' }
        : allSafe
          ? { kind: "policy_no_to_clause", severity: "info", text: "applies to PUBLIC; safe here because the expression fails for anon, but make it explicit", fix: 'Recreate it with "to authenticated".' }
          : { kind: "policy_no_to_clause", severity: "medium", text: "has no TO clause, so it applies to PUBLIC — including anon — with an expression that doesn't check the caller; make sure anonymous visitors are meant to match it", fix: 'Recreate it with an explicit "to authenticated" or "to anon".' }
    );
  }
  return issues;
}

/**
 * One finding per policy, listing all its issues; severity is the worst of them.
 * @param {Array<{schema?:string,table:string,policy:string,permissive?:string|boolean,roles:any,cmd:string,qual:string|null,with_check:string|null}>} policies
 * @param {Array<{schema?:string,table:string,relkind?:string,rls_enabled:boolean}>} [tables]
 * @returns {{ findings: object[], restrictive: object[] }}
 */
export function analyzePolicies(policies, tables = []) {
  const findings = [];
  const restrictive = [];
  const withPolicies = new Set();

  for (const p of policies) {
    const schema = p.schema || "public";
    withPolicies.add(relLabel(schema, p.table));
    if (isRestrictive(p)) {
      restrictive.push({ schema, table: p.table, policy: p.policy, cmd: p.cmd, roles: normRoles(p.roles), qual: p.qual, with_check: p.with_check });
      continue;
    }
    const issues = policyIssues({ ...p, schema });
    if (!issues.length) continue;
    const worst = [...issues].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])[0];
    const cmd = String(p.cmd || "ALL").toUpperCase();
    findings.push({
      severity: worst.severity,
      kind: worst.kind,
      issues: issues.map((i) => i.kind),
      table: schema === "public" ? p.table : relLabel(schema, p.table),
      policy: p.policy,
      message: `Policy "${p.policy}" on ${relLabel(schema, p.table)} (${cmd}): ${issues.map((i) => i.text).join("; ")}.`,
      fix: [...new Set(issues.map((i) => i.fix))].join(" "),
    });
  }

  for (const t of tables) {
    const kind = t.relkind || "r";
    if ((kind === "r" || kind === "p") && t.rls_enabled && !withPolicies.has(relLabel(t.schema, t.table))) {
      findings.push({
        severity: "info", kind: "rls_no_policies", table: t.table,
        message: `${relLabel(t.schema, t.table)} has RLS enabled and no policies — closed to everyone except the service role. Fine if intentional.`,
        fix: "Add policies only if the client needs access.",
      });
    }
  }
  return { findings, restrictive };
}

/** @param {Array<{id:string,name:string,public:boolean}>} buckets */
export function analyzeBuckets(buckets = []) {
  return buckets.filter((b) => b.public).map((b) => ({
    severity: "info", kind: "storage_bucket_public", table: `storage.buckets/${b.id}`,
    message: `Storage bucket "${b.name}" is public: anyone with an object's URL can download it, whatever the storage.objects policies say (listing still goes through them).`,
    fix: `Fine for public assets. For anything else: update storage.buckets set public = false where id = '${b.id}'; and serve files through signed URLs.`,
  }));
}

function hasSearchPath(proconfig) {
  return Array.isArray(proconfig) && proconfig.some((c) => String(c).toLowerCase().startsWith("search_path"));
}

/**
 * @param {Array<{name:string,args:string,prokind?:string,returns_trigger?:boolean,security_definer:boolean,
 *   proconfig:string[]|null,anon_can_execute:boolean,authenticated_can_execute:boolean}>} fns
 */
export function analyzeFunctions(fns) {
  const findings = [];
  for (const f of fns) {
    if (!f.security_definer) continue;
    if ((f.prokind && f.prokind !== "f") || f.returns_trigger) continue;
    const sig = `public.${f.name}(${f.args})`;
    const who = [f.anon_can_execute && "anon", f.authenticated_can_execute && "authenticated"].filter(Boolean);
    if (who.length) {
      findings.push({
        severity: f.anon_can_execute ? "high" : "medium", kind: "definer_function_exposed", table: null, function: `${f.name}(${f.args})`,
        message: `Function ${sig} is SECURITY DEFINER — it runs with the owner's privileges (bypasses RLS if the owner is postgres/BYPASSRLS) — and is executable by [${who.join(", ")}] via /rpc.`,
        fix: `Check the caller inside the function (auth.uid() and ownership of whatever it touches), or revoke execute on function ${sig} from ${who.join(", ")}.`,
      });
    }
    if (!hasSearchPath(f.proconfig)) {
      findings.push({
        severity: "medium", kind: "definer_function_no_search_path", table: null, function: `${f.name}(${f.args})`,
        message: `Function ${sig} is SECURITY DEFINER without a pinned search_path — a caller who can create objects in a schema earlier on the path can make it resolve their table or function instead.`,
        fix: `alter function ${sig} set search_path = ''; and schema-qualify every name inside the body (public.orders, auth.uid(), ...).`,
      });
    }
  }
  return findings;
}

// ---------- live connection ----------

const TLS_ERROR_CODES = new Set([
  "SELF_SIGNED_CERT_IN_CHAIN", "DEPTH_ZERO_SELF_SIGNED_CERT", "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "CERT_HAS_EXPIRED",
  "CERT_UNTRUSTED", "ERR_TLS_CERT_ALTNAME_INVALID",
]);

function isLocalHost(host) {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

/**
 * Remove ssl* parameters from the connection string: pg lets them override the `ssl`
 * object we build, and `sslmode=require`/`no-verify` would silently turn off
 * certificate verification. TLS is configured only through caCert / PGSSLROOTCERT.
 */
export function stripSslParams(databaseUrl) {
  const u = new URL(databaseUrl);
  for (const k of [...u.searchParams.keys()]) if (/^ssl/i.test(k)) u.searchParams.delete(k);
  return u.toString();
}

/**
 * The `ssl` option for pg. Verifies the certificate unless `insecureSkipTlsVerify`.
 * @returns {{ ssl: false | object, tls: "verified-ca" | "verified-system" | "UNVERIFIED" | "none-local" }}
 */
export function buildSsl(databaseUrl, { caCert, insecureSkipTlsVerify } = {}, { env = process.env, readFile = readFileSync } = {}) {
  const host = new URL(databaseUrl).hostname;
  if (isLocalHost(host)) return { ssl: false, tls: "none-local" };
  if (insecureSkipTlsVerify) {
    console.error(
      "[supabase-security-mcp] WARNING: TLS certificate verification is DISABLED for this audit_policies connection " +
        `(insecureSkipTlsVerify: true) to ${host}. Anyone on the network path can impersonate the database and read the password. Local development only.`
    );
    return { ssl: { rejectUnauthorized: false }, tls: "UNVERIFIED" };
  }
  let ca = caCert;
  if (!ca && env.PGSSLROOTCERT) {
    try {
      ca = readFile(env.PGSSLROOTCERT, "utf8");
    } catch (e) {
      throw new Error(`PGSSLROOTCERT=${env.PGSSLROOTCERT} could not be read: ${e.message}`);
    }
  }
  return { ssl: ca ? { rejectUnauthorized: true, ca } : { rejectUnauthorized: true }, tls: ca ? "verified-ca" : "verified-system" };
}

function tlsHelp(host, err) {
  return new Error(
    `TLS certificate verification failed for ${host}: ${err.message}. ` +
      `Supabase's Postgres uses its own certificate authority, which isn't in the system trust store. ` +
      `Download it from Supabase → Project Settings → Database → SSL Configuration (prod-ca-2021.crt), then either ` +
      `set PGSSLROOTCERT=/path/to/prod-ca-2021.crt in the MCP server env, or pass its PEM contents as the caCert argument. ` +
      `For local development only, insecureSkipTlsVerify: true skips verification.`
  );
}

/**
 * Run the full policy audit against a live database.
 * @param {string} databaseUrl  postgres:// connection string (Supabase → Project Settings → Database)
 * @param {{ Client?: any, env?: object, readFile?: Function }} [deps]  injectables for tests
 * @param {{ caCert?: string, insecureSkipTlsVerify?: boolean }} [opts]
 */
export async function auditPolicies(databaseUrl, deps = {}, opts = {}) {
  let Client = deps.Client;
  if (!Client) {
    const pg = await import("pg");
    Client = pg.default?.Client ?? pg.Client;
  }
  const { ssl, tls } = buildSsl(databaseUrl, opts, deps);
  const host = new URL(databaseUrl).hostname;
  const client = new Client({ connectionString: stripSslParams(databaseUrl), ssl });
  try {
    await client.connect();
  } catch (err) {
    if (TLS_ERROR_CODES.has(err.code) || /certificate/i.test(err.message || "")) throw tlsHelp(host, err);
    throw err;
  }
  try {
    // one client, sequential queries (pg forbids overlapping queries on a single client)
    const tables = await client.query(SQL_TABLES);
    const policies = await client.query(SQL_POLICIES);
    const fns = await client.query(SQL_FUNCTIONS);
    const hasStorage = (await client.query(SQL_HAS_STORAGE)).rows[0]?.has_storage;
    const buckets = hasStorage ? (await client.query(SQL_BUCKETS)).rows : [];
    const pol = analyzePolicies(policies.rows, tables.rows);
    const findings = [
      ...analyzeTables(tables.rows),
      ...pol.findings,
      ...analyzeFunctions(fns.rows),
      ...analyzeBuckets(buckets),
    ];
    return {
      tls,
      tables: tables.rows,
      policies: policies.rows,
      restrictivePolicies: pol.restrictive,
      functions: fns.rows.filter((f) => f.security_definer),
      buckets,
      findings,
    };
  } finally {
    await client.end();
  }
}

export const SQL = { SQL_TABLES, SQL_POLICIES, SQL_FUNCTIONS, SQL_HAS_STORAGE, SQL_BUCKETS };
