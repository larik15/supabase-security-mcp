// Policy audit. Two layers:
//   - analyze*() are pure functions over plain rows (unit-testable, no DB)
//   - auditPolicies() runs the SQL against Postgres via `pg` and feeds analyze*()

const SQL_TABLES = `
select n.nspname as schema, c.relname as table, c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p') and n.nspname = 'public'
order by c.relname;`;

const SQL_POLICIES = `
select schemaname as schema, tablename as table, policyname as policy, permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public'
order by tablename, policyname;`;

// Functions in public that are SECURITY DEFINER, plus whether anon/authenticated may execute them.
const SQL_FUNCTIONS = `
select p.proname as name,
       pg_get_function_identity_arguments(p.oid) as args,
       p.prosecdef as security_definer,
       has_function_privilege('anon', p.oid, 'EXECUTE') as anon_can_execute,
       has_function_privilege('authenticated', p.oid, 'EXECUTE') as authenticated_can_execute
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
order by p.proname;`;

// Grants on public tables to anon/authenticated (RLS only matters if the role has table privileges).
const SQL_GRANTS = `
select table_name as table, grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and grantee in ('anon','authenticated')
order by table_name, grantee, privilege_type;`;

function normRoles(roles) {
  if (Array.isArray(roles)) return roles.map(String);
  if (typeof roles === "string") return roles.replace(/[{}]/g, "").split(",").map(s => s.trim()).filter(Boolean);
  return [];
}

function isTrueExpr(expr) {
  if (expr == null) return false;
  const s = String(expr).trim().toLowerCase().replace(/^\(+|\)+$/g, "");
  return s === "true";
}

/**
 * @param {Array<{schema:string,table:string,rls_enabled:boolean,rls_forced:boolean}>} tables
 * @param {Array<{table:string,grantee:string,privilege_type:string}>} grants
 */
export function analyzeTables(tables, grants = []) {
  const findings = [];
  const grantMap = new Map();
  for (const g of grants) {
    const k = g.table;
    if (!grantMap.has(k)) grantMap.set(k, new Set());
    grantMap.get(k).add(`${g.grantee}:${g.privilege_type}`);
  }
  for (const t of tables) {
    const g = grantMap.get(t.table) || new Set();
    const exposed = [...g].some(x => x.startsWith("anon:") || x.startsWith("authenticated:"));
    if (!t.rls_enabled && exposed) {
      findings.push({
        severity: "critical", kind: "rls_disabled", table: t.table,
        message: `RLS is disabled on public.${t.table} and anon/authenticated have table grants — every row is readable/writable through the API.`,
        fix: `alter table public.${t.table} enable row level security; then add policies.`,
      });
    } else if (!t.rls_enabled) {
      findings.push({
        severity: "info", kind: "rls_disabled_unexposed", table: t.table,
        message: `RLS is disabled on public.${t.table} but anon/authenticated have no grants; not reachable via REST today, still worth enabling.`,
        fix: `alter table public.${t.table} enable row level security;`,
      });
    }
  }
  return findings;
}

/**
 * @param {Array<{table:string,policy:string,permissive:string|boolean,roles:any,cmd:string,qual:string|null,with_check:string|null}>} policies
 * @param {Array<{table:string,rls_enabled:boolean}>} tables
 */
export function analyzePolicies(policies, tables = []) {
  const findings = [];
  const withPolicies = new Set();
  for (const p of policies) {
    withPolicies.add(p.table);
    const roles = normRoles(p.roles);
    const isPublicRole = roles.length === 0 || roles.includes("public");
    const cmd = String(p.cmd || "ALL").toUpperCase();
    const qualTrue = isTrueExpr(p.qual);
    const checkTrue = isTrueExpr(p.with_check);
    const isWrite = cmd === "ALL" || cmd === "INSERT" || cmd === "UPDATE" || cmd === "DELETE";

    if (isPublicRole) {
      findings.push({
        severity: isWrite ? "high" : "medium", kind: "policy_no_to_clause", table: p.table, policy: p.policy,
        message: `Policy "${p.policy}" on public.${p.table} (${cmd}) has no TO clause, so it applies to PUBLIC — including anon — regardless of what its name says.`,
        fix: `Recreate the policy with an explicit "to authenticated" (or "to anon" if intended).`,
      });
    }

    if ((cmd === "SELECT" || cmd === "ALL") && qualTrue) {
      findings.push({
        severity: roles.includes("anon") || isPublicRole ? "high" : "medium", kind: "policy_open_read", table: p.table, policy: p.policy,
        message: `Policy "${p.policy}" on public.${p.table} allows ${cmd} with using (true) for roles [${roles.join(", ") || "public"}] — every row is readable.`,
        fix: `Replace with an ownership check, e.g. using (auth.uid() = user_id), or restrict to the role that really needs it.`,
      });
    }

    if ((cmd === "INSERT" || cmd === "ALL") && checkTrue) {
      findings.push({
        severity: "high", kind: "policy_open_insert", table: p.table, policy: p.policy,
        message: `Policy "${p.policy}" on public.${p.table} allows INSERT with with check (true) for [${roles.join(", ") || "public"}] — anyone in that role can write arbitrary rows.`,
        fix: `Use with check (auth.uid() = user_id) so users can only insert rows they own.`,
      });
    }

    if ((cmd === "UPDATE" || cmd === "DELETE" || cmd === "ALL") && qualTrue) {
      findings.push({
        severity: "critical", kind: "policy_open_write", table: p.table, policy: p.policy,
        message: `Policy "${p.policy}" on public.${p.table} allows ${cmd} with using (true) for [${roles.join(", ") || "public"}] — any row can be modified or deleted.`,
        fix: `Add using (auth.uid() = user_id) (and with check for UPDATE).`,
      });
    }
  }

  for (const t of tables) {
    if (t.rls_enabled && !withPolicies.has(t.table)) {
      findings.push({
        severity: "info", kind: "rls_no_policies", table: t.table,
        message: `public.${t.table} has RLS enabled and no policies — closed to everyone except service role. Fine if intentional.`,
        fix: `Add policies only if the client needs access.`,
      });
    }
  }
  return findings;
}

/**
 * @param {Array<{name:string,args:string,security_definer:boolean,anon_can_execute:boolean,authenticated_can_execute:boolean}>} fns
 */
export function analyzeFunctions(fns) {
  const findings = [];
  for (const f of fns) {
    if (!f.security_definer) continue;
    const who = [f.anon_can_execute && "anon", f.authenticated_can_execute && "authenticated"].filter(Boolean);
    if (who.length) {
      findings.push({
        severity: f.anon_can_execute ? "high" : "medium", kind: "definer_function_exposed", table: null, function: `${f.name}(${f.args})`,
        message: `Function public.${f.name}(${f.args}) runs as SECURITY DEFINER (bypasses RLS) and is executable by [${who.join(", ")}].`,
        fix: `Add an explicit auth check inside the function (e.g. auth.uid() is not null and ownership), or revoke execute from ${who.join("/")}.`,
      });
    }
  }
  return findings;
}

/**
 * Run the full policy audit against a live database.
 * @param {string} databaseUrl  postgres:// connection string (Supabase → Project Settings → Database)
 * @param {{ Client?: any }} [deps]  inject a pg Client class for tests
 */
export async function auditPolicies(databaseUrl, deps = {}) {
  let Client = deps.Client;
  if (!Client) {
    const pg = await import("pg");
    Client = pg.default?.Client ?? pg.Client;
  }
  const client = new Client({ connectionString: databaseUrl, ssl: databaseUrl.includes("localhost") ? false : { rejectUnauthorized: false } });
  await client.connect();
  try {
    // one client, sequential queries (pg forbids overlapping queries on a single client)
    const tables = await client.query(SQL_TABLES);
    const policies = await client.query(SQL_POLICIES);
    const fns = await client.query(SQL_FUNCTIONS);
    const grants = await client.query(SQL_GRANTS);
    const findings = [
      ...analyzeTables(tables.rows, grants.rows),
      ...analyzePolicies(policies.rows, tables.rows),
      ...analyzeFunctions(fns.rows),
    ];
    return {
      tables: tables.rows, policies: policies.rows, functions: fns.rows.filter(f => f.security_definer), grants: grants.rows,
      findings,
    };
  } finally {
    await client.end();
  }
}

export const SQL = { SQL_TABLES, SQL_POLICIES, SQL_FUNCTIONS, SQL_GRANTS };
