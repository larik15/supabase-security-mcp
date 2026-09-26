import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runProbes, skippedRpcResults } from "./probe.mjs";
import { auditPolicies } from "./policies.mjs";
import { twoAccountTest } from "./twoAccount.mjs";
import { buildReport } from "./report.mjs";
import { checkApiUrl, checkDatabaseUrl } from "./guard.mjs";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

const env = (k) => process.env[k] || undefined;

function need(v, name, hint) {
  if (!v) throw new Error(`Missing ${name}. Set ${hint} in the MCP server env (preferred for secrets) or pass it as a tool argument.`);
  return v;
}

// ---------- secrets never leave in output ----------

/** Every secret this call could know about: its arguments and the server env. */
function secretsFor(args = {}) {
  const values = [args.anonKey, args.serviceRoleKey, args.databaseUrl, args.caCert, env("SUPABASE_ANON_KEY"), env("SUPABASE_SERVICE_ROLE_KEY"), env("DATABASE_URL")];
  for (const dsn of [args.databaseUrl, env("DATABASE_URL")]) {
    try { if (dsn) values.push(decodeURIComponent(new URL(dsn).password)); } catch { /* not a URL: the whole value is already listed */ }
  }
  return values.filter((v) => typeof v === "string" && v.length >= 8);
}

export function redact(text, secrets) {
  let out = String(text);
  for (const s of secrets) out = out.split(s).join("[redacted]");
  return out;
}

/** Wrap a tool handler so no secret appears in its text, structured output, or errors. */
function guarded(handler) {
  return async (args, extra) => {
    const secrets = secretsFor(args);
    try {
      const res = await handler(args, extra);
      return {
        ...res,
        content: res.content.map((c) => (c.type === "text" ? { ...c, text: redact(c.text, secrets) } : c)),
        ...(res.structuredContent ? { structuredContent: JSON.parse(redact(JSON.stringify(res.structuredContent), secrets)) } : {}),
      };
    } catch (err) {
      throw new Error(redact(err?.message ?? String(err), secrets));
    }
  };
}

// ---------- schemas ----------

const list = z.array(z.string()).optional().describe("names, e.g. [\"profiles\",\"orders\"]");
const SECRET = "Secret — do not echo it back or include it in any message. Prefer the server env; tool arguments stay in the transcript.";

const secretArgs = {
  anonKey: z.string().optional().describe(`anon / publishable key (sb_publishable_... or legacy eyJ...), or env SUPABASE_ANON_KEY. ${SECRET}`),
  serviceRoleKey: z.string().optional().describe(`service_role / secret key (sb_secret_... or legacy eyJ...), or env SUPABASE_SERVICE_ROLE_KEY. ${SECRET}`),
  databaseUrl: z.string().optional().describe(`postgres://... connection string, or env DATABASE_URL. ${SECRET}`),
};

const schemaArg = z.string().regex(/^[A-Za-z_][A-Za-z0-9_$]*$/).optional().describe("Postgres schema to audit / call through the API (default public). Must be exposed in the Data API settings for the REST checks.");

const tlsArgs = {
  caCert: z.string().optional().describe("PEM contents of the CA to verify the database certificate with (Supabase: Project Settings → Database → SSL Configuration). Or env PGSSLROOTCERT=/path/to/prod-ca-2021.crt"),
  insecureSkipTlsVerify: z.boolean().optional().describe("Local development only: connect without verifying the database certificate. Logged as a warning."),
};

const ignoreArg = z.array(z.string()).optional().describe("Findings to suppress, as \"schema.relation:kind\" (e.g. \"public.products:policy_open_read\") or \"schema.relation\" for all kinds on it.");

const twoAccountTable = z.object({
  name: z.string(),
  ownerColumn: z.string().optional().describe("column holding the owner's auth.uid(); default user_id"),
  idColumn: z.string().optional().describe("default id"),
  sampleRow: z.record(z.any()).optional().describe("values for required columns, e.g. {\"name\":\"test\"}"),
});

function probeCfg(url, anonKey, { tables = [], buckets = [], rpc = [], invokeRpc = false, schema } = {}) {
  return { url, key: anonKey, schema, tables, buckets, rpc: invokeRpc ? rpc : [], skippedRpc: invokeRpc ? [] : rpc };
}

async function probe(cfg) {
  return [...(await runProbes(cfg)), ...skippedRpcResults(cfg.skippedRpc)];
}

export function createServer() {
  const server = new McpServer({ name: "supabase-security-mcp", version });

  server.registerTool(
    "probe_anon",
    {
      title: "Probe with anon key",
      description:
        "Uses ONLY the public anon key to check what a stranger can read: tables via REST (select * limit 1) and storage buckets (list). RPC names are only called when invokeRpc is true — each once, with {} as arguments, so name only functions that are safe to invoke. Returned rows become part of the conversation.",
      inputSchema: {
        url: z.string().optional().describe("Project URL, e.g. https://ref.supabase.co (or env SUPABASE_URL)"),
        anonKey: secretArgs.anonKey,
        schema: schemaArg,
        tables: list,
        buckets: list,
        rpc: list,
        invokeRpc: z.boolean().optional().describe("Actually call the functions in rpc (default false: they're listed as not called)."),
      },
    },
    guarded(async (args) => {
      const cfg = probeCfg(need(args.url || env("SUPABASE_URL"), "url", "SUPABASE_URL"), need(args.anonKey || env("SUPABASE_ANON_KEY"), "anonKey", "SUPABASE_ANON_KEY"), args);
      const results = await probe(cfg);
      const open = results.filter(r => r.open).length;
      const text = results.map(r => `${r.open ? "OPEN  " : r.skipped ? "skip  " : "closed"} ${r.kind.padEnd(6)} ${r.target}  [${r.status}] ${r.detail}`).join("\n");
      return { content: [{ type: "text", text: `${open} of ${results.length} open\n\n${text}` }], structuredContent: { results, open, total: results.length } };
    })
  );

  server.registerTool(
    "audit_policies",
    {
      title: "Audit RLS policies in Postgres",
      description:
        "Connects to the database (read-only catalog queries: pg_class, pg_policies, pg_proc, has_table_privilege; TLS-verified) and flags: tables with RLS off that anon/authenticated can reach, views without security_invoker and exposed materialized views / foreign tables, open policies (true, 1=1, or true) and policies open to every logged-in user, policies reading user_metadata, policies without a TO clause, dead policies for service_role, open storage.objects policies, and SECURITY DEFINER functions callable via /rpc or missing a pinned search_path. Returns findings and a summary; raw catalog rows only with includeRaw.",
      inputSchema: {
        databaseUrl: secretArgs.databaseUrl,
        schema: schemaArg,
        ignore: ignoreArg,
        includeRaw: z.boolean().optional().describe("Also return the raw catalog rows (tables, policies, functions, buckets)."),
        ...tlsArgs,
      },
    },
    guarded(async ({ databaseUrl, schema, ignore, includeRaw, caCert, insecureSkipTlsVerify }) => {
      const dsn = need(databaseUrl || env("DATABASE_URL"), "databaseUrl", "DATABASE_URL");
      checkDatabaseUrl(dsn);
      const out = await auditPolicies(dsn, {}, { caCert, insecureSkipTlsVerify, schema, ignore });
      const s = out.summary;
      const lines = out.findings.map(f => `[${f.severity}] ${f.message}\n   fix: ${f.fix}`);
      const warn = s.tls === "UNVERIFIED" ? "WARNING: TLS certificate verification was disabled for this connection.\n" : "";
      const restr = s.restrictivePolicies.length ? ` (${s.restrictivePolicies.length} restrictive, not checked for open expressions)` : "";
      const head = `${warn}schema ${s.schema}: relations ${s.relations}, tables with RLS ${s.tablesWithRls}/${s.tables}, policies ${s.policies}${restr}, security-definer functions ${s.securityDefinerFunctions}, findings ${out.findings.length}${s.ignored ? ` (${s.ignored} ignored)` : ""}`;
      const structured = includeRaw ? out : { summary: s, findings: out.findings };
      return { content: [{ type: "text", text: `${head}\n\n${lines.join("\n") || "no findings"}` }], structuredContent: structured };
    })
  );

  server.registerTool(
    "two_account_test",
    {
      title: "Two-account cross-tenant test",
      description:
        "WRITES to the project. For direct-ownership tables (one column holds the owner's auth.uid()). Creates two temporary users, inserts a row as user A into each table, then tries to read/update/delete it as user B and as anon, insert a row owned by A as B, and reassign B's own row to A. Deletes the test rows and users afterwards and verifies they're gone. Triggers, webhooks and auth hooks fire on the test rows and users. Give sampleRow for tables with required columns.",
      inputSchema: {
        url: z.string().optional().describe("Project URL (or env SUPABASE_URL). Must be the pinned project."),
        anonKey: secretArgs.anonKey,
        serviceRoleKey: secretArgs.serviceRoleKey,
        schema: schemaArg,
        tables: z.array(twoAccountTable).min(1),
      },
    },
    guarded(async ({ url, anonKey, serviceRoleKey, schema, tables }) => {
      const cfg = {
        url: need(url || env("SUPABASE_URL"), "url", "SUPABASE_URL"),
        anonKey: need(anonKey || env("SUPABASE_ANON_KEY"), "anonKey", "SUPABASE_ANON_KEY"),
        serviceRoleKey: need(serviceRoleKey || env("SUPABASE_SERVICE_ROLE_KEY"), "serviceRoleKey", "SUPABASE_SERVICE_ROLE_KEY"),
        schema,
        tables,
      };
      checkApiUrl(cfg.url);
      const out = await twoAccountTest(cfg);
      const lines = out.results.map(r => {
        const s = r.steps;
        const steps = [
          `insert ${s.owner_insert}`, `B-select ${s.other_user_select ?? "-"}`, `anon-select ${s.anon_select ?? "-"}`,
          `B-update ${s.other_user_update ?? "-"}`, `anon-update ${s.anon_update ?? "-"}`, `anon-delete ${s.anon_delete ?? "-"}`,
          `B-delete ${s.other_user_delete ?? "-"}`, `B-insert-as-A ${s.other_user_insert_as_owner ?? "-"}`, `B-reassign-to-A ${s.other_user_reassign_owner ?? "-"}`,
        ];
        return `${r.table}: ${r.leaks.length ? "LEAK " + r.leaks.join(", ") : "ok"}  (${steps.join(", ")})${r.notes.length ? "\n   " + r.notes.join("\n   ") : ""}`;
      });
      if (!out.users.cleaned) lines.push(`\nCLEANUP FAILED: ${out.findings.find(f => f.kind === "cleanup_failed")?.message}`);
      return { content: [{ type: "text", text: lines.join("\n") }], structuredContent: out };
    })
  );

  server.registerTool(
    "security_report",
    {
      title: "Full report (all checks)",
      description:
        "Runs probe_anon and audit_policies (if a database URL is available) and returns one Markdown report sorted by severity. two_account_test only runs with includeTwoAccount: true (it writes test rows and users); rpc names are only called with invokeRpc: true.",
      inputSchema: {
        url: z.string().optional(),
        ...secretArgs,
        schema: schemaArg,
        tables: list.describe("tables to probe with anon key"),
        buckets: list,
        rpc: list,
        invokeRpc: z.boolean().optional().describe("Actually call the functions in rpc (default false)."),
        includeTwoAccount: z.boolean().optional().describe("Run two_account_test on twoAccountTables (default false; it writes to the project)."),
        twoAccountTables: z.array(twoAccountTable).optional(),
        ignore: ignoreArg,
        ...tlsArgs,
      },
    },
    guarded(async (args) => {
      const url = need(args.url || env("SUPABASE_URL"), "url", "SUPABASE_URL");
      const anonKey = need(args.anonKey || env("SUPABASE_ANON_KEY"), "anonKey", "SUPABASE_ANON_KEY");
      const dsn = args.databaseUrl || env("DATABASE_URL");
      const runTwo = args.includeTwoAccount === true && Boolean(args.twoAccountTables?.length);
      const srk = runTwo ? need(args.serviceRoleKey || env("SUPABASE_SERVICE_ROLE_KEY"), "serviceRoleKey", "SUPABASE_SERVICE_ROLE_KEY") : null;
      // Pin before anything is sent, so a refused host doesn't leave a half-run report.
      if (dsn) checkDatabaseUrl(dsn);
      if (runTwo) checkApiUrl(url);

      const parts = { project: url };
      parts.probe = await probe(probeCfg(url, anonKey, args));
      if (dsn) parts.policies = await auditPolicies(dsn, {}, { caCert: args.caCert, insecureSkipTlsVerify: args.insecureSkipTlsVerify, schema: args.schema, ignore: args.ignore });
      if (runTwo) parts.twoAccount = await twoAccountTest({ url, anonKey, serviceRoleKey: srk, schema: args.schema, tables: args.twoAccountTables });
      const rep = buildReport(parts);
      const note = args.twoAccountTables?.length && !runTwo ? "\n_two_account_test was not run: pass includeTwoAccount: true to run it (it writes test rows and users)._\n" : "";
      return { content: [{ type: "text", text: rep.markdown + note }], structuredContent: { counts: rep.counts, findings: rep.findings } };
    })
  );

  return server;
}
