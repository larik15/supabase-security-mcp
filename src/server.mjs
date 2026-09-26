import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runProbes } from "./probe.mjs";
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

const list = z.array(z.string()).optional().describe("names, e.g. [\"profiles\",\"orders\"]");

const tlsArgs = {
  caCert: z.string().optional().describe("PEM contents of the CA to verify the database certificate with (Supabase: Project Settings → Database → SSL Configuration). Or env PGSSLROOTCERT=/path/to/prod-ca-2021.crt"),
  insecureSkipTlsVerify: z.boolean().optional().describe("Local development only: connect without verifying the database certificate. Logged as a warning."),
};

const twoAccountTable = z.object({
  name: z.string(),
  ownerColumn: z.string().optional().describe("default user_id"),
  idColumn: z.string().optional().describe("default id"),
  sampleRow: z.record(z.any()).optional().describe("values for required columns, e.g. {\"name\":\"test\"}"),
});

/** Resolve and pin the privileged inputs. Throws before anything is sent. */
function privilegedDsn(databaseUrl) {
  const dsn = need(databaseUrl || env("DATABASE_URL"), "databaseUrl", "DATABASE_URL");
  checkDatabaseUrl(dsn);
  return dsn;
}

export function createServer() {
  const server = new McpServer({ name: "supabase-security-mcp", version });

  server.registerTool(
    "probe_anon",
    {
      title: "Probe with anon key",
      description:
        "Uses ONLY the public anon key to check what a stranger can read: tables via REST (select * limit 1), storage buckets (list), and the RPC functions you name (each called once with {} — name only functions that are safe to invoke). Returns OPEN/closed per target. Returned rows become part of the conversation.",
      inputSchema: {
        url: z.string().optional().describe("Project URL, e.g. https://ref.supabase.co (or env SUPABASE_URL)"),
        anonKey: z.string().optional().describe("anon/public key (or env SUPABASE_ANON_KEY)"),
        tables: list,
        buckets: list,
        rpc: list,
      },
    },
    async ({ url, anonKey, tables = [], buckets = [], rpc = [] }) => {
      const cfg = { url: need(url || env("SUPABASE_URL"), "url", "SUPABASE_URL"), key: need(anonKey || env("SUPABASE_ANON_KEY"), "anonKey", "SUPABASE_ANON_KEY"), tables, buckets, rpc };
      const results = await runProbes(cfg);
      const open = results.filter(r => r.open).length;
      const text = results.map(r => `${r.open ? "OPEN  " : "closed"} ${r.kind.padEnd(6)} ${r.target}  [${r.status}] ${r.detail}`).join("\n");
      return { content: [{ type: "text", text: `${open} of ${results.length} open\n\n${text}` }], structuredContent: { results, open, total: results.length } };
    }
  );

  server.registerTool(
    "audit_policies",
    {
      title: "Audit RLS policies in Postgres",
      description:
        "Connects to the database (read-only queries on pg_class, pg_policies, pg_proc, has_table_privilege; TLS-verified) and flags: tables with RLS off that anon/authenticated can reach, views without security_invoker and exposed materialized views / foreign tables, open policies (using(true), with check(true), 1=1, or true) and policies open to every logged-in user, policies without a TO clause, open storage.objects policies, and SECURITY DEFINER functions callable by anon/authenticated or missing a pinned search_path. Needs a Postgres connection string for the project in SUPABASE_URL.",
      inputSchema: {
        databaseUrl: z.string().optional().describe("postgres://... connection string. Prefer env DATABASE_URL: tool arguments stay in the transcript."),
        ...tlsArgs,
      },
    },
    async ({ databaseUrl, caCert, insecureSkipTlsVerify }) => {
      const dsn = privilegedDsn(databaseUrl);
      const out = await auditPolicies(dsn, {}, { caCert, insecureSkipTlsVerify });
      const lines = out.findings.map(f => `[${f.severity}] ${f.message}\n   fix: ${f.fix}`);
      const warn = out.tls === "UNVERIFIED" ? "WARNING: TLS certificate verification was disabled for this connection.\n" : "";
      const restr = out.restrictivePolicies.length ? ` (${out.restrictivePolicies.length} restrictive, listed in structuredContent, not checked for open expressions)` : "";
      const head = `${warn}relations: ${out.tables.length}, tables with RLS: ${out.tables.filter(t => t.rls_enabled).length}, policies: ${out.policies.length}${restr}, security-definer functions: ${out.functions.length}, findings: ${out.findings.length}`;
      return { content: [{ type: "text", text: `${head}\n\n${lines.join("\n") || "no findings"}` }], structuredContent: out };
    }
  );

  server.registerTool(
    "two_account_test",
    {
      title: "Two-account cross-tenant test",
      description:
        "WRITES to the project. Creates two temporary users (service role key used only for that, two verification reads, and cleanup), inserts a row as user A into each table, then as user B tries to read/update/delete it, insert a row owned by A, and reassign its own row to A; also tries to read A's row as anon. Deletes the test rows and users afterwards and verifies they're gone. Triggers, webhooks and auth hooks fire on the test rows and users. Give sampleRow for tables with required columns.",
      inputSchema: {
        url: z.string().optional().describe("Project URL (or env SUPABASE_URL). Must be the pinned project."),
        anonKey: z.string().optional(),
        serviceRoleKey: z.string().optional().describe("Prefer env SUPABASE_SERVICE_ROLE_KEY: tool arguments stay in the transcript."),
        tables: z.array(twoAccountTable).min(1),
      },
    },
    async ({ url, anonKey, serviceRoleKey, tables }) => {
      const cfg = {
        url: need(url || env("SUPABASE_URL"), "url", "SUPABASE_URL"),
        anonKey: need(anonKey || env("SUPABASE_ANON_KEY"), "anonKey", "SUPABASE_ANON_KEY"),
        serviceRoleKey: need(serviceRoleKey || env("SUPABASE_SERVICE_ROLE_KEY"), "serviceRoleKey", "SUPABASE_SERVICE_ROLE_KEY"),
        tables,
      };
      checkApiUrl(cfg.url);
      const out = await twoAccountTest(cfg);
      const lines = out.results.map(r => {
        const s = r.steps;
        return `${r.table}: ${r.leaks.length ? "LEAK " + r.leaks.join(", ") : "ok"}  (insert ${s.owner_insert}, B-select ${s.other_user_select ?? "-"}, anon-select ${s.anon_select ?? "-"}, B-update ${s.other_user_update ?? "-"}, B-delete ${s.other_user_delete ?? "-"}, B-insert-as-A ${s.other_user_insert_as_owner ?? "-"}, B-reassign-to-A ${s.other_user_reassign_owner ?? "-"})${r.notes.length ? "\n   " + r.notes.join("\n   ") : ""}`;
      });
      if (!out.users.cleaned) lines.push(`\nCLEANUP FAILED: ${out.findings.find(f => f.kind === "cleanup_failed")?.message}`);
      return { content: [{ type: "text", text: lines.join("\n") }], structuredContent: out };
    }
  );

  server.registerTool(
    "security_report",
    {
      title: "Full report (all checks)",
      description:
        "Runs probe_anon, audit_policies (if a database URL is available) and two_account_test (if a service role key and twoAccountTables are given — that one writes test rows and users), then returns one Markdown report sorted by severity.",
      inputSchema: {
        url: z.string().optional(),
        anonKey: z.string().optional(),
        databaseUrl: z.string().optional(),
        serviceRoleKey: z.string().optional(),
        tables: list.describe("tables to probe with anon key"),
        buckets: list,
        rpc: list,
        twoAccountTables: z.array(twoAccountTable).optional(),
        ...tlsArgs,
      },
    },
    async (args) => {
      const url = need(args.url || env("SUPABASE_URL"), "url", "SUPABASE_URL");
      const anonKey = need(args.anonKey || env("SUPABASE_ANON_KEY"), "anonKey", "SUPABASE_ANON_KEY");
      const dsn = args.databaseUrl || env("DATABASE_URL");
      const srk = args.serviceRoleKey || env("SUPABASE_SERVICE_ROLE_KEY");
      const runTwo = Boolean(srk && args.twoAccountTables?.length);
      // Pin before anything is sent, so a refused host doesn't leave a half-run report.
      if (dsn) checkDatabaseUrl(dsn);
      if (runTwo) checkApiUrl(url);

      const parts = { project: url };
      parts.probe = await runProbes({ url, key: anonKey, tables: args.tables || [], buckets: args.buckets || [], rpc: args.rpc || [] });
      if (dsn) parts.policies = await auditPolicies(dsn, {}, { caCert: args.caCert, insecureSkipTlsVerify: args.insecureSkipTlsVerify });
      if (runTwo) parts.twoAccount = await twoAccountTest({ url, anonKey, serviceRoleKey: srk, tables: args.twoAccountTables });
      const rep = buildReport(parts);
      return { content: [{ type: "text", text: rep.markdown }], structuredContent: { counts: rep.counts, findings: rep.findings } };
    }
  );

  return server;
}
