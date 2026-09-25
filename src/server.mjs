import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runProbes } from "./probe.mjs";
import { auditPolicies } from "./policies.mjs";
import { twoAccountTest } from "./twoAccount.mjs";
import { buildReport } from "./report.mjs";

const env = (k) => process.env[k] || undefined;

function need(v, name, hint) {
  if (!v) throw new Error(`Missing ${name}. Pass it as a tool argument or set ${hint} in the MCP server env.`);
  return v;
}

const list = z.array(z.string()).optional().describe("names, e.g. [\"profiles\",\"orders\"]");

export function createServer() {
  const server = new McpServer({ name: "supabase-security-mcp", version: "0.1.0" });

  server.registerTool(
    "probe_anon",
    {
      title: "Probe with anon key",
      description:
        "Read-only. Uses ONLY the public anon key to check what a stranger can read: tables via REST (select * limit 1), storage buckets (list), and RPC functions (call with {}). Returns OPEN/closed per target. Never writes.",
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
        "Connects to the database (read-only queries on pg_class, pg_policies, pg_proc, information_schema) and flags: tables with RLS off but granted to anon/authenticated, policies with using(true) / with check(true), policies without a TO clause (apply to PUBLIC), and SECURITY DEFINER functions executable by anon/authenticated. Needs a Postgres connection string.",
      inputSchema: {
        databaseUrl: z.string().optional().describe("postgres://... connection string (Supabase → Project Settings → Database). Or env DATABASE_URL"),
      },
    },
    async ({ databaseUrl }) => {
      const dsn = need(databaseUrl || env("DATABASE_URL"), "databaseUrl", "DATABASE_URL");
      const out = await auditPolicies(dsn);
      const lines = out.findings.map(f => `[${f.severity}] ${f.message}\n   fix: ${f.fix}`);
      const head = `tables: ${out.tables.length}, with RLS: ${out.tables.filter(t => t.rls_enabled).length}, policies: ${out.policies.length}, security-definer functions: ${out.functions.length}, findings: ${out.findings.length}`;
      return { content: [{ type: "text", text: `${head}\n\n${lines.join("\n") || "no findings"}` }], structuredContent: out };
    }
  );

  server.registerTool(
    "two_account_test",
    {
      title: "Two-account cross-tenant test",
      description:
        "Creates two temporary users (needs the service role key ONLY for that and for cleanup), inserts a row as user A into each table, then tries to read/update/delete it as user B and as anon through the normal REST API. Reports which tables leak across users. Deletes the test rows and users afterwards. Give sampleRow for tables with required columns.",
      inputSchema: {
        url: z.string().optional(),
        anonKey: z.string().optional(),
        serviceRoleKey: z.string().optional().describe("service_role key (or env SUPABASE_SERVICE_ROLE_KEY). Used only to create/delete the two test users and clean up rows."),
        tables: z.array(z.object({
          name: z.string(),
          ownerColumn: z.string().optional().describe("default user_id"),
          idColumn: z.string().optional().describe("default id"),
          sampleRow: z.record(z.any()).optional().describe("values for required columns, e.g. {\"name\":\"test\"}"),
        })).min(1),
      },
    },
    async ({ url, anonKey, serviceRoleKey, tables }) => {
      const cfg = {
        url: need(url || env("SUPABASE_URL"), "url", "SUPABASE_URL"),
        anonKey: need(anonKey || env("SUPABASE_ANON_KEY"), "anonKey", "SUPABASE_ANON_KEY"),
        serviceRoleKey: need(serviceRoleKey || env("SUPABASE_SERVICE_ROLE_KEY"), "serviceRoleKey", "SUPABASE_SERVICE_ROLE_KEY"),
        tables,
      };
      const out = await twoAccountTest(cfg);
      const lines = out.results.map(r => `${r.table}: ${r.leaks.length ? "LEAK " + r.leaks.join(", ") : "ok"}  (insert ${r.steps.owner_insert}, B-select ${r.steps.other_user_select}, anon-select ${r.steps.anon_select}, B-update ${r.steps.other_user_update}, B-delete ${r.steps.other_user_delete})${r.notes.length ? "\n   " + r.notes.join("\n   ") : ""}`);
      return { content: [{ type: "text", text: lines.join("\n") }], structuredContent: out };
    }
  );

  server.registerTool(
    "security_report",
    {
      title: "Full report (all checks)",
      description:
        "Runs probe_anon, audit_policies (if a database URL is available) and two_account_test (if a service role key and tables are given), then returns one Markdown report sorted by severity.",
      inputSchema: {
        url: z.string().optional(),
        anonKey: z.string().optional(),
        databaseUrl: z.string().optional(),
        serviceRoleKey: z.string().optional(),
        tables: list.describe("tables to probe with anon key"),
        buckets: list,
        rpc: list,
        twoAccountTables: z.array(z.object({ name: z.string(), ownerColumn: z.string().optional(), idColumn: z.string().optional(), sampleRow: z.record(z.any()).optional() })).optional(),
      },
    },
    async (args) => {
      const url = need(args.url || env("SUPABASE_URL"), "url", "SUPABASE_URL");
      const anonKey = need(args.anonKey || env("SUPABASE_ANON_KEY"), "anonKey", "SUPABASE_ANON_KEY");
      const parts = { project: url };
      parts.probe = await runProbes({ url, key: anonKey, tables: args.tables || [], buckets: args.buckets || [], rpc: args.rpc || [] });
      const dsn = args.databaseUrl || env("DATABASE_URL");
      if (dsn) parts.policies = await auditPolicies(dsn);
      const srk = args.serviceRoleKey || env("SUPABASE_SERVICE_ROLE_KEY");
      if (srk && args.twoAccountTables?.length) parts.twoAccount = await twoAccountTest({ url, anonKey, serviceRoleKey: srk, tables: args.twoAccountTables });
      const rep = buildReport(parts);
      return { content: [{ type: "text", text: rep.markdown }], structuredContent: { counts: rep.counts, findings: rep.findings } };
    }
  );

  return server;
}
