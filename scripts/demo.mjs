#!/usr/bin/env node
// Run all checks without an MCP client, straight from the terminal.
//   SUPABASE_URL=... SUPABASE_ANON_KEY=... [DATABASE_URL=...] [SUPABASE_SERVICE_ROLE_KEY=...] \
//   node scripts/demo.mjs --tables leads_open,leads_fixed --two leads_open:user_id,leads_fixed:user_id --sample '{"name":"probe","email":"p@x.test","deal_value":1}'
import { runProbes } from "../src/probe.mjs";
import { auditPolicies } from "../src/policies.mjs";
import { twoAccountTest } from "../src/twoAccount.mjs";
import { buildReport } from "../src/report.mjs";

const args = Object.fromEntries(process.argv.slice(2).reduce((a, x, i, arr) => { if (x.startsWith("--")) a.push([x.slice(2), arr[i + 1] && !arr[i + 1].startsWith("--") ? arr[i + 1] : true]); return a; }, []));
const url = process.env.SUPABASE_URL, anonKey = process.env.SUPABASE_ANON_KEY;
if (!url || !anonKey) { console.error("Set SUPABASE_URL and SUPABASE_ANON_KEY"); process.exit(2); }
const split = (s) => (typeof s === "string" ? s.split(",").map(x => x.trim()).filter(Boolean) : []);

const parts = { project: url };
parts.probe = await runProbes({ url, key: anonKey, tables: split(args.tables), buckets: split(args.buckets), rpc: split(args.rpc) });
if (process.env.DATABASE_URL) {
  try { parts.policies = await auditPolicies(process.env.DATABASE_URL); }
  catch (e) { console.error("audit_policies failed:", e.message); }
}
if (process.env.SUPABASE_SERVICE_ROLE_KEY && args.two) {
  const sample = args.sample ? JSON.parse(args.sample) : {};
  const tables = split(args.two).map(spec => { const [name, ownerColumn] = spec.split(":"); return { name, ownerColumn: ownerColumn || "user_id", sampleRow: sample }; });
  try { parts.twoAccount = await twoAccountTest({ url, anonKey, serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY, tables }); }
  catch (e) { console.error("two_account_test failed:", e.message); }
}
const rep = buildReport(parts);
console.log(rep.markdown);
process.exit(rep.counts.critical + rep.counts.high > 0 ? 1 : 0);
