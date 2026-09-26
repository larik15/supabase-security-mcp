#!/usr/bin/env node
// Run all checks without an MCP client, straight from the terminal.
//
// Keys are read only from the environment or a .env file in the current directory —
// never from the command line, where they'd land in shell history:
//   SUPABASE_URL, SUPABASE_ANON_KEY, [DATABASE_URL], [PGSSLROOTCERT], [SUPABASE_SERVICE_ROLE_KEY]
//
// Flags:
//   --tables a,b        tables to probe with the anon key
//   --buckets a,b       storage buckets to probe
//   --rpc a,b           functions to list; called (with {}) only with --invoke-rpc
//   --two a:user_id,…   run the two-account test (WRITES test rows and users) on these tables
//   --sample '{...}'    sampleRow JSON for the two-account test
//   --schema name       schema to audit / call (default public)
//   --ignore a:kind,…   findings to suppress, e.g. public.products:policy_open_read
//   --json              print JSON instead of Markdown
//
// Exit codes: 2 = critical findings, 1 = high findings, 0 = neither, 3 = usage/config error.
import { existsSync, readFileSync } from "node:fs";
import { runProbes, skippedRpcResults } from "../src/probe.mjs";
import { auditPolicies } from "../src/policies.mjs";
import { twoAccountTest } from "../src/twoAccount.mjs";
import { buildReport } from "../src/report.mjs";

/** Minimal .env loader: KEY=VALUE lines, # comments, optional quotes. Real env wins. */
function loadDotEnv(path = ".env") {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m || line.trimStart().startsWith("#")) continue;
    const value = m[2].replace(/^(['"])(.*)\1$/, "$2");
    if (process.env[m[1]] === undefined) process.env[m[1]] = value;
  }
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith("--")) continue;
    const next = argv[i + 1];
    out[argv[i].slice(2)] = next && !next.startsWith("--") ? argv[++i] : true;
  }
  return out;
}

const split = (s) => (typeof s === "string" ? s.split(",").map((x) => x.trim()).filter(Boolean) : []);

function fail(msg) {
  console.error(msg);
  process.exit(3);
}

loadDotEnv();
const args = parseArgs(process.argv.slice(2));
const url = process.env.SUPABASE_URL;
const anonKey = process.env.SUPABASE_ANON_KEY;
if (!url || !anonKey) fail("Set SUPABASE_URL and SUPABASE_ANON_KEY in the environment or in ./.env (not on the command line).");
const schema = typeof args.schema === "string" ? args.schema : undefined;
const invokeRpc = args["invoke-rpc"] === true;

const parts = { project: url };
parts.probe = [
  ...(await runProbes({ url, key: anonKey, schema, tables: split(args.tables), buckets: split(args.buckets), rpc: invokeRpc ? split(args.rpc) : [] })),
  ...(invokeRpc ? [] : skippedRpcResults(split(args.rpc))),
];

if (process.env.DATABASE_URL) {
  try {
    parts.policies = await auditPolicies(process.env.DATABASE_URL, {}, { schema, ignore: split(args.ignore) });
  } catch (e) {
    console.error("audit_policies failed:", e.message);
  }
}

if (args.two) {
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) fail("--two needs SUPABASE_SERVICE_ROLE_KEY in the environment or ./.env.");
  let sample = {};
  if (typeof args.sample === "string") {
    try { sample = JSON.parse(args.sample); } catch { fail("--sample is not valid JSON."); }
  }
  const tables = split(args.two).map((spec) => {
    const [name, ownerColumn] = spec.split(":");
    return { name, ownerColumn: ownerColumn || "user_id", sampleRow: sample };
  });
  try {
    parts.twoAccount = await twoAccountTest({ url, anonKey, serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY, schema, tables });
  } catch (e) {
    console.error("two_account_test failed:", e.message);
  }
}

const rep = buildReport(parts);
if (args.json) console.log(JSON.stringify({ project: url, counts: rep.counts, findings: rep.findings }, null, 2));
else console.log(rep.markdown);
process.exit(rep.counts.critical > 0 ? 2 : rep.counts.high > 0 ? 1 : 0);
