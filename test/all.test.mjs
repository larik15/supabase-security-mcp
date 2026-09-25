import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeTables, analyzePolicies, analyzeFunctions } from "../src/policies.mjs";
import { twoAccountTest } from "../src/twoAccount.mjs";
import { buildReport } from "../src/report.mjs";
import { createServer } from "../src/server.mjs";

// ---------- policies (pure) ----------

test("rls disabled + anon grant is critical; disabled without grant is info", () => {
  const tables = [
    { schema: "public", table: "leads", rls_enabled: false, rls_forced: false },
    { schema: "public", table: "internal", rls_enabled: false, rls_forced: false },
    { schema: "public", table: "ok", rls_enabled: true, rls_forced: false },
  ];
  const grants = [{ table: "leads", grantee: "anon", privilege_type: "SELECT" }];
  const f = analyzeTables(tables, grants);
  assert.equal(f.find(x => x.table === "leads").severity, "critical");
  assert.equal(f.find(x => x.table === "internal").severity, "info");
  assert.equal(f.find(x => x.table === "ok"), undefined);
});

test("using(true) select for anon is high; missing TO clause flagged; open update is critical", () => {
  const policies = [
    { table: "leads", policy: "anyone reads", permissive: "PERMISSIVE", roles: "{anon}", cmd: "SELECT", qual: "true", with_check: null },
    { table: "leads", policy: "Service role full access", permissive: "PERMISSIVE", roles: "{public}", cmd: "ALL", qual: "true", with_check: "true" },
    { table: "profiles", policy: "own rows", permissive: "PERMISSIVE", roles: "{authenticated}", cmd: "SELECT", qual: "(auth.uid() = user_id)", with_check: null },
    { table: "posts", policy: "insert any", permissive: "PERMISSIVE", roles: "{authenticated}", cmd: "INSERT", qual: null, with_check: "true" },
  ];
  const f = analyzePolicies(policies, [{ table: "leads", rls_enabled: true }, { table: "profiles", rls_enabled: true }, { table: "posts", rls_enabled: true }, { table: "silent", rls_enabled: true }]);
  const kinds = f.map(x => `${x.table}:${x.kind}:${x.severity}`);
  assert.ok(kinds.includes("leads:policy_open_read:high"));
  assert.ok(kinds.includes("leads:policy_no_to_clause:high"));
  assert.ok(kinds.includes("leads:policy_open_write:critical"));
  assert.ok(kinds.includes("posts:policy_open_insert:high"));
  assert.ok(kinds.includes("silent:rls_no_policies:info"));
  assert.ok(!kinds.some(k => k.startsWith("profiles:")), "ownership policy must not be flagged");
});

test("roles given as array are handled; parenthesised '(true)' counts as true", () => {
  const f = analyzePolicies([{ table: "t", policy: "p", roles: ["anon"], cmd: "SELECT", qual: "(true)", with_check: null }]);
  assert.equal(f[0].kind, "policy_open_read");
});

test("security definer functions exposed to anon/authenticated are flagged, invoker functions are not", () => {
  const f = analyzeFunctions([
    { name: "get_stats", args: "", security_definer: true, anon_can_execute: true, authenticated_can_execute: true },
    { name: "safe_fn", args: "", security_definer: false, anon_can_execute: true, authenticated_can_execute: true },
    { name: "internal", args: "p int", security_definer: true, anon_can_execute: false, authenticated_can_execute: false },
  ]);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "high");
  assert.match(f[0].function, /get_stats/);
});

// ---------- two-account test with a fake Supabase ----------

function fakeSupabase({ leakRead = false, leakUpdate = false, leakDelete = false, anonRead = false, blockInsert = false } = {}) {
  const users = {};
  const rows = {};
  let nextId = 1;
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url, method: opts.method || "GET" });
    const h = opts.headers || {};
    const bearer = (h.Authorization || "").replace("Bearer ", "");
    const reply = (status, body) => ({ status, json: async () => body, text: async () => JSON.stringify(body) });

    if (url.includes("/auth/v1/admin/users") && opts.method === "POST") {
      const b = JSON.parse(opts.body); const id = "u" + Object.keys(users).length; users[id] = b; return reply(200, { id });
    }
    if (url.includes("/auth/v1/admin/users/") && opts.method === "DELETE") return reply(200, {});
    if (url.includes("/auth/v1/token")) {
      const b = JSON.parse(opts.body); const id = Object.keys(users).find(k => users[k].email === b.email); return reply(200, { access_token: "tok-" + id });
    }
    const m = url.match(/\/rest\/v1\/([^?]+)(\?.*)?$/);
    if (m) {
      const table = m[1]; const q = m[2] || ""; const asUser = bearer.startsWith("tok-") ? bearer.slice(4) : null;
      const isService = bearer === "service";
      rows[table] = rows[table] || [];
      if (opts.method === "POST") {
        if (blockInsert) return reply(403, { message: "new row violates row-level security policy" });
        const b = JSON.parse(opts.body); const r = { id: nextId++, ...b }; rows[table].push(r); return reply(201, [r]);
      }
      const idm = q.match(/id=eq\.(\d+)/); const id = idm ? Number(idm[1]) : null;
      const target = rows[table].filter(r => id == null || r.id === id);
      const visible = (r) => isService || (asUser && r.user_id === asUser) || (asUser && leakRead) || (!asUser && anonRead);
      if (opts.method === "PATCH") { const ok = target.filter(r => isService || (asUser && (r.user_id === asUser || leakUpdate))); return reply(200, ok); }
      if (opts.method === "DELETE") { const ok = target.filter(r => isService || (asUser && (r.user_id === asUser || leakDelete))); for (const r of ok) rows[table] = rows[table].filter(x => x !== r); return reply(200, ok); }
      return reply(200, target.filter(visible));
    }
    return reply(404, {});
  };
  return { fetchImpl, calls, rows };
}

test("two-account test: closed table reports no leaks and cleans up", async () => {
  const fake = fakeSupabase();
  const out = await twoAccountTest({ url: "https://x.supabase.co", anonKey: "anon", serviceRoleKey: "service", tables: [{ name: "notes", sampleRow: { body: "hi" } }] }, fake.fetchImpl);
  assert.equal(out.results[0].leaks.length, 0);
  assert.equal(out.findings.length, 0);
  assert.equal(fake.rows.notes.length, 0, "test row must be deleted");
  assert.ok(fake.calls.some(c => c.url.includes("/auth/v1/admin/users/") && c.method === "DELETE"), "users must be deleted");
});

test("two-account test: leaking table reports read/update/delete leaks with fixes", async () => {
  const fake = fakeSupabase({ leakRead: true, leakUpdate: true, leakDelete: true, anonRead: true });
  const out = await twoAccountTest({ url: "https://x.supabase.co", anonKey: "anon", serviceRoleKey: "service", tables: [{ name: "leads", sampleRow: { name: "t" } }] }, fake.fetchImpl);
  const leaks = out.results[0].leaks;
  assert.deepEqual(leaks.sort(), ["anon_can_read", "other_user_can_delete", "other_user_can_read", "other_user_can_update"].sort());
  assert.ok(out.findings.some(f => f.kind === "cross_tenant_delete" && f.severity === "critical"));
  assert.ok(out.findings.every(f => f.fix.includes("auth.uid()")));
});

test("two-account test: blocked insert is reported as a note, not a crash", async () => {
  const fake = fakeSupabase({ blockInsert: true });
  const out = await twoAccountTest({ url: "https://x.supabase.co", anonKey: "anon", serviceRoleKey: "service", tables: [{ name: "locked" }] }, fake.fetchImpl);
  assert.equal(out.results[0].steps.owner_insert, 403);
  assert.match(out.results[0].notes[0], /Could not insert as A/);
  assert.equal(out.findings.length, 0);
});

test("two-account test refuses to run without service role key", async () => {
  await assert.rejects(() => twoAccountTest({ url: "u", anonKey: "a", tables: [{ name: "t" }] }), /service role key/);
});

// ---------- report ----------

test("report sorts by severity and counts", () => {
  const rep = buildReport({
    project: "https://x.supabase.co",
    probe: [{ target: "leads", kind: "table", open: true, status: 200, detail: "rows" }, { target: "safe", kind: "table", open: false, status: 200, detail: "none" }],
    policies: { tables: [{ rls_enabled: true }], policies: [], functions: [], findings: [{ severity: "info", kind: "x", message: "info thing", fix: "" }] },
    twoAccount: { results: [{ table: "leads", steps: {}, leaks: ["other_user_can_delete"], notes: [] }], findings: [{ severity: "critical", kind: "cross_tenant_delete", message: "delete leak", fix: "fix it" }] },
  });
  assert.equal(rep.findings[0].severity, "critical");
  assert.equal(rep.findings[rep.findings.length - 1].severity, "info");
  assert.equal(rep.counts.critical, 1);
  assert.equal(rep.counts.high, 1);
  assert.match(rep.markdown, /# Supabase security report/);
  assert.match(rep.markdown, /\*\*OPEN\*\* `table` \*\*leads\*\*/);
});

// ---------- MCP server ----------

test("server registers the four tools", async () => {
  const server = createServer();
  const names = Object.keys(server._registeredTools || {});
  assert.deepEqual(names.sort(), ["audit_policies", "probe_anon", "security_report", "two_account_test"]);
});
