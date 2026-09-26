import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeTables, analyzePolicies, analyzeFunctions, analyzeBuckets, classifyExpr } from "../src/policies.mjs";
import { twoAccountTest } from "../src/twoAccount.mjs";
import { buildReport } from "../src/report.mjs";
import { createServer } from "../src/server.mjs";

// ---------- expression classification ----------

test("classifyExpr: open, authenticated-only, ownership, other", () => {
  for (const e of ["true", "(true)", "(1 = 1)", "( SELECT true AS bool)", "((user_id = auth.uid()) OR true)"]) {
    assert.equal(classifyExpr(e), "open", e);
  }
  for (const e of ["(auth.uid() IS NOT NULL)", "(auth.role() = 'authenticated'::text)", "(auth.jwt() IS NOT NULL)", "(( SELECT auth.uid() AS uid) IS NOT NULL)"]) {
    assert.equal(classifyExpr(e), "authenticated_only", e);
  }
  for (const e of ["(auth.uid() = user_id)", "((auth.jwt() ->> 'email'::text) = email)", "(auth.email() = email)", "(( SELECT auth.uid() AS uid) = owner_id)"]) {
    assert.equal(classifyExpr(e), "ownership", e);
  }
  // `is not null` alongside another condition is still not ownership
  for (const e of ["(status = 'published'::text)", "((auth.uid() IS NOT NULL) AND (status = 'x'::text))", "is_member(team_id)"]) {
    assert.equal(classifyExpr(e), "other", e);
  }
  assert.equal(classifyExpr(null), "none");
  assert.equal(classifyExpr("(visible OR true_flag)"), "other", "`or true_flag` is not `or true`");
});

// ---------- tables / views ----------

test("rls disabled + privileges is critical; disabled without privileges is info; column-level grants count", () => {
  const f = analyzeTables([
    { schema: "public", table: "leads", relkind: "r", rls_enabled: false, anon_select: true },
    { schema: "public", table: "internal", relkind: "r", rls_enabled: false },
    { schema: "public", table: "cols", relkind: "r", rls_enabled: false, auth_any_column: true },
    { schema: "public", table: "ok", relkind: "r", rls_enabled: true, anon_select: true },
  ]);
  assert.equal(f.find(x => x.table === "leads").severity, "critical");
  assert.equal(f.find(x => x.table === "internal").severity, "info");
  assert.equal(f.find(x => x.table === "cols").kind, "rls_disabled");
  assert.equal(f.find(x => x.table === "ok"), undefined);
});

test("views without security_invoker, exposed matviews and foreign tables are high", () => {
  const f = analyzeTables([
    { schema: "public", table: "v_definer", relkind: "v", auth_select: true, security_invoker: false },
    { schema: "public", table: "v_invoker", relkind: "v", auth_select: true, security_invoker: true },
    { schema: "public", table: "v_private", relkind: "v", security_invoker: false },
    { schema: "public", table: "mv", relkind: "m", anon_select: true },
    { schema: "public", table: "ft", relkind: "f", auth_select: true },
  ]);
  const byTable = Object.fromEntries(f.map(x => [x.table, x]));
  assert.equal(byTable.v_definer.kind, "view_without_security_invoker");
  assert.equal(byTable.v_definer.severity, "high");
  assert.equal(byTable.v_invoker, undefined);
  assert.equal(byTable.v_private, undefined);
  assert.equal(byTable.mv.kind, "materialized_view_exposed");
  assert.equal(byTable.ft.kind, "foreign_table_exposed");
});

// ---------- policies ----------

const P = (o) => ({ schema: "public", permissive: "PERMISSIVE", qual: null, with_check: null, ...o });

test("one finding per policy: FOR ALL using(true) with no TO clause lists every issue, severity critical", () => {
  const { findings } = analyzePolicies([P({ table: "leads", policy: "Service role full access", roles: "{public}", cmd: "ALL", qual: "true" })]);
  assert.equal(findings.length, 1);
  const [f] = findings;
  assert.equal(f.severity, "critical");
  assert.equal(f.kind, "policy_open_write");
  assert.deepEqual([...f.issues].sort(), ["policy_no_to_clause", "policy_open_insert", "policy_open_read", "policy_open_write"]);
  assert.match(f.message, /applies to PUBLIC/);
});

test("open read is high for anon and for authenticated alike", () => {
  const { findings } = analyzePolicies([
    P({ table: "a", policy: "anon read", roles: "{anon}", cmd: "SELECT", qual: "true" }),
    P({ table: "b", policy: "auth read", roles: ["authenticated"], cmd: "SELECT", qual: "(true)" }),
  ]);
  assert.deepEqual(findings.map(f => `${f.table}:${f.kind}:${f.severity}`).sort(), ["a:policy_open_read:high", "b:policy_open_read:high"]);
});

test("missing TO clause: info over an ownership expression, high over an open one", () => {
  const { findings } = analyzePolicies([
    P({ table: "notes", policy: "own rows", roles: "{public}", cmd: "SELECT", qual: "(auth.uid() = user_id)" }),
    P({ table: "posts", policy: "read all", roles: "{public}", cmd: "SELECT", qual: "true" }),
  ]);
  const own = findings.find(f => f.table === "notes");
  assert.equal(own.severity, "info");
  assert.equal(own.kind, "policy_no_to_clause");
  assert.match(own.message, /safe here because the expression fails for anon, but make it explicit/);
  const open = findings.find(f => f.table === "posts");
  assert.equal(open.severity, "high");
  assert.ok(open.issues.includes("policy_no_to_clause"));
});

test("ownership policies with an explicit TO clause and TO service_role policies are not flagged", () => {
  const { findings } = analyzePolicies([
    P({ table: "profiles", policy: "own rows", roles: "{authenticated}", cmd: "ALL", qual: "(auth.uid() = user_id)", with_check: "(auth.uid() = user_id)" }),
    P({ table: "profiles", policy: "service", roles: "{service_role}", cmd: "ALL", qual: "true", with_check: "true" }),
  ], [{ schema: "public", table: "profiles", relkind: "r", rls_enabled: true }]);
  assert.deepEqual(findings, []);
});

test("policies open to every logged-in user get their own kind", () => {
  const { findings } = analyzePolicies([
    P({ table: "docs", policy: "logged in reads", roles: "{authenticated}", cmd: "SELECT", qual: "(auth.uid() IS NOT NULL)" }),
    P({ table: "docs", policy: "logged in deletes", roles: "{authenticated}", cmd: "DELETE", qual: "(auth.role() = 'authenticated'::text)" }),
  ]);
  const read = findings.find(f => f.policy === "logged in reads");
  const del = findings.find(f => f.policy === "logged in deletes");
  assert.equal(read.kind, "policy_open_to_all_authenticated");
  assert.equal(read.severity, "high");
  assert.equal(del.kind, "policy_open_to_all_authenticated");
  assert.equal(del.severity, "critical");
});

test("check broader than using: only when with check is open and using is ownership", () => {
  const { findings } = analyzePolicies([
    P({ table: "posts", policy: "open check", roles: "{authenticated}", cmd: "UPDATE", qual: "(auth.uid() = user_id)", with_check: "true" }),
    P({ table: "posts", policy: "status check", roles: "{authenticated}", cmd: "UPDATE", qual: "(auth.uid() = user_id)", with_check: "(status = 'draft'::text)" }),
    P({ table: "posts", policy: "no check", roles: "{authenticated}", cmd: "UPDATE", qual: "(auth.uid() = user_id)" }),
    P({ table: "posts", policy: "status using", roles: "{authenticated}", cmd: "UPDATE", qual: "(status = 'draft'::text)", with_check: "true" }),
  ]);
  const flagged = findings.filter(f => f.issues.includes("policy_check_broader_than_using")).map(f => f.policy);
  assert.deepEqual(flagged, ["open check"]);
  assert.equal(findings.find(f => f.policy === "open check").severity, "high");
});

test("open insert fix mentions anonymous-submission tables", () => {
  const { findings } = analyzePolicies([P({ table: "waitlist", policy: "anyone signs up", roles: "{anon}", cmd: "INSERT", with_check: "true" })]);
  assert.equal(findings[0].kind, "policy_open_insert");
  assert.match(findings[0].fix, /unless this table is meant for anonymous submissions \(contact forms, waitlists\)/);
});

test("restrictive policies are skipped for open checks and returned separately", () => {
  const { findings, restrictive } = analyzePolicies([
    P({ table: "t", policy: "tenant fence", permissive: "RESTRICTIVE", roles: "{public}", cmd: "ALL", qual: "true" }),
  ]);
  assert.deepEqual(findings, []);
  assert.equal(restrictive.length, 1);
  assert.equal(restrictive[0].policy, "tenant fence");
});

test("storage.objects: open policies are storage_policy_open; public buckets are info", () => {
  const { findings } = analyzePolicies([
    P({ schema: "storage", table: "objects", policy: "read anything", roles: "{anon,authenticated}", cmd: "SELECT", qual: "true" }),
    P({ schema: "storage", table: "objects", policy: "upload anything", roles: "{authenticated}", cmd: "INSERT", with_check: "true" }),
    P({ schema: "storage", table: "objects", policy: "avatars", roles: "{authenticated}", cmd: "SELECT", qual: "(bucket_id = 'avatars'::text)" }),
  ]);
  assert.deepEqual(findings.map(f => `${f.policy}:${f.kind}:${f.table}`).sort(), [
    "read anything:storage_policy_open:storage.objects",
    "upload anything:storage_policy_open:storage.objects",
  ]);
  const b = analyzeBuckets([{ id: "avatars", name: "avatars", public: true }, { id: "private", name: "private", public: false }]);
  assert.equal(b.length, 1);
  assert.equal(b[0].kind, "storage_bucket_public");
  assert.equal(b[0].severity, "info");
});

test("rls on with no policies is info; storage policies don't count for public tables", () => {
  const { findings } = analyzePolicies(
    [P({ schema: "storage", table: "objects", policy: "x", roles: "{authenticated}", cmd: "SELECT", qual: "(owner = auth.uid())" })],
    [{ schema: "public", table: "objects", relkind: "r", rls_enabled: true }, { schema: "public", table: "v", relkind: "v", rls_enabled: false }]
  );
  assert.deepEqual(findings.map(f => `${f.table}:${f.kind}`), ["objects:rls_no_policies"]);
});

// ---------- functions ----------

test("security definer: exposed functions flagged with the owner's-privileges wording; triggers and procedures skipped", () => {
  const f = analyzeFunctions([
    { name: "get_stats", args: "", prokind: "f", returns_trigger: false, security_definer: true, proconfig: ["search_path="], anon_can_execute: true, authenticated_can_execute: true },
    { name: "safe_fn", args: "", prokind: "f", security_definer: false, proconfig: null, anon_can_execute: true, authenticated_can_execute: true },
    { name: "on_signup", args: "", prokind: "f", returns_trigger: true, security_definer: true, proconfig: null, anon_can_execute: true, authenticated_can_execute: true },
    { name: "do_proc", args: "", prokind: "p", security_definer: true, proconfig: null, anon_can_execute: true, authenticated_can_execute: true },
  ]);
  assert.equal(f.length, 1);
  assert.equal(f[0].kind, "definer_function_exposed");
  assert.equal(f[0].severity, "high");
  assert.match(f[0].message, /runs with the owner's privileges \(bypasses RLS if the owner is postgres\/BYPASSRLS\)/);
});

test("security definer without a pinned search_path: medium, fix recommends search_path = ''", () => {
  const f = analyzeFunctions([
    { name: "no_path", args: "", security_definer: true, proconfig: null, anon_can_execute: false, authenticated_can_execute: false },
    { name: "with_path", args: "", security_definer: true, proconfig: ["search_path=\"\""], anon_can_execute: false, authenticated_can_execute: false },
  ]);
  assert.equal(f.length, 1);
  assert.equal(f[0].kind, "definer_function_no_search_path");
  assert.equal(f[0].severity, "medium");
  assert.match(f[0].fix, /set search_path = ''/);
  assert.doesNotMatch(f[0].fix, /pg_catalog/);
});

// ---------- two-account test with a fake Supabase ----------

function parseFilters(q) {
  const filters = [];
  for (const part of q.replace(/^\?/, "").split("&").filter(Boolean)) {
    const [col, rest] = part.split("=");
    if (col === "select") continue;
    const v = decodeURIComponent(rest);
    if (v.startsWith("eq.")) filters.push((r) => String(r[col]) === v.slice(3));
    else if (v.startsWith("in.(")) { const set = v.slice(4, -1).split(","); filters.push((r) => set.includes(String(r[col]))); }
  }
  return (r) => filters.every((f) => f(r));
}

/**
 * Minimal PostgREST + GoTrue fake with RLS-ish semantics:
 *   SELECT visible: own rows (+ leakRead for users, anonRead for anon), none if writeOnly
 *   RETURNING a row the caller can't select -> 42501 and the write is rolled back
 *   UPDATE/DELETE only reach rows the caller can select (WHERE applies SELECT policies)
 */
function fakeSupabase(o = {}) {
  const users = {};
  const rows = {};
  let nextId = 1;
  const calls = [];
  const reply = (status, body) => ({ status, ok: status < 300, json: async () => { if (body === undefined) throw new Error("no body"); return body; }, text: async () => JSON.stringify(body ?? "") });
  const denied = (who) => reply(who ? 403 : 401, { code: "42501", message: "new row violates row-level security policy" });

  const fetchImpl = async (url, opts = {}) => {
    const method = opts.method || "GET";
    calls.push({ url, method, body: opts.body, prefer: opts.headers?.Prefer });
    const bearer = (opts.headers?.Authorization || "").replace("Bearer ", "");
    const isService = opts.headers?.apikey === "service";

    if (url.endsWith("/auth/v1/admin/users") && method === "POST") {
      const b = JSON.parse(opts.body); const id = "u" + Object.keys(users).length; users[id] = b; return reply(200, { id });
    }
    const adminUser = url.match(/\/auth\/v1\/admin\/users\/([^/?]+)$/);
    if (adminUser) {
      const id = adminUser[1];
      if (method === "DELETE") { if (o.failUserDelete) return reply(500, { msg: "Database error deleting user" }); delete users[id]; return reply(200, {}); }
      return users[id] ? reply(200, { id }) : reply(404, {});
    }
    if (url.includes("/auth/v1/token")) {
      const b = JSON.parse(opts.body); const id = Object.keys(users).find((k) => users[k].email === b.email); return reply(200, { access_token: "tok-" + id });
    }

    const m = url.match(/\/rest\/v1\/([^?]+)(\?.*)?$/);
    if (!m) return reply(404, {});
    const table = m[1]; const match = parseFilters(m[2] || "");
    const who = isService ? null : bearer.startsWith("tok-") ? bearer.slice(4) : null;
    const representation = opts.headers?.Prefer === "return=representation";
    const list = (rows[table] = rows[table] || []);
    const canSelect = (r) => isService || (!o.writeOnly && (who ? r.user_id === who || o.leakRead : o.anonRead));

    if (method === "POST") {
      if (o.blockInsert) return denied(who);
      const b = JSON.parse(opts.body);
      if (!isService && b.user_id !== who && !o.spoofInsert) return denied(who);
      const r = { id: nextId++, ...b };
      if (representation && !canSelect(r)) return denied(who); // RETURNING failed: rolled back
      list.push(r);
      return representation ? reply(201, [r]) : reply(201);
    }
    const target = list.filter((r) => match(r) && canSelect(r));
    if (method === "GET") return reply(200, target);
    if (method === "PATCH") {
      const b = JSON.parse(opts.body);
      const ok = target.filter((r) => isService || r.user_id === who || o.leakUpdate);
      if (!isService && "user_id" in b && b.user_id !== who && ok.length && !o.reassign) return denied(who);
      for (const r of ok) Object.assign(r, b);
      if (!representation) return reply(204);
      if (ok.some((r) => !canSelect(r))) return denied(who);
      return reply(200, ok);
    }
    if (method === "DELETE") {
      const ok = target.filter((r) => isService || r.user_id === who || o.leakDelete);
      rows[table] = list.filter((r) => !ok.includes(r));
      return representation ? reply(200, ok) : reply(204);
    }
    return reply(405, {});
  };
  return { fetchImpl, calls, rows, users };
}

const cfg = (tables) => ({ url: "https://x.supabase.co", anonKey: "anon", serviceRoleKey: "service", tables });

test("two-account test: closed table reports no leaks, cleans up and verifies it", async () => {
  const fake = fakeSupabase();
  const out = await twoAccountTest(cfg([{ name: "notes", sampleRow: { body: "hi" } }]), fake.fetchImpl);
  const r = out.results[0];
  assert.deepEqual(r.leaks, []);
  assert.equal(out.findings.length, 0);
  assert.equal(r.steps.other_user_insert_as_owner, 403);
  assert.match(r.steps.other_user_reassign_owner, /owner now B/);
  assert.equal(fake.rows.notes.length, 0, "test rows must be deleted");
  assert.deepEqual(Object.keys(fake.users), [], "users must be deleted");
  assert.equal(out.users.cleaned, true);
});

test("two-account test: leaking table reports all six leaks with fixes", async () => {
  const fake = fakeSupabase({ leakRead: true, leakUpdate: true, leakDelete: true, anonRead: true, spoofInsert: true, reassign: true });
  const out = await twoAccountTest(cfg([{ name: "leads", sampleRow: { name: "t" } }]), fake.fetchImpl);
  assert.deepEqual([...out.results[0].leaks].sort(), [
    "anon_can_read", "other_user_can_delete", "other_user_can_insert_as_owner", "other_user_can_read", "other_user_can_reassign_owner", "other_user_can_update",
  ]);
  const kinds = Object.fromEntries(out.findings.map((f) => [f.kind, f.severity]));
  assert.equal(kinds.cross_tenant_delete, "critical");
  assert.equal(kinds.other_user_can_insert_as_owner, "critical");
  assert.equal(kinds.other_user_can_reassign_owner, "critical");
  assert.equal(kinds.anon_read_owned_row, "high");
  assert.ok(out.findings.every((f) => f.fix.includes("auth.uid()")));
  assert.equal(fake.rows.leads.length, 0, "spoofed and reassigned rows are cleaned up too");
});

test("two-account test: the update probe sets a real column to its own value, never {}", async () => {
  const fake = fakeSupabase();
  await twoAccountTest(cfg([{ name: "notes", sampleRow: { body: "hi" } }]), fake.fetchImpl);
  const patches = fake.calls.filter((c) => c.method === "PATCH");
  assert.ok(patches.length > 0);
  assert.ok(patches.every((c) => c.body && c.body !== "{}"));
  assert.deepEqual(JSON.parse(patches[0].body), { body: "hi" });
});

test("two-account test: write-only table is reported, cross checks skipped, owner-spoof insert still checked", async () => {
  const fake = fakeSupabase({ writeOnly: true });
  const out = await twoAccountTest(cfg([{ name: "contact", sampleRow: { msg: "hi" } }]), fake.fetchImpl);
  const r = out.results[0];
  assert.match(String(r.steps.owner_insert), /write-only/);
  assert.match(r.notes.join(" "), /insert allowed, select denied \(write-only table\)/i);
  assert.equal(r.steps.other_user_select, undefined);
  assert.equal(r.steps.other_user_insert_as_owner, 403);
  assert.equal(fake.rows.contact.length, 0, "write-only rows are cleaned up by owner id");
});

test("two-account test: blocked insert is reported as a note, not a crash", async () => {
  const fake = fakeSupabase({ blockInsert: true });
  const out = await twoAccountTest(cfg([{ name: "locked" }]), fake.fetchImpl);
  assert.equal(out.results[0].steps.owner_insert, 403);
  assert.match(out.results[0].notes[0], /Could not insert as A/);
  assert.equal(out.findings.length, 0);
});

test("two-account test: failed user deletion is reported as cleanup_failed with the ids", async () => {
  const fake = fakeSupabase({ failUserDelete: true });
  const out = await twoAccountTest(cfg([{ name: "notes", sampleRow: { body: "hi" } }]), fake.fetchImpl);
  assert.equal(out.users.cleaned, false);
  const f = out.findings.find((x) => x.kind === "cleanup_failed");
  assert.ok(f);
  assert.match(f.message, /u0/);
  assert.match(f.message, /u1/);
  assert.match(f.fix, /profiles/);
});

test("two-account test: passwords are random per run", async () => {
  const pw = [];
  for (let i = 0; i < 2; i++) {
    const fake = fakeSupabase();
    await twoAccountTest(cfg([{ name: "n", sampleRow: { body: "x" } }]), fake.fetchImpl);
    pw.push(JSON.parse(fake.calls.find((c) => c.url.endsWith("/auth/v1/admin/users")).body).password);
  }
  assert.notEqual(pw[0], pw[1]);
  assert.ok(pw[0].length >= 24);
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
    twoAccount: { results: [{ table: "leads", steps: {}, leaks: ["other_user_can_delete"], notes: [] }], findings: [{ severity: "critical", kind: "cross_tenant_delete", table: "leads", message: "delete leak", fix: "fix it" }] },
  });
  assert.equal(rep.findings[0].severity, "critical");
  assert.equal(rep.findings[rep.findings.length - 1].severity, "info");
  assert.equal(rep.counts.critical, 1);
  assert.equal(rep.counts.high, 1);
  assert.match(rep.markdown, /# Supabase security report/);
  assert.match(rep.markdown, /\*\*OPEN\*\* `table` \*\*leads\*\*/);
});

test("report drops the live test's anonymous-read finding when the anon probe already reported that table", () => {
  const rep = buildReport({
    probe: [{ target: "leads", kind: "table", open: true, status: 200, detail: "rows" }],
    twoAccount: {
      results: [{ table: "leads", steps: {}, leaks: ["anon_can_read"], notes: [] }, { table: "other", steps: {}, leaks: ["anon_can_read"], notes: [] }],
      findings: [
        { severity: "high", kind: "anon_read_owned_row", table: "leads", message: "anon reads leads", fix: "" },
        { severity: "high", kind: "anon_read_owned_row", table: "other", message: "anon reads other", fix: "" },
      ],
    },
  });
  const kinds = rep.findings.map((f) => `${f.kind}:${f.table}`);
  assert.deepEqual(kinds.sort(), ["anon_open_table:leads", "anon_read_owned_row:other"]);
});

// ---------- MCP server ----------

test("server registers the four tools", async () => {
  const server = createServer();
  const names = Object.keys(server._registeredTools || {});
  assert.deepEqual(names.sort(), ["audit_policies", "probe_anon", "security_report", "two_account_test"]);
});

test("server refuses to send the service role key or a database URL to an unpinned host, before any request", async () => {
  const saved = { ...process.env };
  const realFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => { fetched = true; throw new Error("must not be called"); };
  try {
    process.env.SUPABASE_URL = "https://abcdefghijklmnopqrst.supabase.co";
    process.env.SUPABASE_ANON_KEY = "anon";
    process.env.SUPABASE_SERVICE_ROLE_KEY = "service";
    delete process.env.ALLOWED_HOSTS;
    delete process.env.DATABASE_URL;
    const tools = createServer()._registeredTools;
    await assert.rejects(() => tools.two_account_test.handler({ url: "https://evil.example", tables: [{ name: "t" }] }), /pinned to abcdefghijklmnopqrst\.supabase\.co/);
    await assert.rejects(() => tools.audit_policies.handler({ databaseUrl: "postgresql://postgres:pw@evil.example:5432/postgres" }), /Refusing to connect to evil\.example/);
    await assert.rejects(() => tools.security_report.handler({ url: "https://evil.example", twoAccountTables: [{ name: "t" }] }), /Refusing to send the service role key/);
    assert.equal(fetched, false);
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
    globalThis.fetch = realFetch;
  }
});
