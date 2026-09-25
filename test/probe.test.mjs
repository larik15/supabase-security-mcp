import { test } from "node:test";
import assert from "node:assert/strict";
import { probeTable, probeBucket, probeRpc, runProbes, summarize } from "../src/probe.mjs";

const URL = "https://example.supabase.co";
const KEY = "anon-key";

// Build a fake fetch that answers based on the request URL.
function fakeFetch(routes) {
  return async (url, opts = {}) => {
    for (const [pattern, reply] of routes) {
      if (url.includes(pattern)) {
        const status = reply.status ?? 200;
        const body = reply.body ?? [];
        return {
          status,
          json: async () => body,
          text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
          _opts: opts,
        };
      }
    }
    return { status: 404, json: async () => [], text: async () => "not found" };
  };
}

test("table with rows is OPEN and lists columns", async () => {
  const f = fakeFetch([["/rest/v1/leads?", { status: 200, body: [{ id: 1, email: "a@b.c" }] }]]);
  const r = await probeTable(URL, KEY, "leads", f);
  assert.equal(r.open, true);
  assert.equal(r.status, 200);
  assert.match(r.detail, /columns: id, email/);
});

test("table returning [] is closed (RLS hides rows)", async () => {
  const f = fakeFetch([["/rest/v1/leads_fixed?", { status: 200, body: [] }]]);
  const r = await probeTable(URL, KEY, "leads_fixed", f);
  assert.equal(r.open, false);
  assert.equal(r.status, 200);
});

test("table 401/403 is closed", async () => {
  const f = fakeFetch([["/rest/v1/secret?", { status: 401, body: "" }]]);
  const r = await probeTable(URL, KEY, "secret", f);
  assert.equal(r.open, false);
  assert.equal(r.status, 401);
});

test("table 404 is closed with a helpful note", async () => {
  const f = fakeFetch([]);
  const r = await probeTable(URL, KEY, "nope", f);
  assert.equal(r.open, false);
  assert.equal(r.status, 404);
  assert.match(r.detail, /not found/);
});

test("network failure is reported, not thrown", async () => {
  const f = async () => { throw new Error("ECONNREFUSED"); };
  const r = await probeTable(URL, KEY, "x", f);
  assert.equal(r.open, false);
  assert.equal(r.status, 0);
  assert.match(r.detail, /ECONNREFUSED/);
});

test("anon key is sent in both apikey and Authorization headers", async () => {
  let captured;
  const f = async (url, opts) => { captured = opts; return { status: 200, json: async () => [], text: async () => "" }; };
  await probeTable(URL, KEY, "t", f);
  assert.equal(captured.headers.apikey, KEY);
  assert.equal(captured.headers.Authorization, `Bearer ${KEY}`);
});

test("bucket with objects is OPEN, empty or 4xx is closed", async () => {
  const open = await probeBucket(URL, KEY, "avatars",
    fakeFetch([["/storage/v1/object/list/avatars", { status: 200, body: [{ name: "a.png" }] }]]));
  assert.equal(open.open, true);

  const empty = await probeBucket(URL, KEY, "uploads",
    fakeFetch([["/storage/v1/object/list/uploads", { status: 200, body: [] }]]));
  assert.equal(empty.open, false);

  const blocked = await probeBucket(URL, KEY, "private",
    fakeFetch([["/storage/v1/object/list/private", { status: 400, body: "" }]]));
  assert.equal(blocked.open, false);
});

test("rpc 200 and 400 are treated as callable, 401/403/404 are not", async () => {
  const ok = await probeRpc(URL, KEY, "fn_ok", fakeFetch([["/rpc/fn_ok", { status: 200, body: {} }]]));
  assert.equal(ok.open, true);

  const needsArgs = await probeRpc(URL, KEY, "fn_args", fakeFetch([["/rpc/fn_args", { status: 400, body: "" }]]));
  assert.equal(needsArgs.open, true);

  const blocked = await probeRpc(URL, KEY, "fn_blocked", fakeFetch([["/rpc/fn_blocked", { status: 403, body: "" }]]));
  assert.equal(blocked.open, false);

  const missing = await probeRpc(URL, KEY, "fn_missing", fakeFetch([]));
  assert.equal(missing.open, false);
});

test("runProbes runs everything in order and summarize counts open items", async () => {
  const f = fakeFetch([
    ["/rest/v1/leads_open?", { status: 200, body: [{ id: 1 }] }],
    ["/rest/v1/leads_fixed?", { status: 200, body: [] }],
    ["/storage/v1/object/list/pub", { status: 200, body: [{ name: "x" }] }],
    ["/rpc/stats", { status: 403, body: "" }],
  ]);
  const results = await runProbes(
    { url: URL + "/", key: KEY, tables: ["leads_open", "leads_fixed"], buckets: ["pub"], rpc: ["stats"] },
    f
  );
  assert.equal(results.length, 4);
  assert.deepEqual(results.map(r => r.target), ["leads_open", "leads_fixed", "pub", "stats"]);
  assert.deepEqual(summarize(results), { total: 4, open: 2 });
});
