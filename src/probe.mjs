// Core probe logic. Pure functions, no I/O except the injected fetch.
// Tables and buckets are only read; each named RPC is called once with {} (whatever it does, it does).

/**
 * @typedef {Object} ProbeResult
 * @property {string} target
 * @property {"table"|"bucket"|"rpc"} kind
 * @property {boolean} open   true if the anon key got data / a callable back
 * @property {number} status  HTTP status (0 = request failed)
 * @property {string} detail  human-readable explanation
 * @property {number} [rows]  row count from a table probe (only set for kind "table")
 */

// Legacy keys are JWTs and go in both headers. New-style keys (sb_publishable_ / sb_secret_)
// go in `apikey` only; Authorization stays free for a user JWT.
export function authHeaders(key, jwt) {
  const h = { apikey: key };
  if (jwt) h.Authorization = `Bearer ${jwt}`;
  else if (!/^sb_/.test(key)) h.Authorization = `Bearer ${key}`;
  return h;
}

/**
 * Try to read one row from a table with the anon key.
 * @param {string} url  project URL, e.g. https://abc.supabase.co
 * @param {string} key  anon/public key
 * @param {string} table
 * @param {typeof fetch} [fetchImpl]
 * @returns {Promise<ProbeResult>}
 */
export async function probeTable(url, key, table, fetchImpl = globalThis.fetch) {
  const endpoint = `${url}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`;
  try {
    const res = await fetchImpl(endpoint, { headers: authHeaders(key) });
    if (res.status === 200) {
      const rows = await res.json();
      const n = Array.isArray(rows) ? rows.length : 0;
      const cols = n > 0 ? Object.keys(rows[0]) : [];
      return {
        target: table, kind: "table", open: n > 0, status: 200, rows: n,
        detail: n > 0
          ? `returned rows; columns: ${cols.join(", ")}`
          : "closed (0 rows returned — RLS filters everything, or the table is empty; an empty table with an open policy would also show this)",
      };
    }
    if (res.status === 401 || res.status === 403) {
      return { target: table, kind: "table", open: false, status: res.status, detail: "blocked (not readable by anon)" };
    }
    if (res.status === 404) {
      return { target: table, kind: "table", open: false, status: 404, detail: "not found (wrong name or not exposed via REST)" };
    }
    const body = await res.text();
    return { target: table, kind: "table", open: false, status: res.status, detail: body.slice(0, 120) };
  } catch (e) {
    return { target: table, kind: "table", open: false, status: 0, detail: `request failed: ${e.message}` };
  }
}

/**
 * Try to list objects in a storage bucket with the anon key.
 * @returns {Promise<ProbeResult>}
 */
export async function probeBucket(url, key, bucket, fetchImpl = globalThis.fetch) {
  const endpoint = `${url}/storage/v1/object/list/${encodeURIComponent(bucket)}`;
  try {
    const res = await fetchImpl(endpoint, {
      method: "POST",
      headers: { ...authHeaders(key), "Content-Type": "application/json" },
      body: JSON.stringify({ prefix: "", limit: 1, offset: 0 }),
    });
    if (res.status === 200) {
      const items = await res.json();
      const n = Array.isArray(items) ? items.length : 0;
      return {
        target: bucket, kind: "bucket", open: n > 0, status: 200,
        detail: n > 0 ? "anon can list objects" : "200 OK but empty listing",
      };
    }
    if ([400, 401, 403, 404].includes(res.status)) {
      return { target: bucket, kind: "bucket", open: false, status: res.status, detail: "not listable by anon" };
    }
    const body = await res.text();
    return { target: bucket, kind: "bucket", open: false, status: res.status, detail: body.slice(0, 120) };
  } catch (e) {
    return { target: bucket, kind: "bucket", open: false, status: 0, detail: `request failed: ${e.message}` };
  }
}

/**
 * Try to call an RPC (Postgres function) with the anon key and empty args.
 * 200 = callable. 400 usually = callable but wants arguments (still worth a look).
 * @returns {Promise<ProbeResult>}
 */
export async function probeRpc(url, key, fn, fetchImpl = globalThis.fetch) {
  const endpoint = `${url}/rest/v1/rpc/${encodeURIComponent(fn)}`;
  try {
    const res = await fetchImpl(endpoint, {
      method: "POST",
      headers: { ...authHeaders(key), "Content-Type": "application/json" },
      body: "{}",
    });
    if (res.status === 200) {
      return { target: fn, kind: "rpc", open: true, status: 200, detail: "anon can call this function (check what it returns / does)" };
    }
    if (res.status === 400) {
      return { target: fn, kind: "rpc", open: true, status: 400, detail: "callable by anon (needs args) — review it" };
    }
    if (res.status === 401 || res.status === 403) {
      return { target: fn, kind: "rpc", open: false, status: res.status, detail: "blocked for anon" };
    }
    if (res.status === 404) {
      return { target: fn, kind: "rpc", open: false, status: 404, detail: "not found" };
    }
    const body = await res.text();
    return { target: fn, kind: "rpc", open: false, status: res.status, detail: body.slice(0, 120) };
  } catch (e) {
    return { target: fn, kind: "rpc", open: false, status: 0, detail: `request failed: ${e.message}` };
  }
}

/**
 * Run all probes for a config.
 * @param {{url:string,key:string,tables?:string[],buckets?:string[],rpc?:string[]}} cfg
 * @param {typeof fetch} [fetchImpl]
 * @returns {Promise<ProbeResult[]>}
 */
export async function runProbes(cfg, fetchImpl = globalThis.fetch) {
  const url = cfg.url.replace(/\/+$/, "");
  const results = [];
  for (const t of cfg.tables ?? []) results.push(await probeTable(url, cfg.key, t, fetchImpl));
  for (const b of cfg.buckets ?? []) results.push(await probeBucket(url, cfg.key, b, fetchImpl));
  for (const f of cfg.rpc ?? []) results.push(await probeRpc(url, cfg.key, f, fetchImpl));
  return results;
}

/** Summarise results: count of open items. */
export function summarize(results) {
  const open = results.filter(r => r.open).length;
  return { total: results.length, open };
}
