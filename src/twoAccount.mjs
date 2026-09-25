// Two-account test. The check every scanner skips: can user B touch user A's row?
// Needs the service role key ONLY to create/delete two throwaway users and to clean
// up test rows. Everything the users do goes through the normal REST API with the
// anon key + their own JWT, exactly like your app does.

import { authHeaders } from "./probe.mjs";

function rid() {
  return Math.random().toString(36).slice(2, 10);
}

async function adminCreateUser(url, serviceKey, email, password, fetchImpl) {
  const res = await fetchImpl(`${url}/auth/v1/admin/users`, {
    method: "POST",
    headers: { ...authHeaders(serviceKey), "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, email_confirm: true }),
  });
  if (res.status !== 200 && res.status !== 201) throw new Error(`create user failed: ${res.status} ${await res.text()}`);
  const j = await res.json();
  return { id: j.id, email, password };
}

async function adminDeleteUser(url, serviceKey, id, fetchImpl) {
  await fetchImpl(`${url}/auth/v1/admin/users/${id}`, {
    method: "DELETE",
    headers: authHeaders(serviceKey),
  });
}

async function signIn(url, anonKey, email, password, fetchImpl) {
  const res = await fetchImpl(`${url}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: anonKey, "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (res.status !== 200) throw new Error(`sign in failed: ${res.status} ${await res.text()}`);
  const j = await res.json();
  return j.access_token;
}

function rest(url, anonKey, jwt) {
  const headers = { apikey: anonKey, "Content-Type": "application/json" };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  else if (!/^sb_/.test(anonKey)) headers.Authorization = `Bearer ${anonKey}`;
  return { headers };
}

async function safeJson(res) {
  try { return await res.json(); } catch { return null; }
}

/**
 * @param {Object} cfg
 * @param {string} cfg.url
 * @param {string} cfg.anonKey
 * @param {string} cfg.serviceRoleKey
 * @param {Array<{name:string, ownerColumn?:string, idColumn?:string, sampleRow?:object}>} cfg.tables
 * @param {typeof fetch} [fetchImpl]
 */
export async function twoAccountTest(cfg, fetchImpl = globalThis.fetch) {
  const url = cfg.url.replace(/\/+$/, "");
  const { anonKey, serviceRoleKey } = cfg;
  if (!serviceRoleKey) throw new Error("two_account_test needs the service role key to create two temporary users (never stored, only used for setup/cleanup).");

  const tag = rid();
  const pw = `Tt-${rid()}-${rid()}!`;
  const A = await adminCreateUser(url, serviceRoleKey, `rlscheck-a-${tag}@example.com`, pw, fetchImpl);
  const B = await adminCreateUser(url, serviceRoleKey, `rlscheck-b-${tag}@example.com`, pw, fetchImpl);
  const results = [];
  const created = []; // rows to clean up: {table, idColumn, id}

  try {
    const tokA = await signIn(url, anonKey, A.email, pw, fetchImpl);
    const tokB = await signIn(url, anonKey, B.email, pw, fetchImpl);

    for (const t of cfg.tables) {
      const table = t.name;
      const ownerCol = t.ownerColumn || "user_id";
      const idCol = t.idColumn || "id";
      const r = { table, ownerColumn: ownerCol, steps: {}, leaks: [], notes: [] };

      // 1. A inserts a row it owns
      const row = { ...(t.sampleRow || {}), [ownerCol]: A.id };
      const ins = await fetchImpl(`${url}/rest/v1/${encodeURIComponent(table)}`, {
        method: "POST",
        headers: { ...rest(url, anonKey, tokA).headers, Prefer: "return=representation" },
        body: JSON.stringify(row),
      });
      const insBody = await safeJson(ins);
      const inserted = Array.isArray(insBody) ? insBody[0] : null;
      r.steps.owner_insert = ins.status;
      if (!inserted || !(idCol in inserted)) {
        r.notes.push(`Could not insert as A (status ${ins.status}). Either inserts are blocked for authenticated users (may be intended), the sampleRow is missing required columns, or the id column is not "${idCol}". Skipping cross-checks for this table.`);
        if (insBody && insBody.message) r.notes.push(`server: ${insBody.message}`);
        results.push(r);
        continue;
      }
      const id = inserted[idCol];
      created.push({ table, idCol, id });

      // 2. B tries to read A's row
      const selB = await fetchImpl(`${url}/rest/v1/${encodeURIComponent(table)}?${idCol}=eq.${encodeURIComponent(id)}&select=*`, { headers: rest(url, anonKey, tokB).headers });
      const selBody = await safeJson(selB);
      r.steps.other_user_select = `${selB.status} (${Array.isArray(selBody) ? selBody.length : 0} rows)`;
      if (selB.status === 200 && Array.isArray(selBody) && selBody.length > 0) r.leaks.push("other_user_can_read");

      // 3. anon tries to read A's row
      const selAnon = await fetchImpl(`${url}/rest/v1/${encodeURIComponent(table)}?${idCol}=eq.${encodeURIComponent(id)}&select=*`, { headers: rest(url, anonKey, null).headers });
      const selAnonBody = await safeJson(selAnon);
      r.steps.anon_select = `${selAnon.status} (${Array.isArray(selAnonBody) ? selAnonBody.length : 0} rows)`;
      if (selAnon.status === 200 && Array.isArray(selAnonBody) && selAnonBody.length > 0) r.leaks.push("anon_can_read");

      // 4. B tries to update A's row (re-sends the same sample values; no-op if it lands)
      const upd = await fetchImpl(`${url}/rest/v1/${encodeURIComponent(table)}?${idCol}=eq.${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: { ...rest(url, anonKey, tokB).headers, Prefer: "return=representation" },
        body: JSON.stringify({ ...(t.sampleRow || {}) }),
      });
      const updBody = await safeJson(upd);
      r.steps.other_user_update = `${upd.status} (${Array.isArray(updBody) ? updBody.length : 0} rows)`;
      if ((upd.status === 200 || upd.status === 204) && Array.isArray(updBody) && updBody.length > 0) r.leaks.push("other_user_can_update");

      // 5. B tries to delete A's row
      const del = await fetchImpl(`${url}/rest/v1/${encodeURIComponent(table)}?${idCol}=eq.${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers: { ...rest(url, anonKey, tokB).headers, Prefer: "return=representation" },
      });
      const delBody = await safeJson(del);
      r.steps.other_user_delete = `${del.status} (${Array.isArray(delBody) ? delBody.length : 0} rows)`;
      if ((del.status === 200 || del.status === 204) && Array.isArray(delBody) && delBody.length > 0) {
        r.leaks.push("other_user_can_delete");
        created.pop(); // already gone
      }

      // 6. sanity: A can read its own row (if B didn't delete it)
      if (!r.leaks.includes("other_user_can_delete")) {
        const selA = await fetchImpl(`${url}/rest/v1/${encodeURIComponent(table)}?${idCol}=eq.${encodeURIComponent(id)}&select=*`, { headers: rest(url, anonKey, tokA).headers });
        const selABody = await safeJson(selA);
        r.steps.owner_select = selA.status;
        if (!(selA.status === 200 && Array.isArray(selABody) && selABody.length > 0)) r.notes.push("Owner cannot read its own row back — select policy may be too strict.");
      }

      results.push(r);
    }
  } finally {
    // cleanup rows with service role, then users
    for (const c of created) {
      try {
        await fetchImpl(`${url}/rest/v1/${encodeURIComponent(c.table)}?${c.idCol}=eq.${encodeURIComponent(c.id)}`, {
          method: "DELETE",
          headers: authHeaders(serviceRoleKey),
        });
      } catch {}
    }
    await adminDeleteUser(url, serviceRoleKey, A.id, fetchImpl).catch(() => {});
    await adminDeleteUser(url, serviceRoleKey, B.id, fetchImpl).catch(() => {});
  }

  const findings = [];
  for (const r of results) {
    for (const leak of r.leaks) {
      const sev = leak.includes("delete") || leak.includes("update") ? "critical" : "high";
      const who = leak.startsWith("anon") ? "an anonymous visitor" : "another logged-in user";
      const what = leak.endsWith("read") ? "read" : leak.endsWith("update") ? "update" : "delete";
      findings.push({
        severity: sev, kind: `cross_tenant_${what}`, table: r.table,
        message: `On public.${r.table}, ${who} can ${what} a row owned by someone else.`,
        fix: what === "read"
          ? `Select policy must use (${r.ownerColumn} = auth.uid()).`
          : what === "update"
            ? `Update policy must use (${r.ownerColumn} = auth.uid()) and with check (${r.ownerColumn} = auth.uid()).`
            : `Delete policy must use (${r.ownerColumn} = auth.uid()).`,
      });
    }
  }
  return { users: { a: A.email, b: B.email, cleaned: true }, results, findings };
}
