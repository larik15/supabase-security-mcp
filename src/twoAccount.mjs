// Two-account test. The check every scanner skips: can user B touch user A's row?
// Needs the service role key ONLY to create/delete two throwaway users, to verify two
// write checks, and to clean up test rows. Everything the users do goes through the
// normal REST API with the anon key + their own JWT, exactly like your app does.
//
// What it can't see: PostgREST's ?id=eq.X filter is a WHERE clause, and Postgres
// applies SELECT policies to rows read by UPDATE/DELETE ... WHERE. So a permissive
// UPDATE/DELETE policy hidden behind an owner-only SELECT policy never shows up here;
// audit_policies catches that from the policy text.

import { randomBytes } from "node:crypto";
import { authHeaders } from "./probe.mjs";

function restUrl(url, table, query) {
  return `${url}/rest/v1/${encodeURIComponent(table)}${query ? `?${query}` : ""}`;
}

function eq(col, value) {
  return `${encodeURIComponent(col)}=eq.${encodeURIComponent(value)}`;
}

function userHeaders(anonKey, jwt) {
  const headers = { apikey: anonKey, "Content-Type": "application/json" };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  else if (!/^sb_/.test(anonKey)) headers.Authorization = `Bearer ${anonKey}`;
  return headers;
}

async function safeJson(res) {
  try { return await res.json(); } catch { return null; }
}

function rowCount(body) {
  return Array.isArray(body) ? body.length : 0;
}

async function adminCreateUser(url, serviceKey, email, password, fetchImpl) {
  const res = await fetchImpl(`${url}/auth/v1/admin/users`, {
    method: "POST",
    headers: { ...authHeaders(serviceKey), "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, email_confirm: true }),
  });
  if (res.status !== 200 && res.status !== 201) throw new Error(`create user failed: ${res.status} ${await res.text()}`);
  const j = await res.json();
  return { id: j.id, email };
}

async function adminDeleteUser(url, serviceKey, id, fetchImpl) {
  const res = await fetchImpl(`${url}/auth/v1/admin/users/${id}`, { method: "DELETE", headers: authHeaders(serviceKey) });
  return res.status;
}

async function adminUserExists(url, serviceKey, id, fetchImpl) {
  const res = await fetchImpl(`${url}/auth/v1/admin/users/${id}`, { headers: authHeaders(serviceKey) });
  return res.status !== 404;
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

/**
 * Insert as a user. Tries return=representation first (to learn the row id); if that
 * fails with 42501, the insert may still be allowed and only the RETURNING read denied
 * by the SELECT policy — retry with return=minimal to tell the two apart.
 * @returns {Promise<{status:number, row?:object, writeOnly?:boolean, message?:string}>}
 */
async function insertAs(url, anonKey, jwt, table, row, fetchImpl) {
  const res = await fetchImpl(restUrl(url, table), {
    method: "POST",
    headers: { ...userHeaders(anonKey, jwt), Prefer: "return=representation" },
    body: JSON.stringify(row),
  });
  const body = await safeJson(res);
  if (res.status >= 200 && res.status < 300 && Array.isArray(body) && body[0]) return { status: res.status, row: body[0] };
  if (body?.code === "42501") {
    const retry = await fetchImpl(restUrl(url, table), {
      method: "POST",
      headers: { ...userHeaders(anonKey, jwt), Prefer: "return=minimal" },
      body: JSON.stringify(row),
    });
    if (retry.status >= 200 && retry.status < 300) return { status: retry.status, writeOnly: true };
    const retryBody = await safeJson(retry);
    return { status: retry.status, message: retryBody?.message ?? body?.message };
  }
  return { status: res.status, message: body?.message };
}

/** A column that's safe to "update" to its own value: not the id, not the owner. */
function pickUpdateColumn(inserted, idCol, ownerCol, sampleRow = {}) {
  const candidates = Object.keys(inserted).filter((k) => k !== idCol && k !== ownerCol);
  return candidates.find((k) => k in sampleRow) ?? candidates[0] ?? null;
}

const LEAK_FINDINGS = {
  other_user_can_read: { kind: "cross_tenant_read", severity: "high", text: (t) => `On public.${t}, another logged-in user can read a row owned by someone else.`, fix: (o) => `Select policy must use (${o} = auth.uid()).` },
  anon_can_read: { kind: "anon_read_owned_row", severity: "high", text: (t) => `On public.${t}, an anonymous visitor can read a row owned by a user.`, fix: (o) => `Select policy must use (${o} = auth.uid()) and be "to authenticated".` },
  other_user_can_update: { kind: "cross_tenant_update", severity: "critical", text: (t) => `On public.${t}, another logged-in user can update a row owned by someone else.`, fix: (o) => `Update policy must use (${o} = auth.uid()) and with check (${o} = auth.uid()).` },
  other_user_can_delete: { kind: "cross_tenant_delete", severity: "critical", text: (t) => `On public.${t}, another logged-in user can delete a row owned by someone else.`, fix: (o) => `Delete policy must use (${o} = auth.uid()).` },
  other_user_can_insert_as_owner: { kind: "other_user_can_insert_as_owner", severity: "critical", text: (t, o) => `On public.${t}, a logged-in user can insert a row with ${o} set to another user's id (owner spoofing).`, fix: (o) => `Insert policy must use with check (${o} = auth.uid()).` },
  other_user_can_reassign_owner: { kind: "other_user_can_reassign_owner", severity: "critical", text: (t, o) => `On public.${t}, a user can change ${o} on their own row to another user's id.`, fix: (o) => `Update policy needs with check (${o} = auth.uid()), not just using.` },
};

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

  const tag = randomBytes(4).toString("hex");
  // Fixed prefix covers "must contain upper/lower/digit/symbol" password policies.
  const pw = `Aa1!-${randomBytes(18).toString("base64url")}`;
  const service = authHeaders(serviceRoleKey);
  const users = [];
  const touched = new Map(); // table -> ownerColumn, for cleanup
  const results = [];
  let A;
  let B;
  let cleanup;

  try {
    A = await adminCreateUser(url, serviceRoleKey, `rlscheck-a-${tag}@example.com`, pw, fetchImpl);
    users.push(A);
    B = await adminCreateUser(url, serviceRoleKey, `rlscheck-b-${tag}@example.com`, pw, fetchImpl);
    users.push(B);
    const tokA = await signIn(url, anonKey, A.email, pw, fetchImpl);
    const tokB = await signIn(url, anonKey, B.email, pw, fetchImpl);

    for (const t of cfg.tables) {
      const table = t.name;
      const ownerCol = t.ownerColumn || "user_id";
      const idCol = t.idColumn || "id";
      const sample = t.sampleRow || {};
      const r = { table, ownerColumn: ownerCol, steps: {}, leaks: [], notes: [] };
      touched.set(table, ownerCol);

      // 1. A inserts a row it owns
      const insA = await insertAs(url, anonKey, tokA, table, { ...sample, [ownerCol]: A.id }, fetchImpl);
      r.steps.owner_insert = insA.writeOnly ? `${insA.status} (write-only)` : insA.status;
      const crossChecks = Boolean(insA.row && idCol in insA.row);
      if (insA.writeOnly) {
        r.notes.push("Insert allowed, select denied (write-only table). Read/update/delete/reassign checks skipped: they filter by id, which goes through the SELECT policy and hides the row from everyone but the service role.");
      } else if (!insA.row) {
        r.notes.push(`Could not insert as A (status ${insA.status}). Either inserts are blocked for authenticated users (may be intended), or the sampleRow is missing required columns. Skipping the cross-user checks for this table.`);
        if (insA.message) r.notes.push(`server: ${insA.message}`);
        results.push(r);
        continue;
      } else if (!crossChecks) {
        r.notes.push(`The inserted row has no "${idCol}" column; set idColumn. Skipping the cross-user checks for this table.`);
      }

      if (crossChecks) {
        const id = insA.row[idCol];
        const byId = restUrl(url, table, eq(idCol, id));

        // 2. B tries to read A's row
        const selB = await fetchImpl(`${byId}&select=*`, { headers: userHeaders(anonKey, tokB) });
        const selBBody = await safeJson(selB);
        r.steps.other_user_select = `${selB.status} (${rowCount(selBBody)} rows)`;
        if (selB.status === 200 && rowCount(selBBody) > 0) r.leaks.push("other_user_can_read");

        // 3. anon tries to read A's row
        const selAnon = await fetchImpl(`${byId}&select=*`, { headers: userHeaders(anonKey, null) });
        const selAnonBody = await safeJson(selAnon);
        r.steps.anon_select = `${selAnon.status} (${rowCount(selAnonBody)} rows)`;
        if (selAnon.status === 200 && rowCount(selAnonBody) > 0) r.leaks.push("anon_can_read");

        // 4. B tries to update A's row: one non-key column set to its current value (a no-op if it lands)
        const col = pickUpdateColumn(insA.row, idCol, ownerCol, sample);
        if (col) {
          const upd = await fetchImpl(byId, {
            method: "PATCH",
            headers: { ...userHeaders(anonKey, tokB), Prefer: "return=representation" },
            body: JSON.stringify({ [col]: insA.row[col] }),
          });
          const updBody = await safeJson(upd);
          r.steps.other_user_update = `${upd.status} (${rowCount(updBody)} rows)`;
          if (upd.status === 200 && rowCount(updBody) > 0) r.leaks.push("other_user_can_update");
        } else {
          r.steps.other_user_update = "skipped";
          r.notes.push("No column besides the id and owner columns to test an update with; update check skipped.");
        }

        // 5. B tries to delete A's row
        const del = await fetchImpl(byId, { method: "DELETE", headers: { ...userHeaders(anonKey, tokB), Prefer: "return=representation" } });
        const delBody = await safeJson(del);
        r.steps.other_user_delete = `${del.status} (${rowCount(delBody)} rows)`;
        if (del.status === 200 && rowCount(delBody) > 0) r.leaks.push("other_user_can_delete");

        // 6. sanity: A can read its own row (if B didn't delete it)
        if (!r.leaks.includes("other_user_can_delete")) {
          const selA = await fetchImpl(`${byId}&select=*`, { headers: userHeaders(anonKey, tokA) });
          const selABody = await safeJson(selA);
          r.steps.owner_select = selA.status;
          if (!(selA.status === 200 && rowCount(selABody) > 0)) r.notes.push("Owner cannot read its own row back — select policy may be too strict.");
        }
      }

      // 7. B inserts a row claiming A as the owner (return=minimal: no RETURNING, so the
      //    SELECT policy can't mask a successful write)
      const spoof = await fetchImpl(restUrl(url, table), {
        method: "POST",
        headers: { ...userHeaders(anonKey, tokB), Prefer: "return=minimal" },
        body: JSON.stringify({ ...sample, [ownerCol]: A.id }),
      });
      r.steps.other_user_insert_as_owner = spoof.status;
      if (spoof.status >= 200 && spoof.status < 300) r.leaks.push("other_user_can_insert_as_owner");
      else if (spoof.status === 409) r.notes.push("Insert-as-owner check hit a unique constraint (409) against A's row — inconclusive; use sampleRow values that can repeat.");

      // 8. B creates its own row, then tries to hand it to A. Verified with the service
      //    role, because a SELECT policy would hide the reassigned row from B.
      if (crossChecks) {
        const insB = await insertAs(url, anonKey, tokB, table, { ...sample, [ownerCol]: B.id }, fetchImpl);
        if (insB.row && idCol in insB.row) {
          const bId = insB.row[idCol];
          const patch = await fetchImpl(restUrl(url, table, eq(idCol, bId)), {
            method: "PATCH",
            headers: { ...userHeaders(anonKey, tokB), Prefer: "return=minimal" },
            body: JSON.stringify({ [ownerCol]: A.id }),
          });
          const check = await fetchImpl(restUrl(url, table, `${eq(idCol, bId)}&select=${encodeURIComponent(ownerCol)}`), { headers: service });
          const checkBody = await safeJson(check);
          const nowOwner = Array.isArray(checkBody) ? checkBody[0]?.[ownerCol] : undefined;
          r.steps.other_user_reassign_owner = `${patch.status} (owner now ${nowOwner === A.id ? "A" : nowOwner === B.id ? "B" : "unknown"})`;
          if (nowOwner === A.id) r.leaks.push("other_user_can_reassign_owner");
        } else {
          r.steps.other_user_reassign_owner = "skipped";
          r.notes.push(`B could not create its own row (status ${insB.status}); reassign-owner check skipped.`);
        }
      }

      results.push(r);
    }
  } finally {
    cleanup = await cleanUp({ url, serviceRoleKey, service, users, touched, fetchImpl });
  }

  const findings = [];
  for (const r of results) {
    for (const leak of r.leaks) {
      const spec = LEAK_FINDINGS[leak];
      findings.push({ severity: spec.severity, kind: spec.kind, leak, table: r.table, message: spec.text(r.table, r.ownerColumn), fix: spec.fix(r.ownerColumn) });
    }
  }
  if (!cleanup.cleaned) {
    findings.push({
      severity: "medium", kind: "cleanup_failed", table: null,
      message: `two_account_test could not fully clean up.${cleanup.users.length ? ` Test users still exist: ${cleanup.users.map((u) => `${u.id} (delete returned ${u.deleteStatus})`).join(", ")}.` : ""}${cleanup.rows.length ? ` Test rows left: ${cleanup.rows.map((x) => `${x.table} (${x.count})`).join(", ")}.` : ""}`,
      fix: "Remove them by hand (Authentication → Users; the rows by owner id). A user usually can't be deleted because a table such as public.profiles has a foreign key to auth.users without on delete cascade — delete those rows first, or add on delete cascade.",
    });
  }
  return {
    users: { a: A?.email, b: B?.email, ids: users.map((u) => u.id), cleaned: cleanup.cleaned, leftovers: { users: cleanup.users, rows: cleanup.rows } },
    results,
    findings,
  };
}

/** Delete every test row (by owner = A or B) and both users, then check they're really gone. */
async function cleanUp({ url, serviceRoleKey, service, users, touched, fetchImpl }) {
  const leftRows = [];
  const leftUsers = [];
  const ids = users.map((u) => u.id);

  if (ids.length) {
    for (const [table, ownerCol] of touched) {
      const byOwner = restUrl(url, table, `${encodeURIComponent(ownerCol)}=in.(${ids.map(encodeURIComponent).join(",")})`);
      try {
        await fetchImpl(byOwner, { method: "DELETE", headers: service });
        const left = await fetchImpl(`${byOwner}&select=${encodeURIComponent(ownerCol)}`, { headers: service });
        const n = rowCount(await safeJson(left));
        if (n > 0) leftRows.push({ table, count: n });
      } catch (e) {
        leftRows.push({ table, count: "unknown", error: e.message });
      }
    }
  }

  for (const u of users) {
    let deleteStatus = 0;
    try {
      deleteStatus = await adminDeleteUser(url, serviceRoleKey, u.id, fetchImpl);
      if (await adminUserExists(url, serviceRoleKey, u.id, fetchImpl)) leftUsers.push({ id: u.id, email: u.email, deleteStatus });
    } catch (e) {
      leftUsers.push({ id: u.id, email: u.email, deleteStatus, error: e.message });
    }
  }

  return { cleaned: leftRows.length === 0 && leftUsers.length === 0, rows: leftRows, users: leftUsers };
}
