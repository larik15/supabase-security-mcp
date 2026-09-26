// Two-account test. The check every scanner skips: can user B touch user A's row?
// Needs the service role key ONLY to create/delete two throwaway users, to verify one
// write check, and to clean up test rows. Everything the users do goes through the
// normal REST API with the anon key + their own JWT, exactly like your app does.
//
// Scope: direct-ownership tables, where one column holds the owner's auth.uid().
// Org/tenant schemas (access via a membership table) need their own test.
//
// What it can't see: PostgREST's ?id=eq.X filter is a WHERE clause, and Postgres
// applies SELECT policies to rows read by UPDATE/DELETE ... WHERE. So a permissive
// UPDATE/DELETE policy hidden behind an owner-only SELECT policy never shows up here;
// audit_policies catches that from the policy text.

import { randomBytes } from "node:crypto";
import { authHeaders, timed, profileHeaders } from "./probe.mjs";

function restUrl(url, table, query) {
  return `${url}/rest/v1/${encodeURIComponent(table)}${query ? `?${query}` : ""}`;
}

function eq(col, value) {
  return `${encodeURIComponent(col)}=eq.${encodeURIComponent(value)}`;
}

async function safeJson(res) {
  try { return await res.json(); } catch { return null; }
}

function rowCount(body) {
  return Array.isArray(body) ? body.length : 0;
}

const ok = (status) => status >= 200 && status < 300;

// What a failed insert usually means, by Postgres / PostgREST error code.
const INSERT_ERROR_HINTS = {
  "42501": "row-level security: no insert policy lets this user write this row",
  "23503": "foreign key violation: a referenced row is missing (e.g. the owner must exist in public.profiles first)",
  "23502": "a NOT NULL column is missing from sampleRow",
  "23505": "unique constraint: a sampleRow value already exists",
  "23514": "check constraint rejected a sampleRow value",
  PGRST204: "a sampleRow column doesn't exist on this table",
  PGRST205: "table not found or not exposed through the API",
  PGRST301: "the user's JWT was rejected",
};

function describeError(status, body) {
  const code = body?.code;
  const hint = INSERT_ERROR_HINTS[code] ?? (status === 401 ? "not authenticated (JWT missing or rejected)" : null);
  const parts = [`status ${status}`];
  if (code) parts.push(`code ${code}`);
  if (hint) parts.push(hint);
  const server = [body?.message, body?.details, body?.hint].filter(Boolean).join(" — ");
  return server ? `${parts.join(", ")}. server: ${server}` : parts.join(", ");
}

/**
 * The context every request in one run shares.
 * @typedef {{ url:string, anonKey:string, serviceRoleKey:string, schema?:string, fetchImpl: typeof fetch }} Ctx
 */

function userHeaders(ctx, jwt, method) {
  const headers = { apikey: ctx.anonKey, "Content-Type": "application/json", ...profileHeaders(ctx.schema, method) };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  else if (!/^sb_/.test(ctx.anonKey)) headers.Authorization = `Bearer ${ctx.anonKey}`;
  return headers;
}

function serviceHeaders(ctx, method) {
  return { ...authHeaders(ctx.serviceRoleKey), ...profileHeaders(ctx.schema, method) };
}

/** A REST call as a user (jwt) or anon (jwt = null). */
function asUser(ctx, jwt, method, target, { body, prefer } = {}) {
  const headers = userHeaders(ctx, jwt, method);
  if (prefer) headers.Prefer = prefer;
  return ctx.fetchImpl(target, timed({ method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }));
}

async function authSettings(ctx) {
  const res = await ctx.fetchImpl(`${ctx.url}/auth/v1/settings`, timed({ headers: { apikey: ctx.anonKey } }));
  return res.status === 200 ? safeJson(res) : null;
}

async function adminCreateUser(ctx, email, password) {
  const res = await ctx.fetchImpl(`${ctx.url}/auth/v1/admin/users`, timed({
    method: "POST",
    headers: { ...authHeaders(ctx.serviceRoleKey), "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, email_confirm: true }),
  }));
  if (!ok(res.status)) {
    const body = await safeJson(res);
    throw new Error(`creating a test user failed: status ${res.status}${body?.msg || body?.message ? ` — ${body.msg || body.message}` : ""}`);
  }
  const j = await res.json();
  return { id: j.id, email };
}

async function signIn(ctx, email, password) {
  const res = await ctx.fetchImpl(`${ctx.url}/auth/v1/token?grant_type=password`, timed({
    method: "POST",
    headers: { apikey: ctx.anonKey, "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  }));
  if (res.status !== 200) {
    const body = await safeJson(res);
    throw new Error(`signing in a test user failed: status ${res.status}${body?.error_description || body?.msg ? ` — ${body.error_description || body.msg}` : ""}`);
  }
  const j = await res.json();
  return j.access_token;
}

/**
 * Insert as a user. Tries return=representation first (to learn the row id); if that
 * fails with 42501, the insert may still be allowed and only the RETURNING read denied
 * by the SELECT policy — retry with return=minimal to tell the two apart.
 * @returns {Promise<{status:number, row?:object, writeOnly?:boolean, error?:string}>}
 */
async function insertAs(ctx, jwt, table, row) {
  const res = await asUser(ctx, jwt, "POST", restUrl(ctx.url, table), { body: row, prefer: "return=representation" });
  const body = await safeJson(res);
  if (ok(res.status) && Array.isArray(body) && body[0]) return { status: res.status, row: body[0] };
  if (body?.code === "42501") {
    const retry = await asUser(ctx, jwt, "POST", restUrl(ctx.url, table), { body: row, prefer: "return=minimal" });
    if (ok(retry.status)) return { status: retry.status, writeOnly: true };
    return { status: retry.status, error: describeError(retry.status, (await safeJson(retry)) ?? body) };
  }
  return { status: res.status, error: describeError(res.status, body) };
}

/** A column that's safe to "update" to its own value: not the id, not the owner. */
function pickUpdateColumn(inserted, idCol, ownerCol, sampleRow = {}) {
  const candidates = Object.keys(inserted).filter((k) => k !== idCol && k !== ownerCol);
  return candidates.find((k) => k in sampleRow) ?? candidates[0] ?? null;
}

// Each leak -> finding. We only know the operation succeeded, not which policy allowed
// it, so the text points at audit_policies instead of naming one.
const LEAKS = {
  other_user_can_read: { kind: "cross_tenant_read", severity: "high", who: "another logged-in user", verb: "read a row owned by someone else", cmd: "SELECT", role: "authenticated" },
  anon_can_read: { kind: "anon_read_owned_row", severity: "high", who: "an anonymous visitor", verb: "read a row owned by a user", cmd: "SELECT", role: "anon" },
  other_user_can_update: { kind: "cross_tenant_update", severity: "critical", who: "another logged-in user", verb: "update a row owned by someone else", cmd: "UPDATE", role: "authenticated" },
  anon_can_update: { kind: "anon_update_owned_row", severity: "critical", who: "an anonymous visitor", verb: "update a row owned by a user", cmd: "UPDATE", role: "anon" },
  other_user_can_delete: { kind: "cross_tenant_delete", severity: "critical", who: "another logged-in user", verb: "delete a row owned by someone else", cmd: "DELETE", role: "authenticated" },
  anon_can_delete: { kind: "anon_delete_owned_row", severity: "critical", who: "an anonymous visitor", verb: "delete a row owned by a user", cmd: "DELETE", role: "anon" },
  other_user_can_insert_as_owner: { kind: "other_user_can_insert_as_owner", severity: "critical", who: "a logged-in user", verb: "insert a row owned by another user (owner spoofing)", cmd: "INSERT", role: "authenticated" },
  other_user_can_reassign_owner: { kind: "other_user_can_reassign_owner", severity: "critical", who: "a logged-in user", verb: "hand their own row to another user by changing the owner column", cmd: "UPDATE", role: "authenticated" },
};

function leakFinding(leak, rel, ownerCol) {
  const l = LEAKS[leak];
  const check = l.cmd === "INSERT" || leak === "other_user_can_reassign_owner" ? `with check (${ownerCol} = auth.uid())` : `using (${ownerCol} = auth.uid())`;
  return {
    severity: l.severity, kind: l.kind, leak, table: rel.split(".").pop(),
    message: `On ${rel}, ${l.who} can ${l.verb}: some policy grants ${l.cmd} to ${l.role} on this table — run audit_policies to see which.`,
    fix: `Every ${l.cmd} policy for ${l.role} on ${rel} needs ${check}${l.role === "anon" ? `, or should be "to authenticated" instead of applying to anon` : ""}.`,
  };
}

/**
 * @param {Object} cfg
 * @param {string} cfg.url
 * @param {string} cfg.anonKey
 * @param {string} cfg.serviceRoleKey
 * @param {string} [cfg.schema]  default public
 * @param {Array<{name:string, ownerColumn?:string, idColumn?:string, sampleRow?:object}>} cfg.tables
 * @param {typeof fetch} [fetchImpl]
 */
export async function twoAccountTest(cfg, fetchImpl = globalThis.fetch) {
  if (!cfg.serviceRoleKey) throw new Error("two_account_test needs the service role key to create two temporary users (never stored, only used for setup/cleanup).");
  const schema = cfg.schema || "public";
  const ctx = { url: cfg.url.replace(/\/+$/, ""), anonKey: cfg.anonKey, serviceRoleKey: cfg.serviceRoleKey, schema, fetchImpl };

  const settings = await authSettings(ctx);
  if (settings?.external && settings.external.email === false) {
    throw new Error("two_account_test signs its test users in with email + password, but the Email provider is disabled on this project (Authentication → Sign In / Providers → Email). Enable it, or skip this test. Nothing was created.");
  }

  const tag = randomBytes(4).toString("hex");
  // Fixed prefix covers "must contain upper/lower/digit/symbol" password policies.
  const pw = `Aa1!-${randomBytes(18).toString("base64url")}`;
  const users = [];
  const touched = new Map(); // table -> ownerColumn, for cleanup
  const results = [];
  let A;
  let B;
  let cleanup;

  try {
    A = await adminCreateUser(ctx, `rlscheck-a-${tag}@example.com`, pw);
    users.push(A);
    B = await adminCreateUser(ctx, `rlscheck-b-${tag}@example.com`, pw);
    users.push(B);
    const tokA = await signIn(ctx, A.email, pw);
    const tokB = await signIn(ctx, B.email, pw);

    for (const t of cfg.tables) {
      const table = t.name;
      const ownerCol = t.ownerColumn || "user_id";
      const idCol = t.idColumn || "id";
      const sample = t.sampleRow || {};
      const r = { table, schema, ownerColumn: ownerCol, steps: {}, leaks: [], notes: [] };
      touched.set(table, ownerCol);

      // 1. A inserts a row it owns
      const insA = await insertAs(ctx, tokA, table, { ...sample, [ownerCol]: A.id });
      r.steps.owner_insert = insA.writeOnly ? `${insA.status} (write-only)` : insA.status;
      const crossChecks = Boolean(insA.row && idCol in insA.row);
      if (insA.writeOnly) {
        r.notes.push("Insert allowed, select denied (write-only table). Read/update/delete/reassign checks skipped: they filter by id, which goes through the SELECT policy and hides the row from everyone but the service role.");
      } else if (!insA.row) {
        r.notes.push(`Could not insert as A (${insA.error}). Skipping the cross-user checks for this table.`);
        results.push(r);
        continue;
      } else if (!crossChecks) {
        r.notes.push(`The inserted row has no "${idCol}" column; set idColumn. Skipping the cross-user checks for this table.`);
      }

      if (crossChecks) {
        let id = insA.row[idCol];
        const byId = () => restUrl(ctx.url, table, eq(idCol, id));
        const col = pickUpdateColumn(insA.row, idCol, ownerCol, sample);
        const noop = col ? { [col]: insA.row[col] } : null;

        // 2-3. B and anon try to read A's row
        for (const [who, jwt, step, leak] of [["B", tokB, "other_user_select", "other_user_can_read"], ["anon", null, "anon_select", "anon_can_read"]]) {
          const res = await asUser(ctx, jwt, "GET", `${byId()}&select=*`);
          const n = rowCount(await safeJson(res));
          r.steps[step] = `${res.status} (${n} rows)`;
          if (res.status === 200 && n > 0) r.leaks.push(leak);
        }

        // 4-5. B and anon try to update A's row: one non-key column set to its current
        //      value (a no-op if it lands). Never an empty PATCH.
        if (noop) {
          for (const [jwt, step, leak] of [[tokB, "other_user_update", "other_user_can_update"], [null, "anon_update", "anon_can_update"]]) {
            const res = await asUser(ctx, jwt, "PATCH", byId(), { body: noop, prefer: "return=representation" });
            const n = rowCount(await safeJson(res));
            r.steps[step] = `${res.status} (${n} rows)`;
            if (res.status === 200 && n > 0) r.leaks.push(leak);
          }
        } else {
          r.steps.other_user_update = r.steps.anon_update = "skipped";
          r.notes.push("No column besides the id and owner columns to test an update with; update checks skipped.");
        }

        // 6. anon tries to delete A's row; if it can, A inserts a fresh one for B's turn
        const delAnon = await asUser(ctx, null, "DELETE", byId(), { prefer: "return=representation" });
        const delAnonN = rowCount(await safeJson(delAnon));
        r.steps.anon_delete = `${delAnon.status} (${delAnonN} rows)`;
        if (delAnon.status === 200 && delAnonN > 0) {
          r.leaks.push("anon_can_delete");
          const again = await insertAs(ctx, tokA, table, { ...sample, [ownerCol]: A.id });
          if (again.row && idCol in again.row) id = again.row[idCol];
        }

        // 7. B tries to delete A's row
        const delB = await asUser(ctx, tokB, "DELETE", byId(), { prefer: "return=representation" });
        const delBN = rowCount(await safeJson(delB));
        r.steps.other_user_delete = `${delB.status} (${delBN} rows)`;
        if (delB.status === 200 && delBN > 0) r.leaks.push("other_user_can_delete");
      }

      // 8. B inserts a row claiming A as the owner (return=minimal: no RETURNING, so the
      //    SELECT policy can't mask a successful write)
      const spoof = await asUser(ctx, tokB, "POST", restUrl(ctx.url, table), { body: { ...sample, [ownerCol]: A.id }, prefer: "return=minimal" });
      r.steps.other_user_insert_as_owner = spoof.status;
      if (ok(spoof.status)) r.leaks.push("other_user_can_insert_as_owner");
      else if (spoof.status === 409) r.notes.push("Insert-as-owner check hit a unique constraint (409) against A's row — inconclusive; use sampleRow values that can repeat.");

      // 9. B creates its own row, then tries to hand it to A. Verified with the service
      //    role, because a SELECT policy would hide the reassigned row from B.
      if (crossChecks) {
        const insB = await insertAs(ctx, tokB, table, { ...sample, [ownerCol]: B.id });
        if (insB.row && idCol in insB.row) {
          const bId = insB.row[idCol];
          const patch = await asUser(ctx, tokB, "PATCH", restUrl(ctx.url, table, eq(idCol, bId)), { body: { [ownerCol]: A.id }, prefer: "return=minimal" });
          const check = await fetchImpl(restUrl(ctx.url, table, `${eq(idCol, bId)}&select=${encodeURIComponent(ownerCol)}`), timed({ headers: serviceHeaders(ctx, "GET") }));
          const checkBody = await safeJson(check);
          const nowOwner = Array.isArray(checkBody) ? checkBody[0]?.[ownerCol] : undefined;
          r.steps.other_user_reassign_owner = `${patch.status} (owner now ${nowOwner === A.id ? "A" : nowOwner === B.id ? "B" : "unknown"})`;
          if (nowOwner === A.id) r.leaks.push("other_user_can_reassign_owner");
        } else {
          r.steps.other_user_reassign_owner = "skipped";
          r.notes.push(`B could not create its own row (${insB.error ?? "no id returned"}); reassign-owner check skipped.`);
        }
      }

      results.push(r);
    }
  } finally {
    cleanup = await cleanUp(ctx, users, touched);
  }

  const findings = [];
  for (const r of results) for (const leak of r.leaks) findings.push(leakFinding(leak, `${schema}.${r.table}`, r.ownerColumn));
  if (!cleanup.cleaned) {
    const u = cleanup.users.map((x) => `${x.id} (${x.error ?? `delete returned ${x.deleteStatus}, user still exists`})`);
    const rows = cleanup.rows.map((x) => `${schema}.${x.table} (${x.error ?? `${x.left} row(s) left`})`);
    findings.push({
      severity: "medium", kind: "cleanup_failed", table: null,
      message: `two_account_test could not fully clean up.${u.length ? ` Test users: ${u.join(", ")}.` : ""}${rows.length ? ` Test rows: ${rows.join(", ")}.` : ""}`,
      fix: "Remove them by hand (Authentication → Users; the rows by owner id). A user usually can't be deleted because a table such as public.profiles has a foreign key to auth.users without on delete cascade — delete those rows first, or add on delete cascade.",
    });
  }
  return {
    users: { a: A?.email, b: B?.email, ids: users.map((x) => x.id), cleaned: cleanup.cleaned, failures: { users: cleanup.users, rows: cleanup.rows } },
    results,
    findings,
  };
}

/**
 * Delete every test row (owner = A or B) and both users, checking each status and then
 * re-querying. Returns every failure; nothing is swallowed.
 */
async function cleanUp(ctx, users, touched) {
  const rows = [];
  const left = [];
  const ids = users.map((u) => u.id);

  if (ids.length) {
    for (const [table, ownerCol] of touched) {
      const byOwner = restUrl(ctx.url, table, `${encodeURIComponent(ownerCol)}=in.(${ids.map(encodeURIComponent).join(",")})`);
      try {
        const del = await ctx.fetchImpl(byOwner, timed({ method: "DELETE", headers: serviceHeaders(ctx, "DELETE") }));
        if (!ok(del.status)) {
          const body = await safeJson(del);
          rows.push({ table, error: `delete returned ${describeError(del.status, body)}` });
          continue;
        }
        const check = await ctx.fetchImpl(`${byOwner}&select=${encodeURIComponent(ownerCol)}`, timed({ headers: serviceHeaders(ctx, "GET") }));
        const n = rowCount(await safeJson(check));
        if (!ok(check.status)) rows.push({ table, error: `re-query returned status ${check.status}` });
        else if (n > 0) rows.push({ table, left: n });
      } catch (e) {
        rows.push({ table, error: e.message });
      }
    }
  }

  for (const u of users) {
    let deleteStatus = 0;
    try {
      const del = await ctx.fetchImpl(`${ctx.url}/auth/v1/admin/users/${u.id}`, timed({ method: "DELETE", headers: authHeaders(ctx.serviceRoleKey) }));
      deleteStatus = del.status;
      const get = await ctx.fetchImpl(`${ctx.url}/auth/v1/admin/users/${u.id}`, timed({ headers: authHeaders(ctx.serviceRoleKey) }));
      if (get.status !== 404) left.push({ id: u.id, email: u.email, deleteStatus });
    } catch (e) {
      left.push({ id: u.id, email: u.email, deleteStatus, error: e.message });
    }
  }

  return { cleaned: rows.length === 0 && left.length === 0, rows, users: left };
}
