import { test } from "node:test";
import assert from "node:assert/strict";
import { checkApiUrl, checkDatabaseUrl, supabaseRef } from "../src/guard.mjs";
import { auditPolicies, buildSsl, stripSslParams } from "../src/policies.mjs";

const REF = "abcdefghijklmnopqrst";
const OTHER = "zyxwvutsrqponmlkjihg";

// ---------- host pinning ----------

test("supabaseRef extracts the project ref only from <ref>.supabase.co", () => {
  assert.equal(supabaseRef(`https://${REF}.supabase.co`), REF);
  assert.equal(supabaseRef("https://example.com"), null);
});

test("checkApiUrl: pinned to SUPABASE_URL when it's set", () => {
  const env = { SUPABASE_URL: `https://${REF}.supabase.co` };
  checkApiUrl(`https://${REF}.supabase.co/`, env);
  assert.throws(() => checkApiUrl(`https://${OTHER}.supabase.co`, env), /pinned to/);
  assert.throws(() => checkApiUrl("https://evil.example", env), /pinned to/);
  checkApiUrl(`https://${OTHER}.supabase.co`, { ...env, ALLOWED_HOSTS: `${OTHER}.supabase.co` });
});

test("checkApiUrl: without SUPABASE_URL only https://<ref>.supabase.co or ALLOWED_HOSTS", () => {
  checkApiUrl(`https://${REF}.supabase.co`, {});
  assert.throws(() => checkApiUrl("https://evil.example", {}), /only go to https:\/\/<ref>\.supabase\.co/);
  assert.throws(() => checkApiUrl(`http://${REF}.supabase.co`, {}), /Refusing/);
  assert.throws(() => checkApiUrl(`https://${REF}.supabase.co.evil.example`, {}), /Refusing/);
  checkApiUrl("http://localhost:54321", { ALLOWED_HOSTS: "localhost, 127.0.0.1" });
});

test("checkDatabaseUrl: direct and pooler hosts for the pinned ref only", () => {
  const env = { SUPABASE_URL: `https://${REF}.supabase.co` };
  checkDatabaseUrl(`postgresql://postgres:pw@db.${REF}.supabase.co:5432/postgres`, env);
  checkDatabaseUrl(`postgresql://postgres.${REF}:pw@aws-0-eu-central-1.pooler.supabase.com:6543/postgres`, env);
  assert.throws(() => checkDatabaseUrl(`postgresql://postgres.${OTHER}:pw@aws-0-eu-central-1.pooler.supabase.com:6543/postgres`, env), /pinned to/);
  assert.throws(() => checkDatabaseUrl(`postgresql://postgres:pw@db.${OTHER}.supabase.co:5432/postgres`, env), /pinned to/);
  assert.throws(() => checkDatabaseUrl("postgresql://postgres:pw@evil.example:5432/postgres", env), /Refusing to connect to evil\.example/);
  assert.throws(() => checkDatabaseUrl("postgresql://postgres:pw@aws-0-x.pooler.supabase.com:6543/postgres", {}), /Refusing/, "pooler without a ref in the user name");
  checkDatabaseUrl(`postgresql://postgres.${OTHER}:pw@aws-0-x.pooler.supabase.com:6543/postgres`, {});
  checkDatabaseUrl("postgresql://postgres:pw@localhost:54322/postgres", { ALLOWED_HOSTS: "localhost" });
});

// ---------- TLS ----------

const DSN = `postgresql://postgres:pw@db.${REF}.supabase.co:5432/postgres`;

function fakeClient({ connectError } = {}) {
  const seen = [];
  const queries = [];
  class Client {
    constructor(config) { this.config = config; seen.push(config); seen.queries = queries; }
    async connect() { if (connectError) throw connectError; }
    async query(sql, params) {
      queries.push({ sql, params });
      if (sql.includes("to_regclass")) return { rows: [{ has_storage: false }] };
      return { rows: [] };
    }
    async end() {}
  }
  return { Client, seen };
}

test("TLS: certificate verification is on by default, with system CAs", async () => {
  const { Client, seen } = fakeClient();
  const out = await auditPolicies(DSN, { Client, env: {} });
  assert.equal(seen[0].ssl.rejectUnauthorized, true);
  assert.equal(seen[0].ssl.ca, undefined);
  assert.equal(out.tls, "verified-system");
});

test("TLS: caCert argument or PGSSLROOTCERT supplies the CA", async () => {
  const a = fakeClient();
  await auditPolicies(DSN, { Client: a.Client, env: {} }, { caCert: "-----BEGIN CERTIFICATE-----x" });
  assert.equal(a.seen[0].ssl.ca, "-----BEGIN CERTIFICATE-----x");
  assert.equal(a.seen[0].ssl.rejectUnauthorized, true);

  const b = fakeClient();
  const out = await auditPolicies(DSN, { Client: b.Client, env: { PGSSLROOTCERT: "/ca.crt" }, readFile: (p) => `pem from ${p}` });
  assert.equal(b.seen[0].ssl.ca, "pem from /ca.crt");
  assert.equal(out.tls, "verified-ca");
});

test("TLS: sslmode from the URL is honoured, but require/prefer still verify", async () => {
  assert.equal(stripSslParams(`${DSN}?sslmode=no-verify&application_name=x&sslrootcert=/tmp/a`), `${DSN}?application_name=x`);
  const { Client, seen } = fakeClient();
  await auditPolicies(`${DSN}?sslmode=require`, { Client, env: {} });
  assert.doesNotMatch(seen[0].connectionString, /sslmode/, "ssl params never reach pg, which would let them override");
  assert.equal(seen[0].ssl.rejectUnauthorized, true);

  assert.deepEqual(buildSsl(`${DSN}?sslmode=disable`, {}, { env: {} }), { ssl: false, tls: "disabled" });
  const verifyCa = buildSsl(`${DSN}?sslmode=verify-ca`, {}, { env: {} });
  assert.equal(verifyCa.ssl.rejectUnauthorized, true);
  assert.equal(typeof verifyCa.ssl.checkServerIdentity, "function", "verify-ca checks the chain, not the hostname");
  assert.equal(buildSsl(`${DSN}?sslmode=verify-full`, {}, { env: {} }).ssl.checkServerIdentity, undefined);
  const fromUrl = buildSsl(`${DSN}?sslrootcert=/certs/ca.pem`, {}, { env: { PGSSLROOTCERT: "/other" }, readFile: (p) => `pem:${p}` });
  assert.equal(fromUrl.ssl.ca, "pem:/certs/ca.pem", "sslrootcert in the URL beats PGSSLROOTCERT");
});

test("TLS: only local hosts without an sslmode skip TLS", () => {
  for (const host of ["localhost", "127.0.0.1", "host.docker.internal"]) {
    assert.deepEqual(buildSsl(`postgresql://postgres:pw@${host}:54322/postgres`, {}, { env: {} }), { ssl: false, tls: "none-local" }, host);
  }
  assert.equal(buildSsl("postgresql://postgres:pw@localhost:54322/postgres?sslmode=verify-full", {}, { env: {} }).ssl.rejectUnauthorized, true);
  assert.equal(buildSsl("postgresql://postgres:pw@10.0.0.5:5432/postgres", {}, { env: {} }).ssl.rejectUnauthorized, true);
});

test("TLS: sslmode=no-verify is honoured but logged loudly", () => {
  const logged = [];
  const orig = console.error;
  console.error = (m) => logged.push(m);
  try {
    assert.equal(buildSsl(`${DSN}?sslmode=no-verify`, {}, { env: {} }).tls, "UNVERIFIED");
  } finally {
    console.error = orig;
  }
  assert.match(logged.join("\n"), /sslmode=no-verify/);
});

test("audit: schema is a bind parameter, pg timeouts are set, output has a summary", async () => {
  const { Client, seen } = fakeClient();
  const out = await auditPolicies(DSN, { Client, env: {} }, { schema: "api", ignore: ["api.t:rls_no_policies"] });
  assert.equal(seen[0].connectionTimeoutMillis, 20000);
  assert.equal(seen[0].query_timeout, 20000);
  assert.equal(seen[0].statement_timeout, 20000);
  const withParams = seen.queries.filter((q) => q.params);
  assert.equal(withParams.length, 3);
  assert.ok(withParams.every((q) => q.params[0] === "api" && q.sql.includes("$1")));
  assert.equal(out.summary.schema, "api");
  assert.deepEqual(out.summary.findings, { critical: 0, high: 0, medium: 0, info: 0 });
});

test("TLS: a verification failure explains how to pass Supabase's CA, and never retries insecurely", async () => {
  const err = Object.assign(new Error("self-signed certificate in certificate chain"), { code: "SELF_SIGNED_CERT_IN_CHAIN" });
  const { Client, seen } = fakeClient({ connectError: err });
  await assert.rejects(() => auditPolicies(DSN, { Client, env: {} }), (e) => {
    assert.match(e.message, /PGSSLROOTCERT/);
    assert.match(e.message, /caCert/);
    assert.match(e.message, /prod-ca-2021\.crt/);
    return true;
  });
  assert.equal(seen.length, 1, "no second, unverified attempt");
});

test("TLS: insecureSkipTlsVerify is explicit and logged loudly; localhost skips TLS", () => {
  const logged = [];
  const orig = console.error;
  console.error = (m) => logged.push(m);
  try {
    const r = buildSsl(DSN, { insecureSkipTlsVerify: true }, { env: {} });
    assert.equal(r.ssl.rejectUnauthorized, false);
    assert.equal(r.tls, "UNVERIFIED");
    assert.match(logged.join("\n"), /WARNING: TLS certificate verification is DISABLED/);
  } finally {
    console.error = orig;
  }
  assert.deepEqual(buildSsl("postgresql://postgres:pw@localhost:54322/postgres", {}, { env: {} }), { ssl: false, tls: "none-local" });
});
