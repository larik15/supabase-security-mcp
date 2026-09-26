// Host pinning for privileged credentials.
//
// Tool arguments come from the model, and the model reads untrusted text: web pages,
// issue comments, database rows returned by a probe. A prompt injection in any of
// those can ask the assistant to "re-run two_account_test against https://evil.example"
// — and the server would happily attach the service role key from its env. So before
// the service role key or a database URL leaves this process, the destination must be
// the project the user configured (SUPABASE_URL), or at least look like a Supabase
// project, or be on an explicit allow-list (ALLOWED_HOSTS, comma-separated hostnames).

const SUPABASE_API_HOST = /^([a-z0-9]{20})\.supabase\.co$/;
const SUPABASE_DB_HOST = /^db\.([a-z0-9]{20})\.supabase\.co$/;
const SUPABASE_POOLER_HOST = /^[a-z0-9-]+\.pooler\.supabase\.com$/;

function allowedHosts(env) {
  return String(env.ALLOWED_HOSTS || "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
}

function parseUrl(value, what) {
  try {
    return new URL(value);
  } catch {
    throw new Error(`${what} is not a valid URL.`);
  }
}

/** Project ref from https://<ref>.supabase.co, or null for any other host. */
export function supabaseRef(url) {
  const m = parseUrl(url, "url").hostname.toLowerCase().match(SUPABASE_API_HOST);
  return m ? m[1] : null;
}

/**
 * Throw unless it's safe to send the service role key to `url`.
 * @param {string} url
 * @param {Record<string,string|undefined>} [env]
 */
export function checkApiUrl(url, env = process.env) {
  const target = parseUrl(url, "url");
  const host = target.hostname.toLowerCase();
  const allowed = allowedHosts(env);
  if (allowed.includes(host)) return;

  if (env.SUPABASE_URL) {
    const pinned = parseUrl(env.SUPABASE_URL, "SUPABASE_URL");
    if (target.protocol === pinned.protocol && target.host.toLowerCase() === pinned.host.toLowerCase()) return;
    throw new Error(
      `Refusing to send the service role key to ${target.host}: this server is pinned to ${pinned.host} (SUPABASE_URL). ` +
        `If you really mean another project, add its hostname to ALLOWED_HOSTS in the MCP server env.`
    );
  }

  if (target.protocol === "https:" && SUPABASE_API_HOST.test(host)) return;
  throw new Error(
    `Refusing to send the service role key to ${target.host}: without SUPABASE_URL in the server env, privileged calls ` +
      `only go to https://<ref>.supabase.co. Set SUPABASE_URL, or list the host in ALLOWED_HOSTS.`
  );
}

/**
 * Throw unless it's safe to connect (and send the password in) `databaseUrl`.
 * Accepts db.<ref>.supabase.co and the Supavisor pooler (*.pooler.supabase.com with
 * user postgres.<ref>); when SUPABASE_URL is set, the ref must match it.
 * @param {string} databaseUrl
 * @param {Record<string,string|undefined>} [env]
 */
export function checkDatabaseUrl(databaseUrl, env = process.env) {
  const dsn = parseUrl(databaseUrl, "databaseUrl");
  const host = dsn.hostname.toLowerCase();
  if (allowedHosts(env).includes(host)) return;

  let ref = null;
  const direct = host.match(SUPABASE_DB_HOST);
  if (direct) ref = direct[1];
  else if (SUPABASE_POOLER_HOST.test(host)) {
    const user = decodeURIComponent(dsn.username || "");
    const m = user.match(/\.([a-z0-9]{20})$/);
    ref = m ? m[1] : null;
  }
  if (!ref) {
    throw new Error(
      `Refusing to connect to ${host}: database URLs must point at db.<ref>.supabase.co or a *.pooler.supabase.com ` +
        `pooler (user postgres.<ref>). For another host, list it in ALLOWED_HOSTS in the MCP server env.`
    );
  }

  const pinnedRef = env.SUPABASE_URL ? supabaseRef(env.SUPABASE_URL) : null;
  if (env.SUPABASE_URL && pinnedRef && pinnedRef !== ref) {
    throw new Error(
      `Refusing to connect: the database URL is for project ${ref}, but this server is pinned to ${pinnedRef} (SUPABASE_URL). ` +
        `Add the host to ALLOWED_HOSTS if that's intended.`
    );
  }
}
