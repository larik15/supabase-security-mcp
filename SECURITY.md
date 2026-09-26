# Security policy

## Reporting a vulnerability in this tool

Please don't open a public issue. Report it privately through GitHub:
**Security → Report a vulnerability** on
[larik15/supabase-security-mcp](https://github.com/larik15/supabase-security-mcp/security/advisories/new).

Include what you did, what happened, and which version (`npx supabase-security-mcp@x.y.z`).
Reports are handled on a best-effort basis by the maintainer; you'll get an answer in
the advisory thread, and a fix is released before details are made public.

## In scope

This server holds credentials that can read or change a whole Supabase project, so the
interesting bugs are about that:

- the service role key or a database URL being sent anywhere other than the pinned
  project (see "Host pinning" in the README), or leaking into tool output, errors or logs;
- TLS to Postgres being skipped or weakened without an explicit `sslmode=disable` /
  `no-verify` / `insecureSkipTlsVerify`;
- `two_account_test` leaving users or rows behind without reporting `cleanup_failed`,
  or touching rows it didn't create;
- a tool running writes or invoking RPCs when the caller didn't opt in
  (`includeTwoAccount`, `invokeRpc`);
- prompt-injection paths that get the server to do any of the above.

## Out of scope

- Security findings about *your* Supabase project — that's what the tool reports; fix
  them in your project.
- False positives / false negatives in the checks — open a normal issue.
- Anything that requires an attacker who can already edit your MCP client config or
  the server's environment.

## Supported versions

Only the latest release gets fixes. Pin a version in your MCP config (`@0.3.0`) and
upgrade deliberately.
