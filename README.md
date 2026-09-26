# supabase-security-mcp

[![test](https://github.com/larik15/supabase-security-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/larik15/supabase-security-mcp/actions/workflows/test.yml)
[![npm](https://img.shields.io/npm/v/supabase-security-mcp)](https://www.npmjs.com/package/supabase-security-mcp)

An MCP server that lets Claude, Cursor, or any MCP client audit a Supabase project's
security — the parts the dashboard's Security Advisor doesn't cover.

Ask your assistant *"is my Supabase project safe to ship?"* and it can actually check:

| Tool | What it does | Needs |
|---|---|---|
| `probe_anon` | What a stranger can read with only the public anon key: tables, storage buckets, RPCs | anon key |
| `audit_policies` | Reads `pg_policies` / `pg_class` / `pg_proc`: RLS off on exposed tables, `using (true)` / `with check (true)`, policies with **no `TO` clause** (they apply to PUBLIC), `SECURITY DEFINER` functions callable by anon/authenticated | database URL |
| `two_account_test` | Creates two throwaway users, inserts a row as A, tries to read / update / delete it as B and as anon through the real REST API, then cleans up. The cross-tenant check most people never run | service role key (setup/cleanup only) |
| `security_report` | All of the above as one Markdown report sorted by severity | any of the above |

Everything is read-only except `two_account_test`, which inserts and deletes its own
test rows and users. Nothing is stored. The service role key is used only to create
and delete the two test users.

## Why

In Lovable / Bolt + Supabase apps the pattern repeats: RLS "on", Advisor green, and a
table still readable by anyone — because the policy is `using (true)`, or has no `TO`
clause and silently applies to `anon`, or a `SECURITY DEFINER` function bypasses RLS.
Advisor reports whether RLS is enabled. It doesn't say whether a policy is effectively
public, and it can't tell you that user B can delete user A's rows. These tools do.

## Setup

**Claude Desktop** — `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "supabase-security": {
      "command": "npx",
      "args": ["-y", "supabase-security-mcp"],
      "env": {
        "SUPABASE_URL": "https://YOURREF.supabase.co",
        "SUPABASE_ANON_KEY": "eyJ...",
        "DATABASE_URL": "postgresql://postgres.YOURREF:PASSWORD@aws-0-eu-central-1.pooler.supabase.com:6543/postgres",
        "SUPABASE_SERVICE_ROLE_KEY": "eyJ..."
      }
    }
  }
}
```

**Claude Code**:

```bash
claude mcp add supabase-security -e SUPABASE_URL=... -e SUPABASE_ANON_KEY=... -- npx -y supabase-security-mcp
```

**Cursor** — `.cursor/mcp.json` with the same `command` / `args` / `env` shape.

All env vars are optional — every tool also accepts the same values as arguments,
so the assistant can pass them per call. `DATABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`
are only needed for `audit_policies` and `two_account_test` respectively.

Find the values in Supabase → Project Settings → API (URL, anon, service_role) and
Project Settings → Database (connection string; use the pooler URL).

## Example: a real run

Against a test project with two tables — `leads_open` written the way a rushed
Lovable app usually is (`using (true)` reads, "Service role full access" policies
with no `TO` clause), and `leads_fixed` with proper `auth.uid() = user_id` policies:

```
# Supabase security report
Project: `https://caalmxsprputqeqwotdx.supabase.co`

## Anonymous access (anon key only)
- **OPEN** `table` **leads_open** — returned rows; columns: id, user_id, name, email, deal_value, created_at
- closed `table` **leads_fixed** — 200 OK but no rows (empty table, or RLS returns nothing)

## Two-account test (user B vs user A's rows)
- **leads_open** — owner insert: 201 · other-user select: 200 (1 rows) · anon select: 200 (1 rows) · other-user update: 200 (1 rows) · other-user delete: 200 (1 rows) → **LEAK: other_user_can_read, anon_can_read, other_user_can_update, other_user_can_delete**
- **leads_fixed** — owner insert: 201 · other-user select: 200 (0 rows) · anon select: 200 (0 rows) · other-user update: 200 (0 rows) · other-user delete: 200 (0 rows) → ok

## Findings (5) — critical 2, high 3, medium 0, info 0
- **[critical]** On public.leads_open, another logged-in user can update a row owned by someone else.
  - fix: Update policy must use (user_id = auth.uid()) and with check (user_id = auth.uid()).
- **[critical]** On public.leads_open, another logged-in user can delete a row owned by someone else.
  - fix: Delete policy must use (user_id = auth.uid()).
- **[high]** table leads_open returns data to an anonymous request.
  - fix: Fix the select policy to check ownership.
- **[high]** On public.leads_open, another logged-in user can read a row owned by someone else.
  - fix: Select policy must use (user_id = auth.uid()).
- **[high]** On public.leads_open, an anonymous visitor can read a row owned by someone else.
  - fix: Select policy must use (user_id = auth.uid()).
```

Both tables show `200` on the cross-user calls — PostgREST answers 200 either way.
The difference is the row count: RLS that works returns zero rows, not an error.
That's exactly why "the request succeeded" tells you nothing and this test exists.

Run it from a terminal without an MCP client:

```bash
SUPABASE_URL=... SUPABASE_ANON_KEY=... SUPABASE_SERVICE_ROLE_KEY=... \
node scripts/demo.mjs --tables leads_open,leads_fixed \
  --two leads_open:user_id,leads_fixed:user_id \
  --sample '{"name":"probe","email":"probe@example.test","deal_value":1}'
```

## Two-account test notes

- Give `sampleRow` with values for any NOT NULL columns without defaults.
- `ownerColumn` defaults to `user_id`, `idColumn` to `id`.
- If the owner's own insert is blocked (403), the tool reports that and skips the
  table — that can be intended (server-only writes) or a policy bug; you decide.
- Test users are `rlscheck-a-*@example.com` / `rlscheck-b-*@example.com` and are deleted at the end.

## Keys and safety

- Prefer passing `SUPABASE_SERVICE_ROLE_KEY` / `DATABASE_URL` as arguments on the tool
  call rather than in the MCP server's env. Env values in `claude_desktop_config.json`
  sit there in plain text; a value passed per call only exists for that call.
- Run `audit_policies` against a staging project, or with a read-only database user,
  when you can — it only runs `select` queries against `pg_catalog`, but a read-only
  role means a typo or a future change to this tool can't do more than that by accident.
- `two_account_test` creates two real auth users, inserts a row as one of them, and
  tries to read/update/delete it as the other — then deletes the row and both users.
  Don't run it against production without a backup: a policy bug can leave a row
  modified or deleted by the "wrong" user before the test notices and cleans up.

## Development

```bash
npm install
npm test        # node:test, no network: fake fetch + fake Postgres rows
```

Related: [`supabase-anon-probe`](https://github.com/larik15/supabase-anon-probe) — the
anon-key probe as a standalone CLI (same core).

## License

MIT
