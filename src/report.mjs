// Turn findings from any of the checks into one Markdown report.

const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function sortFindings(findings) {
  return [...findings].sort((a, b) => (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9));
}

export function summarizeFindings(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

/**
 * @param {{ project?: string, probe?: any[], policies?: any, twoAccount?: any }} parts
 */
export function buildReport(parts) {
  const lines = [];
  const all = [];
  lines.push(`# Supabase security report`);
  if (parts.project) lines.push(`Project: \`${parts.project}\``);
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push("");

  if (parts.probe) {
    lines.push(`## Anonymous access (anon key only)`);
    for (const r of parts.probe) {
      lines.push(`- ${r.open ? "**OPEN**" : "closed"} \`${r.kind}\` **${r.target}** — ${r.detail}`);
      if (r.open) all.push({ severity: r.kind === "rpc" ? "medium" : "high", kind: `anon_open_${r.kind}`, table: r.target,
        message: `${r.kind} ${r.target} returns data to an anonymous request.`, fix: r.kind === "bucket" ? "Make the bucket private or scope it with a storage policy." : r.kind === "rpc" ? "Add an auth check inside the function or revoke execute from anon." : "Fix the select policy to check ownership." });
    }
    lines.push("");
  }

  if (parts.policies) {
    lines.push(`## Policy audit (from pg_policies / pg_class / pg_proc)`);
    const t = parts.policies.tables || [];
    lines.push(`Tables in public: ${t.length}; with RLS: ${t.filter(x => x.rls_enabled).length}; policies: ${(parts.policies.policies || []).length}; SECURITY DEFINER functions: ${(parts.policies.functions || []).length}`);
    all.push(...(parts.policies.findings || []));
    lines.push("");
  }

  if (parts.twoAccount) {
    lines.push(`## Two-account test (user B vs user A's rows)`);
    for (const r of parts.twoAccount.results || []) {
      const s = r.steps;
      lines.push(`- **${r.table}** — owner insert: ${s.owner_insert ?? "-"} · other-user select: ${s.other_user_select ?? "-"} · anon select: ${s.anon_select ?? "-"} · other-user update: ${s.other_user_update ?? "-"} · other-user delete: ${s.other_user_delete ?? "-"}${r.leaks.length ? ` → **LEAK: ${r.leaks.join(", ")}**` : " → ok"}`);
      for (const n of r.notes) lines.push(`  - note: ${n}`);
    }
    all.push(...(parts.twoAccount.findings || []));
    lines.push("");
  }

  const sorted = sortFindings(all);
  const counts = summarizeFindings(sorted);
  lines.push(`## Findings (${sorted.length}) — critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, info ${counts.info}`);
  if (!sorted.length) lines.push("Nothing found by these checks. This is not a certificate — it means the anonymous surface, the policy shapes, and the cross-user cases tested here are clean.");
  for (const f of sorted) {
    lines.push(`- **[${f.severity}]** ${f.message}`);
    if (f.fix) lines.push(`  - fix: ${f.fix}`);
  }
  lines.push("");
  return { markdown: lines.join("\n"), findings: sorted, counts };
}
