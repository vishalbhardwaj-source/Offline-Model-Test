from offtest.core.models import CheckStatus, RunContext, Severity
from offtest.intake.safety import redact_sensitive_data


class IssueFocusedReportGenerator:
    def __init__(self, context: RunContext):
        self.ctx = context

    def generate_markdown(self) -> str:
        lines = []

        lines.append("# Actionable Issue-Focused Assessment Report")
        lines.append(f"**Target:** `{self.ctx.repo_name}` | **Run ID:** `{self.ctx.run_id}` | **Commit:** `{self.ctx.commit_hash or 'HEAD'}` | **Working Tree Clean:** `{self.ctx.working_tree_clean}`\n")
        iso_str = "Verified Container / Kernel Air-Gap" if self.ctx.kernel_isolation_active else "Python-level egress guard (Defense in Depth); Kernel Isolation: Not Present (Bare Metal)"
        lines.append(f"**Isolation Mode:** `{iso_str}`\n")

        # Counts
        crit_issues = [f for f in self.ctx.findings if f.severity == Severity.CRITICAL]
        high_issues = [f for f in self.ctx.findings if f.severity == Severity.HIGH]
        med_issues = [f for f in self.ctx.findings if f.severity == Severity.MEDIUM]
        low_issues = [f for f in self.ctx.findings if f.severity == Severity.LOW]
        info_issues = [f for f in self.ctx.findings if f.severity == Severity.INFORMATIONAL]

        # Status summary
        lines.append("## Issue Summary by Severity")
        lines.append("| Severity | Count | Immediate Priority |")
        lines.append("| :--- | :---: | :--- |")
        lines.append(f"| **CRITICAL** | **{len(crit_issues)}** | Must resolve before any release or distribution |")
        lines.append(f"| **HIGH** | **{len(high_issues)}** | Fix required prior to staging deployment |")
        lines.append(f"| **MEDIUM** | {len(med_issues)} | Address in upcoming iteration |")
        lines.append(f"| **LOW** | {len(low_issues)} | Clean up during regular maintenance |")
        lines.append(f"| **INFORMATIONAL** | {len(info_issues)} | Best-practice observations |")
        lines.append(f"| **TOTAL FINDINGS** | **{len(self.ctx.findings)}** | |")

        # Warning banner if critical/high or blocked checks
        blocked_checks = [c for c in self.ctx.check_results if c.status == CheckStatus.BLOCKED]
        skipped_checks = [c for c in self.ctx.check_results if c.status == CheckStatus.SKIPPED]

        if len(crit_issues) > 0 or len(high_issues) > 0 or len(blocked_checks) > 0:
            lines.append(f"\n> [!CAUTION]\n> **NO CLEAN BILL OF HEALTH**: {len(crit_issues) + len(high_issues)} high-severity defects identified and {len(blocked_checks)} checks were blocked. Comprehensive security and stability are NOT guaranteed.")

        # Grouped issues
        severity_groups = [
            ("Critical Severity Issues", crit_issues),
            ("High Severity Issues", high_issues),
            ("Medium Severity Issues", med_issues),
            ("Low Severity Issues", low_issues),
            ("Informational Observations", info_issues),
        ]

        for title, group in severity_groups:
            if not group:
                continue
            lines.append(f"\n## {title} ({len(group)})")
            for f in group:
                loc = f"`{f.file_path}:{f.line_number}`" if f.line_number else (f"`{f.file_path}`" if f.file_path else "Repository level")
                branch_str = f" | Branch: `{f.branch}`" if f.branch else ""
                lines.append(f"\n### [{f.id}] {f.title}")
                lines.append(f"- **Severity:** `{f.severity.value}` | **Confidence:** `{f.confidence.value}` | **Status:** `{f.status.value}`{branch_str}")
                if f.cwe_id:
                    lines.append(f"- **Taxonomy:** `{f.cwe_id}` ({f.cwe_name})")
                if f.cvss_score_estimate is not None:
                    lines.append(f"- **Estimated CVSS Base:** `{f.cvss_score_estimate}` _[Heuristic Estimate]_")
                lines.append(f"- **Location:** {loc}")
                lines.append(f"- **Impact:** {f.impact}")
                lines.append(f"- **Evidence / Reproduction:**\n```\n{f.evidence}\n```")
                lines.append(f"- **Suggested Action:** {f.suggested_action}")

        # Flakiness Quarantine Section
        if self.ctx.flakiness.enabled and self.ctx.flakiness.quarantined_tests:
            lines.append(f"\n## Quarantined Flaky Tests ({len(self.ctx.flakiness.quarantined_tests)})")
            lines.append("> [!WARNING]\n> The following tests demonstrated non-deterministic outcomes across repeated runs and are isolated from blocking regression gates:")
            lines.append("\n| Test Identifier | Total Runs | Passed | Failed | Variance |")
            lines.append("| :--- | :---: | :---: | :---: | :---: |")
            for q in self.ctx.flakiness.quarantined_tests:
                lines.append(f"| **`{q.test_identifier}`** | {q.total_runs} | {q.passed_runs} | {q.failed_runs} | {q.variance_sec}s |")

        # Blocked or Unverified Checks
        lines.append("\n## Blocked & Unverified Checks")
        if blocked_checks or skipped_checks:
            lines.append("| Check Name | Status | Tool | Reason / Blocker |")
            lines.append("| :--- | :---: | :--- | :--- |")
            for b in blocked_checks:
                lines.append(f"| **{b.check_name}** | **BLOCKED** | `{b.tool_name}` | {b.skip_or_blocked_reason} |")
            for s in skipped_checks:
                lines.append(f"| **{s.check_name}** | **SKIPPED** | `{s.tool_name}` | {s.skip_or_blocked_reason} |")
        else:
            lines.append("_No checks were blocked or skipped._")

        # Top Coverage Gaps
        lines.append("\n## Key Coverage Gaps")
        gaps = [d for d in self.ctx.coverage.dimensions if not d.is_available or (d.value_pct is not None and d.value_pct < 100.0)]
        if gaps:
            for g in gaps:
                val = f"{g.value_pct}%" if g.value_pct is not None else "UNAVAILABLE"
                lines.append(f"- **{g.name} ({val}):** {g.explanation}")
        else:
            lines.append("- All evaluated dimensions reached 100% within current offline tools.")

        return redact_sensitive_data("\n".join(lines))
