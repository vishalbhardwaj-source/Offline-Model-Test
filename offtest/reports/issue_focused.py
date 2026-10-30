from typing import List, Optional
from offtest.core.models import CheckStatus, Finding, RunContext, Severity
from offtest.intake.safety import redact_sensitive_data
from offtest.reports.categorizer import split_findings, sort_findings_by_severity


class IssueFocusedReportGenerator:
    def __init__(self, context: RunContext):
        self.ctx = context

    def _render_findings_list(self, findings: List[Finding], cap_vendor_noise: bool = False) -> List[str]:
        lines: List[str] = []
        crit_issues = [f for f in findings if f.severity == Severity.CRITICAL]
        high_issues = [f for f in findings if f.severity == Severity.HIGH]
        med_issues = [f for f in findings if f.severity == Severity.MEDIUM]
        low_issues = [f for f in findings if f.severity == Severity.LOW]
        info_issues = [f for f in findings if f.severity == Severity.INFORMATIONAL]

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
            sorted_group = sort_findings_by_severity(group)

            # Cap vendor/node_modules noise if specified
            if cap_vendor_noise and len(sorted_group) > 100:
                repo_items = [f for f in sorted_group if "node_modules" not in (f.file_path or "")]
                vendor_items = [f for f in sorted_group if "node_modules" in (f.file_path or "")]
                items_to_render = repo_items + vendor_items[: max(0, 100 - len(repo_items))]
                render_limit = len(items_to_render)
            else:
                items_to_render = sorted_group
                render_limit = len(sorted_group)

            for f in items_to_render:
                loc = f"`{f.file_path}:{f.line_number}`" if f.line_number else (f"`{f.file_path}`" if f.file_path else "Repository level")
                branch_str = f" | Branch: `{f.branch}`" if f.branch else ""
                suppr_badge = " [SUPPRESSED]" if getattr(f, "suppressed", False) else ""
                lines.append(f"\n### [{f.id}]{suppr_badge} {f.title}")
                priority_val = getattr(f, "priority_score", 1.0)
                reach_val = getattr(f, "reachability", "unknown")
                expo_val = getattr(f, "exposure", "internal")
                lines.append(f"- **Priority Score:** `{priority_val}` | **Severity:** `{f.severity.value}` | **Confidence:** `{f.confidence.value}` | **Reachability:** `{reach_val}` | **Exposure:** `{expo_val}`{branch_str}")
                if f.cwe_id:
                    lines.append(f"- **Taxonomy:** `{f.cwe_id}` ({f.cwe_name})")
                if getattr(f, "owasp_category", None) or getattr(f, "asvs_chapter", None):
                    stds = []
                    if getattr(f, "owasp_category", None):
                        stds.append(f"OWASP: {f.owasp_category}")
                    if getattr(f, "asvs_chapter", None):
                        stds.append(f"ASVS: {f.asvs_chapter}")
                    lines.append(f"- **Standards:** {' | '.join(stds)}")
                if f.cvss_score_estimate is not None:
                    lines.append(f"- **Estimated CVSS Base:** `{f.cvss_score_estimate}` _[Heuristic Estimate]_")
                if getattr(f, "suppressed", False):
                    lines.append(f"> [!NOTE]\n> **Suppression Justification:** {getattr(f, 'suppression_reason', 'Inline comment directive')}")
                lines.append(f"- **Location:** {loc}")
                lines.append(f"- **Impact:** {f.impact}")
                lines.append(f"- **Evidence / Reproduction:**\n```\n{f.evidence}\n```")
                lines.append(f"- **Suggested Action:** {f.suggested_action}")

            if len(sorted_group) > render_limit:
                remaining = len(sorted_group) - render_limit
                lines.append(f"\n> [!NOTE]\n> Truncated {remaining} repetitive dependency/vendor findings in this tier. All raw detections are fully recorded in evidence.json and results.sarif.\n")

        return lines

    def _render_header_and_summary(self, title: str, findings: List[Finding], subtitle: Optional[str] = None) -> List[str]:
        lines: List[str] = []
        lines.append(f"# {title}")
        lines.append(f"**Target:** `{self.ctx.repo_name}` | **Run ID:** `{self.ctx.run_id}` | **Commit:** `{self.ctx.commit_hash or 'HEAD'}` | **Working Tree Clean:** `{self.ctx.working_tree_clean}`\n")
        iso_str = "Verified Container / Kernel Air-Gap" if self.ctx.kernel_isolation_active else "Python-level egress guard (Defense in Depth); Kernel Isolation: Not Present (Bare Metal)"
        lines.append(f"**Isolation Mode:** `{iso_str}`\n")

        if subtitle:
            lines.append(f"> [!IMPORTANT]\n> **Scope:** {subtitle}\n")

        if self.ctx.allow_scripts and not self.ctx.kernel_isolation_active:
            lines.append("> [!CAUTION]")
            lines.append("> **UNISOLATED SCRIPT EXECUTION WARNING**")
            lines.append("> Operator explicitly bypassed kernel sandbox boundaries via `--accept-no-kernel-isolation`.")
            lines.append("> Untrusted repository code was executed directly on a bare host without network namespace, container, or read-only filesystem isolation.\n")

        crit_count = len([f for f in findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in findings if f.severity == Severity.HIGH])
        med_count = len([f for f in findings if f.severity == Severity.MEDIUM])
        low_count = len([f for f in findings if f.severity == Severity.LOW])
        info_count = len([f for f in findings if f.severity == Severity.INFORMATIONAL])

        lines.append("## Issue Summary by Severity")
        lines.append("| Severity | Count | Immediate Priority |")
        lines.append("| :--- | :---: | :--- |")
        lines.append(f"| **CRITICAL** | **{crit_count}** | Must resolve before any release or distribution |")
        lines.append(f"| **HIGH** | **{high_count}** | Fix required prior to staging deployment |")
        lines.append(f"| **MEDIUM** | {med_count} | Address in upcoming iteration |")
        lines.append(f"| **LOW** | {low_count} | Clean up during regular maintenance |")
        lines.append(f"| **INFORMATIONAL** | {info_count} | Best-practice observations |")
        lines.append(f"| **TOTAL FINDINGS** | **{len(findings)}** | |")

        blocked_checks = [c for c in self.ctx.check_results if c.status == CheckStatus.BLOCKED]
        if crit_count > 0 or high_count > 0 or len(blocked_checks) > 0:
            lines.append(f"\n> [!CAUTION]\n> **NO CLEAN BILL OF HEALTH**: {crit_count + high_count} high-severity defects identified and {len(blocked_checks)} checks were blocked. Comprehensive security and stability are NOT guaranteed.")

        return lines

    def generate_markdown(self) -> str:
        """
        Generates the standard REPORT_2_ISSUES.md, with findings sorted Critical to Low.
        """
        lines = self._render_header_and_summary("Actionable Issue-Focused Assessment Report", self.ctx.findings)

        # Multi-Language Adapter Coverage Matrix
        coverages = getattr(self.ctx, "language_coverages", {})
        if coverages:
            lines.append("\n## Multi-Language Adapter Coverage & Analysis Depth")
            lines.append("| Language Adapter | Symbols | Call Graph | Reachability | Routes & Auth | Taint & Rules | Test Synthesis | Notes |")
            lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |")
            for c_name, cov in coverages.items():
                cov_dict = cov.model_dump() if hasattr(cov, "model_dump") else cov
                lines.append(f"| **{cov_dict.get('language', c_name)}** | `{cov_dict.get('symbols', 'heuristic')}` | `{cov_dict.get('call_graph', 'heuristic')}` | `{cov_dict.get('reachability', 'heuristic')}` | `{cov_dict.get('routes_and_auth', 'heuristic')}` | `{cov_dict.get('taint_and_rules', 'heuristic')}` | `{cov_dict.get('test_synthesis', 'none')}` | {cov_dict.get('notes') or ''} |")

        lines.extend(self._render_findings_list(self.ctx.findings, cap_vendor_noise=False))

        # Flakiness Quarantine Section
        if self.ctx.flakiness.enabled and self.ctx.flakiness.quarantined_tests:
            lines.append(f"\n## Quarantined Flaky Tests ({len(self.ctx.flakiness.quarantined_tests)})")
            lines.append("> [!WARNING]\n> The following tests demonstrated non-deterministic outcomes across repeated runs and are isolated from blocking regression gates:")
            lines.append("\n| Test Identifier | Total Runs | Passed | Failed | Variance |")
            lines.append("| :--- | :---: | :---: | :---: | :---: |")
            for q in self.ctx.flakiness.quarantined_tests:
                lines.append(f"| **`{q.test_identifier}`** | {q.total_runs} | {q.passed_runs} | {q.failed_runs} | {q.variance_sec}s |")

        # Blocked or Unverified Checks
        blocked_checks = [c for c in self.ctx.check_results if c.status == CheckStatus.BLOCKED]
        skipped_checks = [c for c in self.ctx.check_results if c.status == CheckStatus.SKIPPED]
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

    def generate_hardcoded_markdown(self) -> str:
        """
        Generates Branch 1: REPORT_2A_ISSUES_HARDCODED.md (Hardcoded Secrets & Values only).
        """
        hardcoded, _ = split_findings(self.ctx.findings)
        lines = self._render_header_and_summary(
            "Security Issues: Hardcoded Secrets, Credentials & Tokens",
            hardcoded,
            subtitle="Branch 1: Exclusive focus on hardcoded secrets, passwords, tokens, and high-entropy credentials."
        )
        lines.extend(self._render_findings_list(hardcoded, cap_vendor_noise=True))
        return redact_sensitive_data("\n".join(lines))

    def generate_code_defects_markdown(self) -> str:
        """
        Generates Branch 2: REPORT_2B_ISSUES_CODE_DEFECTS.md (Code defects & vulnerabilities only).
        """
        _, code_defects = split_findings(self.ctx.findings)
        lines = self._render_header_and_summary(
            "Code Quality, Security & Architecture Issues",
            code_defects,
            subtitle="Branch 2: Code vulnerabilities, authorization flaws, runtime bugs, dead code, and unpinned dependencies."
        )
        lines.extend(self._render_findings_list(code_defects, cap_vendor_noise=False))
        return redact_sensitive_data("\n".join(lines))
