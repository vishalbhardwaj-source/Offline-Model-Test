from pathlib import Path
from typing import List, Optional
from offtest.core.models import EvidenceStatus, Finding, RunContext, Severity
from offtest.intake.safety import redact_sensitive_data
from offtest.reports.categorizer import split_findings, sort_findings_by_severity


class DetailedReportGenerator:
    def __init__(self, context: RunContext):
        self.ctx = context

    def _render_finding_card(self, f: Finding) -> List[str]:
        lines: List[str] = []
        loc = f"`{f.file_path}:{f.line_number}`" if f.line_number else (f"`{f.file_path}`" if f.file_path else "Repository level")
        branch_tag = f" | Branch: `{f.branch}`" if f.branch else ""
        lines.append(f"\n### [{f.id}] {f.title}")
        lines.append(f"- **Severity:** **{f.severity.value}** | **Confidence:** **{f.confidence.value}** | **Status:** **{f.status.value}**{branch_tag}")
        if f.cwe_id:
            lines.append(f"- **Taxonomy:** `{f.cwe_id}` ({f.cwe_name})")
        if f.cvss_score_estimate is not None:
            lines.append(f"- **Estimated CVSS Base:** `{f.cvss_score_estimate}` ({f.cvss_vector_estimate or 'N/A'}) _[Heuristic Estimate]_")
        lines.append(f"- **Location:** {loc}")
        if f.file_sha256:
            lines.append(f"- **Source Anchor Content Hash:** `{f.file_sha256[:16]}...` (verified)")
        if f.oracle_origin:
            lines.append(f"- **Oracle Origin:** `{f.oracle_origin}`")
        lines.append(f"- **Tool:** `{f.check_tool or 'offtest'}`")
        lines.append(f"- **User / System Impact:** {f.impact}")
        lines.append(f"- **Evidence / Reproduction:**\n```\n{f.evidence}\n```")
        lines.append(f"- **Recommended Next Action:** {f.suggested_action}")
        return lines

    def _render_common_preamble(self, report_title: str, scope_subtitle: Optional[str] = None) -> List[str]:
        lines: List[str] = []
        lines.append(f"# {report_title}")
        lines.append(f"**Run ID:** `{self.ctx.run_id}`  ")
        lines.append(f"**Generated:** {self.ctx.timestamp}  ")
        lines.append(f"**Target Repository:** `{self.ctx.repo_name}` (`{self.ctx.repo_path}`)  ")
        lines.append(f"**Commit Revision:** `{self.ctx.commit_hash or 'Non-git or Uncommitted'}` (Working Tree Clean: {self.ctx.working_tree_clean})  ")
        lines.append(f"**Active Branch:** `{self.ctx.active_branch or 'N/A'}` | **Comparison Base:** `{self.ctx.comparison_base or 'N/A'}`  ")
        iso_str = "Verified Container / Kernel Air-Gap (Network Namespace)" if self.ctx.kernel_isolation_active else "Python-level egress guard (Defense in Depth); Kernel Isolation: Not Present (Bare Metal)"
        script_approval = str(self.ctx.allow_scripts)
        if self.ctx.allow_scripts and not self.ctx.kernel_isolation_active:
            script_approval += " (Risk Accepted via --accept-no-kernel-isolation)"

        lines.append(f"**Operating System / Platform:** `{self.ctx.platform}` | **Python:** `{self.ctx.python_version}`  ")
        lines.append(f"**Network Isolation:** `{iso_str}` | **Script Execution Approved:** `{script_approval}`  ")

        if scope_subtitle:
            lines.append(f"\n> [!IMPORTANT]\n> **Scope:** {scope_subtitle}\n")

        if self.ctx.allow_scripts and not self.ctx.kernel_isolation_active:
            lines.append("\n> [!CAUTION]")
            lines.append("> **UNISOLATED SCRIPT EXECUTION WARNING**")
            lines.append("> Operator explicitly bypassed kernel sandbox boundaries via `--accept-no-kernel-isolation`.")
            lines.append("> Untrusted repository code was executed directly on a bare host without network namespace, container, or read-only filesystem isolation.\n")

        lines.append("\n---\n")
        return lines

    def _render_executive_and_inventory(self, findings_subset: Optional[List[Finding]] = None) -> List[str]:
        lines: List[str] = []
        findings = findings_subset if findings_subset is not None else self.ctx.findings

        # 2. Executive Summary
        lines.append("## 1. Executive Summary")
        crit_count = len([f for f in findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in findings if f.severity == Severity.HIGH])
        med_count = len([f for f in findings if f.severity == Severity.MEDIUM])
        low_count = len([f for f in findings if f.severity == Severity.LOW])
        info_count = len([f for f in findings if f.severity == Severity.INFORMATIONAL])

        if crit_count > 0 or high_count > 0:
            lines.append(f"> [!WARNING]\n> **Assessment Status: ACTION REQUIRED**\n> Identified **{crit_count} Critical** and **{high_count} High** severity findings that warrant immediate remediation before deployment.")
        else:
            lines.append(f"> [!NOTE]\n> **Assessment Status: REVIEW RECOMMENDED**\n> No Critical or High issues identified. {med_count + low_count + info_count} minor or informational observations recorded.")

        lines.append("\n### Key Observations & Operational Risk")
        lines.append(f"- **Total Discovered Files:** {self.ctx.inventory_summary.total_files} ({self.ctx.inventory_summary.analyzed_count} analyzed, {self.ctx.inventory_summary.excluded_count} excluded, {self.ctx.inventory_summary.generated_count} generated, {self.ctx.inventory_summary.binary_count} binary)")
        lines.append(f"- **Identified Ecosystem:** Languages: `{', '.join(self.ctx.inventory_summary.languages.keys()) or 'None'}` | Frameworks: `{', '.join(self.ctx.inventory_summary.frameworks) or 'None'}`")
        lines.append(f"- **Offline SBOM Dependencies:** {self.ctx.sbom.total_dependencies} components across `{', '.join(self.ctx.sbom.ecosystems) or 'None'}`")
        lines.append(f"- **Test Execution Security:** {'Script execution was approved by user flag.' if self.ctx.allow_scripts else 'Project-supplied test scripts were BLOCKED from automated execution per safety policy.'}")
        lines.append("\n---\n")

        # 3. Repository Inventory
        lines.append("## 2. Repository Inventory")
        lines.append("### File Classification Breakdown")
        lines.append("| Classification | Count | Description |")
        lines.append("| :--- | :---: | :--- |")
        lines.append(f"| **Analyzed** | {self.ctx.inventory_summary.analyzed_count} | Source code and configuration files processed offline |")
        lines.append(f"| **Excluded** | {self.ctx.inventory_summary.excluded_count} | Files matching default exclusion patterns (.git, caches, build dirs) |")
        lines.append(f"| **Generated** | {self.ctx.inventory_summary.generated_count} | Bundles, minified files, lockfiles, or code generation output |")
        lines.append(f"| **Binary** | {self.ctx.inventory_summary.binary_count} | Non-text assets (images, binaries, fonts, archives) |")
        lines.append(f"| **Unsupported** | {self.ctx.inventory_summary.unsupported_count} | Formats not mapped to an active offline language parser |")
        lines.append(f"| **Failed to Inspect** | {self.ctx.inventory_summary.failed_to_inspect_count} | Files unreadable due to I/O or permissions |")
        lines.append(f"| **Total Discovered** | **{self.ctx.inventory_summary.total_files}** | **100% cataloged** |")

        # Excluded files breakdown by reason
        excluded_files = [f for f in self.ctx.files if f.disposition.value == "excluded"]
        if excluded_files:
            lines.append("\n### Excluded Files by Reason")
            lines.append("| Excluded File Path | Reason / Matched Pattern |")
            lines.append("| :--- | :--- |")
            for ef in excluded_files:
                lines.append(f"| `{ef.path}` | {ef.disposition_reason} |")

        # Inspected source files and analyzer attribution
        analyzed_files = [f for f in self.ctx.files if f.disposition.value == "analyzed"]
        if analyzed_files:
            lines.append("\n### Inspected Source Files & Assigned Analyzers")
            lines.append("| File Path | Language | Category | Assigned Offline Analyzer | Lines |")
            lines.append("| :--- | :--- | :--- | :--- | :---: |")
            for af in analyzed_files:
                if af.language == "Python":
                    analyzer = "Python AST Validator & Security AST Visitor"
                elif af.language == "HTML":
                    analyzer = "HTML DOM Template & Route Structure Mapper"
                elif af.language in ["Requirements", "JSON", "YAML", "TOML"]:
                    analyzer = "Offline SBOM & Dependency Configuration Inspector"
                elif af.language in ["JavaScript", "TypeScript"]:
                    analyzer = "JavaScript/TypeScript Static Route & Syntax Inspector"
                else:
                    analyzer = f"Offline {af.language or 'Text'} Inspector"
                lc_str = str(af.line_count) if af.line_count is not None else "N/A"
                lines.append(f"| `{af.path}` | {af.language or 'Plain Text'} | {af.category} | {analyzer} | {lc_str} |")

            total_lines = sum(af.line_count for af in analyzed_files if af.line_count is not None)
            lines.append(f"\n- **Total Inspected Source Lines:** {total_lines} lines.")

        lines.append("\n---\n")

        # 4. App Structure & APIs
        lines.append("## 3. Application Map & Structure, Routes & APIs")
        lines.append(f"- **Discovered Routes & Endpoints:** {len(self.ctx.routes)}")
        lines.append(f"- **APIs Cataloged:** {len(self.ctx.apis)}")
        lines.append(f"- **Key Functional Features:** {len(self.ctx.features)}")
        lines.append(f"- **Multi-Step Workflows:** {len(self.ctx.workflows)}")
        lines.append(f"- **External Integrations:** {len(self.ctx.integrations)}")

        if self.ctx.routes:
            lines.append("\n| Route Path | Method | Handler | Source File:Line | Status |")
            lines.append("| :--- | :---: | :--- | :--- | :---: |")
            for r in self.ctx.routes:
                ln_str = f":{r.line_number}" if r.line_number else ""
                lines.append(f"| `{r.path}` | `{r.method}` | `{r.handler or 'N/A'}` | `{r.file_path}{ln_str}` | {r.status.value} |")

        lines.append("\n---\n")

        # 5. Branch and Change Analysis
        lines.append("## 4. Branch and Change Analysis")
        clean_status = "Clean (0 uncommitted changes)" if self.ctx.working_tree_clean else "Dirty (Uncommitted modifications present)"
        lines.append(f"- **Working Tree Status:** `{clean_status}`")
        if self.ctx.branches:
            lines.append("\n| Branch | Status | HEAD Commit | Message |")
            lines.append("| :--- | :---: | :--- | :--- |")
            for b in self.ctx.branches:
                curr_mark = " (active)" if b.is_current else ""
                base_mark = " (base)" if b.is_base else ""
                lines.append(f"| **`{b.name}`**{curr_mark}{base_mark} | {b.status} | `{b.head_commit or 'N/A'}` | {b.commit_message or 'N/A'} |")
        lines.append("\n---\n")

        # 6. Checks & Test Execution Results
        lines.append("## 5. Checks & Test Execution Results")
        if self.ctx.check_results:
            lines.append("| Check Name | Tool (Version) | Type | Execution | Gate Policy | Duration | Output / Diagnostics |")
            lines.append("| :--- | :--- | :---: | :---: | :---: | :---: | :--- |")
            for cr in self.ctx.check_results:
                reason = cr.skip_or_blocked_reason or f"Exit code {cr.exit_code}"
                gate_badge = f"**{cr.gate_outcome.upper()}**"
                lines.append(f"| **{cr.check_name}** | {cr.tool_name} (`{cr.tool_version}`) | {cr.check_type} | {cr.execution_status} | {gate_badge} | {cr.duration_sec}s | {reason} |")
        else:
            lines.append("_No checks were scheduled or executed._")

        if self.ctx.flakiness.enabled:
            lines.append("\n### Flakiness Repeat Sampling & Quarantine Summary")
            lines.append(f"- **Deterministic Passed:** {self.ctx.flakiness.deterministic_passed_count}")
            lines.append(f"- **Deterministic Failed:** {self.ctx.flakiness.deterministic_failed_count}")
            lines.append(f"- **Quarantined Flaky Tests:** {self.ctx.flakiness.quarantined_flaky_count}")
            if self.ctx.flakiness.quarantined_tests:
                lines.append("\n| Test Name | Total Runs | Passed | Failed | Duration Variance |")
                lines.append("| :--- | :---: | :---: | :---: | :---: |")
                for q in self.ctx.flakiness.quarantined_tests:
                    lines.append(f"| **`{q.test_identifier}`** | {q.total_runs} | {q.passed_runs} | {q.failed_runs} | {q.variance_sec}s |")

        lines.append("\n### Synthesized Branch Tests (Constrained Generation)")
        lines.append(f"- **Total Generated Tests:** {self.ctx.generated_test_suite.total_generated}")
        lines.append(f"- **Syntax Verified:** {self.ctx.generated_test_suite.verified_count} | **Repaired:** {self.ctx.generated_test_suite.repaired_count}")
        if self.ctx.generated_test_suite.suite_file_path:
            lines.append(f"- **Test Suite Output File:** `{self.ctx.generated_test_suite.suite_file_path}`")
        if self.ctx.generated_test_suite.test_cases:
            lines.append("\n| Test ID | Target File:Line | Predicate Type | Validation Status | Description |")
            lines.append("| :--- | :--- | :---: | :---: | :--- |")
            for tc in self.ctx.generated_test_suite.test_cases[:8]:
                lines.append(f"| `{tc.test_id}` | `{tc.target_file}:{tc.target_branch_line}` | {tc.test_type} | `{tc.validation_status}` | {tc.description} |")
        lines.append("\n---\n")

        return lines

    def _render_coverage_and_reproducibility(self) -> List[str]:
        lines: List[str] = []
        # 8. Coverage & Gaps
        lines.append("## 7. Coverage Assessment & Gaps")
        lines.append("| Dimension | Value | Formula / Denominator | Status | Details |")
        lines.append("| :--- | :---: | :---: | :---: | :--- |")
        for dim in self.ctx.coverage.dimensions:
            if dim.value_pct is not None:
                val_str = f"**{dim.value_pct}%**"
            elif dim.name == "Repository Inventory Disposition":
                val_str = "_N/A (Breakdown)_"
            else:
                val_str = "_Unavailable_"
            denom_str = f"{dim.numerator}/{dim.denominator} {dim.unit}" if dim.numerator is not None and dim.denominator is not None else "N/A"
            status_str = "Available" if dim.is_available else "**UNAVAILABLE**"
            lines.append(f"| **{dim.name}** | {val_str} | {denom_str} | {status_str} | {dim.explanation} |")

        lines.append("\n> [!IMPORTANT]\n> **Coverage Principles:** Missing metrics are labeled `Unavailable`, not zero or 100%. A passing test suite does not guarantee that every code path or workflow is defect-free.")
        lines.append("\n---\n")

        # 9. Reproducibility Details
        lines.append("## 8. Reproducibility Details & Tool Manifest")
        lines.append("| Tool Name | Version | Path | Category | Available Offline |")
        lines.append("| :--- | :--- | :--- | :--- | :---: |")
        for tm in self.ctx.tools_manifest:
            lines.append(f"| **{tm.name}** | `{tm.version}` | `{tm.path or 'built-in'}` | {tm.category} | {'Yes' if tm.is_available else 'No'} |")

        lines.append("\n### Execution Assumptions")
        for asm in self.ctx.execution_assumptions:
            lines.append(f"- {asm}")

        lines.append("\n---\n")
        # 10. Limitations
        lines.append("## 9. Explicit Limitations & Boundaries")
        for lim in self.ctx.limitations:
            lines.append(f"- {lim}")

        return lines

    def generate_markdown(self) -> str:
        """
        Generates the standard REPORT_1_DETAILED.md, with Section 6 partitioned into
        two distinct branches: Hardcoded Secrets vs Code Defects, both sorted Critical to Low.
        """
        lines = self._render_common_preamble("Detailed Repository Assessment Report")
        lines.extend(self._render_executive_and_inventory())

        # 7. Findings (Categorized into two branches, sorted Critical to Low)
        lines.append("## 6. Discovered Findings & Vulnerabilities")
        hardcoded, code_defects = split_findings(self.ctx.findings)

        if not self.ctx.findings:
            lines.append("_No security, syntax, or configuration defects were discovered._")
        else:
            lines.append("> [!NOTE]\n> Findings are categorized into **Branch 1 (Hardcoded Secrets & Values)** and **Branch 2 (Code Defects & Vulnerabilities)**, ranked strictly from **Critical to Low/Informational** threat level.\n")

            # Branch 1
            lines.append(f"### Branch 1: Hardcoded Secrets, Credentials & Tokens ({len(hardcoded)} Findings)")
            if hardcoded:
                # Cap vendor noise if > 100
                if len(hardcoded) > 100:
                    repo_items = [f for f in hardcoded if "node_modules" not in (f.file_path or "")]
                    vendor_items = [f for f in hardcoded if "node_modules" in (f.file_path or "")]
                    render_items = repo_items + vendor_items[: max(0, 100 - len(repo_items))]
                else:
                    render_items = hardcoded

                for f in render_items:
                    lines.extend(self._render_finding_card(f))

                if len(hardcoded) > len(render_items):
                    remaining = len(hardcoded) - len(render_items)
                    lines.append(f"\n> [!NOTE]\n> Truncated {remaining} repetitive vendor/node_modules findings. See REPORT_1A_DETAILED_HARDCODED.md, evidence.json, and results.sarif for complete catalog.\n")
            else:
                lines.append("_No hardcoded secrets or plaintext credentials detected._")

            lines.append("\n---\n")

            # Branch 2
            lines.append(f"### Branch 2: Code Quality, Security & Architecture Issues ({len(code_defects)} Findings)")
            if code_defects:
                for f in code_defects:
                    lines.extend(self._render_finding_card(f))
            else:
                lines.append("_No code defects or logic vulnerabilities detected._")

        lines.append("\n---\n")
        lines.extend(self._render_coverage_and_reproducibility())
        return redact_sensitive_data("\n".join(lines))

    def generate_hardcoded_markdown(self) -> str:
        """
        Generates Branch 1: REPORT_1A_DETAILED_HARDCODED.md (Detailed Report for Hardcoded Secrets only).
        """
        hardcoded, _ = split_findings(self.ctx.findings)
        lines = self._render_common_preamble(
            "Detailed Assessment Report: Hardcoded Secrets & Credentials",
            scope_subtitle="Branch 1: In-depth technical report exclusively covering hardcoded secrets, API tokens, passwords, and high-entropy credentials."
        )
        lines.extend(self._render_executive_and_inventory(findings_subset=hardcoded))

        lines.append(f"## 6. Discovered Hardcoded Secrets & Credentials ({len(hardcoded)} Findings)")
        if hardcoded:
            if len(hardcoded) > 100:
                repo_items = [f for f in hardcoded if "node_modules" not in (f.file_path or "")]
                vendor_items = [f for f in hardcoded if "node_modules" in (f.file_path or "")]
                render_items = repo_items + vendor_items[: max(0, 100 - len(repo_items))]
            else:
                render_items = hardcoded

            for f in render_items:
                lines.extend(self._render_finding_card(f))

            if len(hardcoded) > len(render_items):
                remaining = len(hardcoded) - len(render_items)
                lines.append(f"\n> [!NOTE]\n> Truncated {remaining} repetitive vendor/node_modules findings. All raw detections are fully preserved in evidence.json.\n")
        else:
            lines.append("_No hardcoded secrets detected in this assessment._")

        lines.append("\n---\n")
        lines.extend(self._render_coverage_and_reproducibility())
        return redact_sensitive_data("\n".join(lines))

    def generate_code_defects_markdown(self) -> str:
        """
        Generates Branch 2: REPORT_1B_DETAILED_CODE_DEFECTS.md (Detailed Report for Code Defects only).
        """
        _, code_defects = split_findings(self.ctx.findings)
        lines = self._render_common_preamble(
            "Detailed Assessment Report: Code Quality, Security & Architecture",
            scope_subtitle="Branch 2: In-depth technical report covering API security, runtime correctness bugs, dead code, unused imports, and supply-chain policies."
        )
        lines.extend(self._render_executive_and_inventory(findings_subset=code_defects))

        lines.append(f"## 6. Discovered Code Defects & Vulnerabilities ({len(code_defects)} Findings)")
        if code_defects:
            for f in code_defects:
                lines.extend(self._render_finding_card(f))
        else:
            lines.append("_No code defects or vulnerabilities detected in this assessment._")

        lines.append("\n---\n")
        lines.extend(self._render_coverage_and_reproducibility())
        return redact_sensitive_data("\n".join(lines))
