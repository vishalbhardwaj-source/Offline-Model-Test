from pathlib import Path
from typing import Optional
from offtest.core.models import EvidenceStatus, RunContext, Severity
from offtest.intake.safety import redact_sensitive_data


class DetailedReportGenerator:
    def __init__(self, context: RunContext):
        self.ctx = context

    def generate_markdown(self) -> str:
        lines = []

        # 1. Run Summary
        lines.append(f"# Detailed Repository Assessment Report")
        lines.append(f"**Run ID:** `{self.ctx.run_id}`  ")
        lines.append(f"**Generated:** {self.ctx.timestamp}  ")
        lines.append(f"**Target Repository:** `{self.ctx.repo_name}` (`{self.ctx.repo_path}`)  ")
        lines.append(f"**Commit Revision:** `{self.ctx.commit_hash or 'Non-git or Uncommitted'}` (Working Tree Clean: {self.ctx.working_tree_clean})  ")
        lines.append(f"**Active Branch:** `{self.ctx.active_branch or 'N/A'}` | **Comparison Base:** `{self.ctx.comparison_base or 'N/A'}`  ")
        lines.append(f"**Operating System / Platform:** `{self.ctx.platform}` | **Python:** `{self.ctx.python_version}`  ")
        lines.append(f"**Offline Enforced:** `{self.ctx.offline_enforced}` | **Script Execution Approved:** `{self.ctx.allow_scripts}`  ")
        lines.append("\n---\n")

        # 2. Executive Summary
        lines.append("## 1. Executive Summary")
        crit_count = len([f for f in self.ctx.findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in self.ctx.findings if f.severity == Severity.HIGH])
        med_count = len([f for f in self.ctx.findings if f.severity == Severity.MEDIUM])
        low_count = len([f for f in self.ctx.findings if f.severity == Severity.LOW])
        info_count = len([f for f in self.ctx.findings if f.severity == Severity.INFORMATIONAL])

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

        lines.append("\n### Offline Software Bill of Materials (SBOM) Summary")
        lines.append(f"- **Total Tracked Dependencies:** {self.ctx.sbom.total_dependencies}")
        lines.append(f"- **Direct Dependencies:** {self.ctx.sbom.direct_dependencies}")
        lines.append(f"- **Ecosystems:** {', '.join(self.ctx.sbom.ecosystems) or 'None'}")
        if self.ctx.sbom.components:
            lines.append("\n| Package | Version | Ecosystem | Direct | Source File |")
            lines.append("| :--- | :--- | :---: | :---: | :--- |")
            for comp in self.ctx.sbom.components[:15]:
                lines.append(f"| **`{comp.name}`** | `{comp.version}` | {comp.ecosystem} | {'Yes' if comp.direct else 'No'} | `{comp.source_file}` |")
            if len(self.ctx.sbom.components) > 15:
                lines.append(f"| ... and {len(self.ctx.sbom.components) - 15} more dependencies | | | | |")
        lines.append("\n---\n")

        # 4. Application Map
        lines.append("## 3. Application Map & Structure")
        lines.append("Discovered endpoints, feature flags, integrations, and application workflows:")

        lines.append("\n### Web & API Routes")
        if self.ctx.routes or self.ctx.apis:
            lines.append("| Type | Method | Path / Endpoint | Source Location | Evidence Status |")
            lines.append("| :--- | :---: | :--- | :--- | :---: |")
            for r in self.ctx.routes:
                loc = f"`{r.file_path}:{r.line_number}`" if r.line_number else f"`{r.file_path}`"
                lines.append(f"| Web Route | `{r.method}` | `{r.path}` | {loc} | {r.status.value} |")
            for a in self.ctx.apis:
                loc = f"`{a.file_path}:{a.line_number}`" if a.line_number else f"`{a.file_path}`"
                lines.append(f"| API Endpoint | `{a.method}` | `{a.endpoint}` | {loc} | {a.status.value} |")
        else:
            lines.append("_No explicit HTTP routes or API endpoints discovered in source files._")

        lines.append("\n### Role-Based Access Control (RBAC) Matrix")
        roles_list_str = ', '.join(f'`{r}`' for r in self.ctx.rbac_matrix.roles) if self.ctx.rbac_matrix.roles else "_None explicitly identified_"
        lines.append(f"- **Identified Roles:** {roles_list_str}")
        lines.append(f"- **Endpoints Covered in RBAC Map:** {self.ctx.rbac_matrix.endpoints_count}")
        if self.ctx.rbac_matrix.permissions:
            lines.append("\n| Endpoint | Method | Auth Required | Guard Status | Required Roles | Evidence Location |")
            lines.append("| :--- | :---: | :---: | :---: | :--- | :--- |")
            for p in self.ctx.rbac_matrix.permissions[:10]:
                if p.auth_required:
                    guard_status = "Protected"
                    roles_str = ", ".join(f"`{r}`" for r in p.required_roles) or "`Authenticated`"
                elif p.status.value == "unverified":
                    guard_status = "**Unverified** (No local guard)"
                    roles_str = "_None verified_"
                else:
                    guard_status = "Public (Inferred/Observed)"
                    roles_str = "`Anonymous`"
                lines.append(f"| `{p.endpoint}` | `{p.method}` | {'Yes' if p.auth_required else 'No'} | {guard_status} | {roles_str} | `{p.file_path}:{p.line_number or 1}` |")
            if len(self.ctx.rbac_matrix.permissions) > 10:
                lines.append(f"| ... and {len(self.ctx.rbac_matrix.permissions) - 10} more endpoints | | | | | |")

        lines.append(f"\n### Inferred OpenAPI 3.1 Spec")
        lines.append(f"- **OpenAPI Version:** `{self.ctx.openapi_spec.openapi_version}` | **Endpoints Synthesized:** {self.ctx.openapi_spec.paths_count}")

        lines.append("\n### Application Workflows & Features")
        if self.ctx.workflows:
            for w in self.ctx.workflows:
                lines.append(f"- **Workflow `{w.name}`:** {w.description} (Steps: {len(w.steps)})")
        if self.ctx.features:
            for feat in self.ctx.features:
                lines.append(f"- **Feature `{feat.name}`:** Flag `{feat.flag_key or 'None'}` ({feat.file_path})")
        lines.append("\n---\n")

        # 5. Branch & Change Analysis
        lines.append("## 4. Branch and Change Analysis")
        if self.ctx.branches:
            lines.append("| Branch | Status | HEAD Commit | Message |")
            lines.append("| :--- | :---: | :--- | :--- |")
            for b in self.ctx.branches:
                curr_mark = " (active)" if b.is_current else ""
                base_mark = " (base)" if b.is_base else ""
                lines.append(f"| **`{b.name}`**{curr_mark}{base_mark} | {b.status} | `{b.head_commit or 'N/A'}` | {b.commit_message or 'N/A'} |")
        lines.append("\n---\n")

        # 6. Checks & Test Execution Results
        lines.append("## 5. Checks & Test Execution Results")
        if self.ctx.check_results:
            lines.append("| Check Name | Tool (Version) | Type | Status | Duration | Output / Blocker |")
            lines.append("| :--- | :--- | :--- | :---: | :---: | :--- |")
            for cr in self.ctx.check_results:
                reason = cr.skip_or_blocked_reason or f"Exit code {cr.exit_code}"
                lines.append(f"| **{cr.check_name}** | {cr.tool_name} (`{cr.tool_version}`) | {cr.check_type} | **{cr.status.value}** | {cr.duration_sec}s | {reason} |")
        else:
            lines.append("_No checks were scheduled or executed._")

        if self.ctx.flakiness.enabled:
            lines.append("\n### Flakiness Bisection & Quarantine Summary")
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

        # 7. Findings
        lines.append("## 6. Discovered Findings & Vulnerabilities")
        if self.ctx.findings:
            for f in self.ctx.findings:
                loc = f"`{f.file_path}:{f.line_number}`" if f.line_number else (f"`{f.file_path}`" if f.file_path else "Repository level")
                branch_tag = f" | Branch: `{f.branch}`" if f.branch else ""
                lines.append(f"\n### [{f.id}] {f.title}")
                lines.append(f"- **Severity:** **{f.severity.value}** | **Confidence:** **{f.confidence.value}** | **Status:** **{f.status.value}**{branch_tag}")
                lines.append(f"- **Location:** {loc}")
                lines.append(f"- **Tool:** `{f.check_tool or 'offtest'}`")
                lines.append(f"- **User / System Impact:** {f.impact}")
                lines.append(f"- **Evidence / Reproduction:**\n```\n{f.evidence}\n```")
                lines.append(f"- **Recommended Next Action:** {f.suggested_action}")
        else:
            lines.append("_No security, syntax, or configuration defects were discovered._")
        lines.append("\n---\n")

        # 8. Coverage & Gaps
        lines.append("## 7. Coverage Assessment & Gaps")
        lines.append("| Dimension | Value | Formula / Denominator | Status | Details |")
        lines.append("| :--- | :---: | :---: | :---: | :--- |")
        for dim in self.ctx.coverage.dimensions:
            val_str = f"**{dim.value_pct}%**" if dim.value_pct is not None else "_Unavailable_"
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

        return redact_sensitive_data("\n".join(lines))
