from pathlib import Path
from typing import Optional
from offtest.core.models import EvidenceStatus, RunContext, Severity


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

        lines.append("\n### Languages & Frameworks")
        if self.ctx.inventory_summary.languages:
            lines.append("| Language | Files |")
            lines.append("| :--- | :---: |")
            for lang, cnt in sorted(self.ctx.inventory_summary.languages.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {lang} | {cnt} |")
        else:
            lines.append("_No recognized programming language files detected._")

        lines.append(f"\n- **Build Systems Detected:** {', '.join(self.ctx.inventory_summary.build_systems) or 'None'}")
        lines.append(f"- **Package Managers Detected:** {', '.join(self.ctx.inventory_summary.package_managers) or 'None'}")
        lines.append(f"- **Entry Points Identified:** {', '.join(f'`{ep}`' for ep in self.ctx.inventory_summary.entry_points) or 'None'}")
        lines.append(f"- **Discovered Test Files:** {self.ctx.inventory_summary.test_files_count}")
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
                lines.append(f"| Web Route | `{r.method}` | `{r.path}` | {loc} | **{r.status.value}** |")
            for a in self.ctx.apis:
                loc = f"`{a.file_path}:{a.line_number}`" if a.line_number else f"`{a.file_path}`"
                lines.append(f"| API Endpoint | `{a.method}` | `{a.endpoint}` | {loc} | **{a.status.value}** |")
        else:
            lines.append("_No web routes or API endpoints detected in analyzed files._")

        lines.append("\n### Discovered Features & Toggles")
        if self.ctx.features:
            lines.append("| Feature Name | Flag Identifier | Source File | Status | Linked Tests |")
            lines.append("| :--- | :--- | :--- | :---: | :--- |")
            for ft in self.ctx.features:
                linked = f"{len(ft.linked_tests)} test(s)" if ft.linked_tests else "_No linked test_"
                lines.append(f"| {ft.name} | `{ft.flag_key or 'N/A'}` | `{ft.file_path}` | **{ft.status.value}** | {linked} |")
        else:
            lines.append("_No feature flags or toggles detected in source code._")

        lines.append("\n### Application Workflows")
        if self.ctx.workflows:
            lines.append("| Workflow Name | Type / Status | Entry Point | Related Files | Linked Test Suites |")
            lines.append("| :--- | :---: | :--- | :--- | :--- |")
            for wf in self.ctx.workflows:
                linked = ", ".join(f"`{t}`" for t in wf.linked_tests) if wf.linked_tests else "_None detected_"
                related = ", ".join(f"`{r}`" for r in wf.related_files[:3])
                lines.append(f"| **{wf.name}** | **{wf.status.value}** | `{wf.entry_point or 'N/A'}` | {related} | {linked} |")
        else:
            lines.append("_No multi-step workflows recognized._")

        lines.append("\n### External Integrations & Data Stores")
        if self.ctx.integrations:
            lines.append("| Integration | Category | Status | Detected In |")
            lines.append("| :--- | :--- | :---: | :--- |")
            for ig in self.ctx.integrations:
                files_preview = ", ".join(f"`{p}`" for p in ig.detected_in[:3])
                lines.append(f"| **{ig.name}** | {ig.category} | **{ig.status.value}** | {files_preview} |")
        else:
            lines.append("_No third-party integrations or distinct database drivers observed._")
        lines.append("\n---\n")

        # 5. Branch and Change Analysis
        lines.append("## 4. Branch and Change Analysis")
        if self.ctx.branches:
            lines.append("| Branch | Head Commit | Current | Base | Status | Commit Message |")
            lines.append("| :--- | :---: | :---: | :---: | :---: | :--- |")
            for b in self.ctx.branches:
                curr = "Yes" if b.is_current else "No"
                base = "Yes" if b.is_base else "No"
                lines.append(f"| `{b.name}` | `{b.head_commit or 'unknown'}` | {curr} | {base} | {b.status} | {b.commit_message or ''} |")
        else:
            lines.append("_Repository is not a Git repository or no local branches were found._")

        if self.ctx.branch_diffs:
            lines.append("\n### Comparison Diff Against Base Branch")
            for bd in self.ctx.branch_diffs:
                lines.append(f"- **Target:** `{bd.branch_name}` vs **Base:** `{bd.base_branch}`: {bd.diff_summary}")
                if bd.added_files:
                    lines.append(f"  - Added ({len(bd.added_files)}): {', '.join(f'`{f}`' for f in bd.added_files[:5])}")
                if bd.modified_files:
                    lines.append(f"  - Modified ({len(bd.modified_files)}): {', '.join(f'`{f}`' for f in bd.modified_files[:5])}")
                if bd.deleted_files:
                    lines.append(f"  - Deleted ({len(bd.deleted_files)}): {', '.join(f'`{f}`' for f in bd.deleted_files[:5])}")
        lines.append("\n---\n")

        # 6. Checks & Test Results
        lines.append("## 5. Checks & Test Execution Results")
        if self.ctx.check_results:
            lines.append("| Check Name | Tool & Version | Type | Status | Duration | Reason / Details |")
            lines.append("| :--- | :--- | :---: | :---: | :---: | :--- |")
            for cr in self.ctx.check_results:
                reason = cr.skip_or_blocked_reason or f"Exit code {cr.exit_code}"
                lines.append(f"| **{cr.check_name}** | {cr.tool_name} (`{cr.tool_version}`) | {cr.check_type} | **{cr.status.value}** | {cr.duration_sec}s | {reason} |")
        else:
            lines.append("_No checks were scheduled or executed._")
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

        return "\n".join(lines)
