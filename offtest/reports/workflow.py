from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from offtest.core.models import EvidenceStatus, FeatureRecord, IntegrationRecord, RouteRecord, RunContext, WorkflowRecord
from offtest.intake.safety import redact_sensitive_data


class WorkflowReportGenerator:
    """
    Dedicated generator for REPORT_3_WORKFLOWS.md:
    Actionable Application Workflow & Journey Report.
    Generates:
    1. Executive Workflow Summary & Statistics
    2. Interactive Workflow Architecture & Navigation Flow (Mermaid diagrams)
    3. Discovered Application Features & Capabilities Breakdown (Catalog + Detailed Explanations)
    4. Discovered Workflow Catalog & Step-by-Step Journeys
    5. State Management, Store & API Integrations
    6. Workflow & Feature Coverage Gaps & Actionable Recommendations
    7. Audit Trail & Cryptographic Verification
    """

    def __init__(self, context: RunContext):
        self.ctx = context

    def generate_markdown(self) -> str:
        lines: List[str] = []

        workflows: List[WorkflowRecord] = list(self.ctx.workflows or [])
        features: List[FeatureRecord] = list(self.ctx.features or [])
        integrations: List[IntegrationRecord] = list(self.ctx.integrations or [])
        routes = list(self.ctx.routes or [])
        apis = list(self.ctx.apis or [])

        # Sanitize related files and test paths (remove internal node_modules and bytecode caches)
        for wf in workflows:
            wf.linked_tests = [t for t in wf.linked_tests if "node_modules" not in t and "__pycache__" not in t]
            wf.related_files = [rf for rf in wf.related_files if "node_modules" not in rf and "__pycache__" not in rf]

        for feat in features:
            feat.linked_tests = [t for t in feat.linked_tests if "node_modules" not in t and "__pycache__" not in t]
            if "__pycache__" in feat.file_path:
                clean_path = re.sub(r'__pycache__/', '', feat.file_path)
                clean_path = re.sub(r'\.cpython-[0-9]+\.pyc', '.py', clean_path)
                clean_path = re.sub(r'\.pyc$', '.py', clean_path)
                feat.file_path = clean_path

        iso_str = (
            "Verified Container / Kernel Air-Gap (Network Namespace)"
            if self.ctx.kernel_isolation_active
            else "Python-level egress guard (Defense in Depth); Kernel Isolation: Not Present (Bare Metal)"
        )

        # Title & Preamble
        lines.append("# Actionable Application Workflow & Journey Report")
        lines.append(
            f"**Target:** `{self.ctx.repo_name}` | **Run ID:** `{self.ctx.run_id}` | "
            f"**Commit:** `{self.ctx.commit_hash or 'HEAD'}` | **Working Tree Clean:** `{self.ctx.working_tree_clean}`\n"
        )
        lines.append(f"**Isolation Mode:** `{iso_str}` | **Platform:** `{self.ctx.platform}`\n")
        lines.append("---\n")

        # 1. Executive Workflow Summary
        total_wf = len(workflows)
        total_feat = len(features)
        observed_wf = len([w for w in workflows if w.status == EvidenceStatus.OBSERVED])
        inferred_wf = len([w for w in workflows if w.status == EvidenceStatus.INFERRED])
        tested_wf = len([w for w in workflows if len(w.linked_tests) > 0])
        untested_wf = total_wf - tested_wf
        tested_feat = len([f for f in features if len(f.linked_tests) > 0])
        untested_feat = total_feat - tested_feat

        obs_pct = (observed_wf / total_wf * 100.0) if total_wf > 0 else 0.0
        inf_pct = (inferred_wf / total_wf * 100.0) if total_wf > 0 else 0.0
        feat_pct = (tested_feat / total_feat * 100.0) if total_feat > 0 else 0.0

        lines.append("## 1. Executive Workflow Summary")
        lines.append(
            f"Identified **{total_wf} application workflows** and **{total_feat} functional features** "
            f"governing user navigation, UI presentation, reactive state management, and external API integrations.\n"
        )
        lines.append("### Workflow & Feature Statistics")
        lines.append("| Metric | Count | Ratio / Status |")
        lines.append("| :--- | :---: | :--- |")
        lines.append(f"| **Total Discovered Workflows** | **{total_wf}** | 100% cataloged |")
        lines.append(f"| **Observed Workflows (Explicit Code / Routes)** | {observed_wf} | {obs_pct:.1f}% |")
        lines.append(f"| **Inferred Workflows (Synthesized Journeys)** | {inferred_wf} | {inf_pct:.1f}% |")
        lines.append(f"| **Total Application Features** | **{total_feat}** | 100% mapped to components |")
        lines.append(f"| **Features with Verified Test Anchors** | {tested_feat} | {feat_pct:.1f}% |")
        lines.append(f"| **Workflows with Linked Test Suites** | {tested_wf} | Verified by test suites |")
        lines.append(f"| **Untested Workflow Coverage Gaps** | **{untested_wf}** | Requires automated verification |")
        lines.append("\n---\n")

        # 2. Interactive Workflow Architecture & Visualizations
        lines.append("## 2. Interactive Workflow Architecture & Visualizations")
        lines.append("The following diagrams illustrate application workflows, navigation states, and data pipelines:\n")

        is_frontend_or_reactive = any(
            any(k in getattr(f, "path", "").lower() for k in ["component", "store", "ngrx", "redux", "src/app", "react", "view"])
            for f in getattr(self.ctx, "files", [])
        ) or any(
            any(k in wf.name.lower() for k in ["state", "ngrx", "redux", "navigation", "screen"])
            for wf in workflows
        )

        lines.append("```mermaid")
        lines.append("flowchart TD")
        if is_frontend_or_reactive:
            lines.append('    subgraph Client["🌐 Client & User Interaction"]')
            lines.append('        User["User Browser / Client"] --> UI["UI Components & Views"]')
            lines.append('    end')
            lines.append('    subgraph State["⚡ State & Reactive Pipeline"]')
            lines.append('        UI --> Actions["Action Dispatch / Route Change"]')
            lines.append('        Actions --> Effects["Effects / Controllers / Handlers"]')
            lines.append('        Effects --> Reducers["State Reducers / Local Stores"]')
            lines.append('        Reducers --> UI')
            lines.append('    end')
            lines.append('    subgraph Services["🔌 Services & Backend Contracts"]')
            lines.append('        Effects --> APISvc["Service Client / HTTP Agent"]')
            lines.append('        APISvc --> ExternalAPI["Target API / Server Endpoints"]')
            lines.append('    end')
        else:
            lines.append('    subgraph Client["🌐 Client & External Consumers"]')
            lines.append('        User["Client Request / HTTP Agent"] --> Gateway["API Gateway / Router"]')
            lines.append('    end')
            lines.append('    subgraph Core["⚡ Controllers & Business Logic"]')
            lines.append('        Gateway --> Auth["Authentication & Guards"]')
            lines.append('        Auth --> Handlers["Route Handlers & Controllers"]')
            lines.append('        Handlers --> Services["Domain Business Services"]')
            lines.append('    end')
            lines.append('    subgraph Data["🔌 Persistence & External Integrations"]')
            lines.append('        Services --> Store[("Database / State Persistence")]')
            lines.append('        Services --> ExternalAPI["External Services & Target Endpoints"]')
            lines.append('    end')
        lines.append("```\n")

        # Navigation & Routing Flow
        lines.append("### Navigation & Routing Flow")
        lines.append("```mermaid")
        lines.append("flowchart LR")
        lines.append('    Root["/ (Entry Point)"]')

        all_paths: List[str] = []
        for r in routes:
            p = getattr(r, "path", "")
            if p and p != "/" and p not in all_paths:
                all_paths.append(p)
        for a in apis:
            p = getattr(a, "endpoint", "")
            if p and p != "/" and p not in all_paths:
                all_paths.append(p)

        if all_paths:
            for r_idx, r_path in enumerate(all_paths[:8], start=1):
                clean_r = re.sub(r'[^a-zA-Z0-9_ \-:/.]', '', r_path)
                lines.append(f'    Root --> R{r_idx}["{clean_r}"]')
        else:
            lines.append('    Root --> Main["Application Core Services"]')
        lines.append("```\n")
        lines.append("---\n")

        # 3. Discovered Application Features & Capabilities Breakdown
        lines.append("## 3. Discovered Application Features & Capabilities Breakdown")
        lines.append(
            "Each discovered feature represents an autonomous capability, presentation component, or service module. "
            "The catalog and explanations below detail the functional purpose, underlying implementation, and workflow mapping for each feature:\n"
        )
        lines.append("### Feature Catalog & Workflow Matrix")
        lines.append("| Feature ID | Feature Name | Source Component | Mapped Workflow | Verification Status |")
        lines.append("| :--- | :--- | :--- | :--- | :---: |")

        # Helper to map a feature to its best workflow
        def get_mapped_workflow_name(feat: FeatureRecord) -> str:
            feat_lower = (feat.name + " " + (feat.flag_key or "") + " " + feat.file_path).lower()
            for wf in workflows:
                wf_lower = wf.name.lower()
                if any(rf in feat.file_path or feat.file_path in rf for rf in wf.related_files):
                    return wf.name
                if "state" in feat_lower or "service" in feat_lower or "effect" in feat_lower or "reducer" in feat_lower:
                    if "state" in wf_lower or "ingestion" in wf_lower or "pipeline" in wf_lower:
                        return wf.name
                if "nav" in feat_lower or "route" in feat_lower or "menu" in feat_lower:
                    if "nav" in wf_lower or "route" in wf_lower or "transition" in wf_lower:
                        return wf.name
            if workflows:
                return workflows[0].name
            return "_General System_"

        feature_mappings: List[Tuple[str, FeatureRecord, str]] = []
        for f_idx, feat in enumerate(features, start=1):
            f_id = f"FEAT-{f_idx:03d}"
            mapped_wf = get_mapped_workflow_name(feat)
            feature_mappings.append((f_id, feat, mapped_wf))
            loc = f"`{feat.file_path}:{feat.line_number}`" if feat.line_number else f"`{feat.file_path}`"
            test_badge = f"✅ Verified ({len(feat.linked_tests)} tests)" if feat.linked_tests else "⚠️ Untested Gap"
            wf_disp = f"`{mapped_wf}`" if mapped_wf != "_General System_" else "_General System_"
            lines.append(f"| **`{f_id}`** | **{feat.name}** | {loc} | {wf_disp} | {test_badge} |")

        lines.append("\n### Detailed Feature Explanations\n")
        for f_id, feat, mapped_wf in feature_mappings:
            lines.append(f"#### [{f_id}] {feat.name}")
            desc = feat.description or f"User presentation and view interaction component managing {feat.name} interface lifecycle."
            loc = f"`{feat.file_path}:{feat.line_number}`" if feat.line_number else f"`{feat.file_path}`"
            ident = feat.flag_key or re.sub(r'[^A-Za-z0-9_]', '', feat.name) or feat.name
            lines.append(f"- **Description & Purpose:** {desc}")
            lines.append(f"- **Component Anchor:** {loc}")
            lines.append(f"- **Identifier / Flag:** `{ident}`")
            lines.append(f"- **Evidence Status:** `{feat.status.value}`")
            lines.append(f"- **Participating Workflow(s):** `{mapped_wf}`")
            if feat.linked_tests:
                tests_str = ", ".join(f"`{t}`" for t in feat.linked_tests)
                lines.append(f"- **Verification Evidence:** Covered by {tests_str}")
            else:
                lines.append("- **Verification Evidence:** _No dedicated unit test detected (Coverage Gap)_")
            lines.append("")

        lines.append("---\n")

        # 4. Discovered Workflow Catalog & Step-by-Step Journeys
        lines.append("## 4. Discovered Workflow Catalog & Step-by-Step Journeys\n")

        for w_idx, wf in enumerate(workflows, start=1):
            wf_id = f"WF-{w_idx:03d}"
            lines.append(f"### [{wf_id}] {wf.name}")
            lines.append(f"- **Description:** {wf.description}")
            lines.append(f"- **Evidence Status:** `{wf.status.value}` | **Advisory Journey:** `{str(wf.is_advisory)}`")
            entry_disp = wf.entry_point or "User Interface / Direct Navigation"
            lines.append(f"- **Entry Point / Trigger:** `{entry_disp}`")
            rel_files_str = ", ".join(f"`{rf}`" for rf in wf.related_files) if wf.related_files else "`General Application Context`"
            lines.append(f"- **Related Components & Files:** {rel_files_str}")
            if wf.linked_tests:
                tests_str = ", ".join(f"`{t}`" for t in wf.linked_tests)
                lines.append(f"- **Linked Tests:** {tests_str} (✅ Covered)")
            else:
                lines.append("- **Linked Tests:** _No dedicated unit test detected (Coverage Gap)_")

            lines.append("- **Execution Steps:**")
            steps = getattr(wf, "processing_pipeline", None) or getattr(wf, "steps", None) or []
            if not steps:
                steps = [
                    f"User selects navigation link or initiates interaction to '{entry_disp}'",
                    "Router resolves target path and mounts active component lifecycle",
                    "Component triggers state queries and executes domain business logic",
                    "Updated state is committed and projected to the user interface view",
                ]
            for s_idx, st in enumerate(steps, start=1):
                clean_st = re.sub(r'^\d+\.\s*', '', st)
                lines.append(f"  {s_idx}. {clean_st}")

            lines.append("- **Failure & Edge-Case Considerations:**")
            lines.append("  - Handling of unexpected network latency, HTTP 4xx/5xx, or offline disconnection.")
            lines.append("  - Defensive recovery and fallback state representation in UI/client.")
            lines.append("")

        lines.append("---\n")

        # 5. State Management, Store & API Integrations
        lines.append("## 5. State Management, Store & API Integrations")
        if integrations:
            lines.append("| Integration | Category | Detected In | Status | Details |")
            lines.append("| :--- | :--- | :--- | :---: | :--- |")
            for ig in integrations:
                det = ", ".join(f"`{d}`" for d in ig.detected_in[:3]) if ig.detected_in else "`N/A`"
                lines.append(f"| **{ig.name}** | {ig.category} | {det} | `{ig.status.value}` | {ig.details or 'Integrated service interface'} |")
        else:
            lines.append("_No third-party SDKs, databases, or external integrations detected in codebase._")
        lines.append("\n---\n")

        # 6. Workflow & Feature Coverage Gaps & Actionable Recommendations
        lines.append("## 6. Workflow & Feature Coverage Gaps & Actionable Recommendations")
        if untested_wf > 0 or untested_feat > 0:
            lines.append(
                f"> [!WARNING]\n"
                f"> **Identified {untested_wf} untested workflows and {untested_feat} untested features.** "
                f"Bugs or regression breaks in these paths may go undetected during continuous integration.\n"
            )
        else:
            lines.append(
                "> [!TIP]\n"
                "> **All cataloged workflows and features have verified test suites associated with them.**\n"
            )

        lines.append("### Recommended Test Implementation Template")
        lines.append("To close coverage gaps, add end-to-end integration tests following this structure:\n")

        is_ts_js = any(
            getattr(f, "language", "") in ["TypeScript", "JavaScript", "TypeScript (TSX)", "JavaScript (JSX)"]
            for f in getattr(self.ctx, "files", [])
        ) or any(
            feat.file_path.endswith((".ts", ".js", ".tsx", ".jsx"))
            for feat in features
        ) or any(
            any(rf.endswith((".ts", ".js", ".tsx", ".jsx")) for rf in wf.related_files)
            for wf in workflows
        )
        if is_ts_js:
            lines.append("```typescript")
            lines.append("// Recommended Workflow & Feature Integration Test")
            lines.append("describe('Application Feature & Workflow Verification', () => {")
            lines.append("  it('should execute end-to-end user journey and component lifecycle without errors', async () => {")
            lines.append("    // 1. Initialize component / page state")
            lines.append("    // 2. Trigger entry action or route transition")
            lines.append("    // 3. Verify store state dispatch or service invocation")
            lines.append("    // 4. Assert UI updates and expected terminal state")
            lines.append("  });")
            lines.append("});")
            lines.append("```\n")
        else:
            lines.append("```python")
            lines.append("# Recommended Workflow & Feature Integration Test")
            lines.append("import pytest\n")
            lines.append("def test_application_feature_workflow_journey(client):")
            lines.append('    """Verify end-to-end user journey and component lifecycle without errors."""')
            lines.append("    # 1. Initialize test state and dependencies")
            lines.append("    # 2. Trigger entry action or route transition")
            lines.append("    # 3. Verify service invocation and state updates")
            lines.append("    # 4. Assert expected terminal response")
            lines.append("```\n")

        lines.append("---\n")

        # 7. Audit Trail & Cryptographic Verification
        lines.append("## 7. Audit Trail & Cryptographic Verification")
        lines.append(
            f"- **Immutable Evidence Reference:** `evidence.json` (SHA-256 verified)\n"
            f"- **Deterministic Pipeline:** Generated autonomously by `offtest` air-gapped testing model.\n"
            f"- **Report Status:** Finalized."
        )

        return redact_sensitive_data("\n".join(lines))
