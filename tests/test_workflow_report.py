from offtest.core.models import (
    EvidenceStatus,
    FeatureRecord,
    IntegrationRecord,
    RouteRecord,
    RunContext,
    WorkflowRecord,
)
from offtest.reports.workflow import WorkflowReportGenerator


def test_workflow_report_structure_and_sections():
    # Setup test run context with features, workflows, routes, and integrations
    f1 = FeatureRecord(
        name="App UI Component",
        flag_key="AppComponent",
        file_path="src/app/app.component.ts",
        line_number=8,
        status=EvidenceStatus.OBSERVED,
        linked_tests=["src/app/app.component.spec.ts"],
        description="User presentation and view interaction component managing App interface lifecycle.",
    )
    f2 = FeatureRecord(
        name="NgRx Reactive Side-Effect Dispatcher",
        flag_key="NewsEffects",
        file_path="src/app/store/effects/news.effects.ts",
        line_number=17,
        status=EvidenceStatus.OBSERVED,
        linked_tests=[],
        description="Intercepts dispatched store actions, triggers asynchronous service queries, and feeds results back to state store.",
    )

    wf1 = WorkflowRecord(
        name="Asynchronous Data Ingestion & State Pipeline",
        description="End-to-end reactive state management workflow (Action Dispatch -> Effect Service Query -> Reducer Store Update -> View Projection)",
        entry_point="Action Dispatch (NgRx / State Store)",
        related_files=[
            "src/app/services/news.service.ts",
            "src/app/store/effects/news.effects.ts",
        ],
        linked_tests=["src/app/services/news.service.spec.ts"],
        status=EvidenceStatus.OBSERVED,
        is_advisory=False,
        steps=[
            "UI component dispatches action with intent and parameters",
            "Reactive Effect intercepts action and executes asynchronous service call",
            "Service issues HTTP request to external/internal API endpoint",
            "On HTTP Success: Dispatches success action with response payload",
            "Reducer commits updated immutable state slice into global store",
        ],
    )
    wf2 = WorkflowRecord(
        name="Content Navigation & Screen Route Transition",
        description="User client-side routing and view transition workflow across application sections",
        entry_point="/section/:section",
        related_files=["src/app/app-routing.module.ts"],
        linked_tests=["src/app/app.component.spec.ts"],
        status=EvidenceStatus.OBSERVED,
        is_advisory=False,
        steps=[
            "User selects navigation link or initiates route change to '/section/:section'",
            "Client router matches URL path and resolves route configuration",
            "Target view component is mounted and lifecycle hooks execute",
        ],
    )

    r1 = RouteRecord(
        path="/section/:section",
        method="GET",
        file_path="src/app/app-routing.module.ts",
        line_number=15,
    )

    ctx = RunContext(
        run_id="run_20261024_152800_8d4f71",
        repo_name="angular-ngrx-news-app",
        repo_path="C:/repos/angular-ngrx-news-app",
        platform="Windows-11-10.0.26200-SP0",
        python_version="3.12.0",
        commit_hash="98d02b920993a072f1bb202944bc220f1eb8e617",
        working_tree_clean=False,
        workflows=[wf1, wf2],
        features=[f1, f2],
        routes=[r1],
    )

    gen = WorkflowReportGenerator(ctx)
    md = gen.generate_markdown()

    # 1. Preamble & Context
    assert "# Actionable Application Workflow & Journey Report" in md
    assert "**Target:** `angular-ngrx-news-app`" in md
    assert "**Run ID:** `run_20261024_152800_8d4f71`" in md
    assert "**Commit:** `98d02b920993a072f1bb202944bc220f1eb8e617`" in md
    assert "**Working Tree Clean:** `False`" in md
    assert "**Platform:** `Windows-11-10.0.26200-SP0`" in md

    # 2. Executive Workflow Summary
    assert "## 1. Executive Workflow Summary" in md
    assert "Identified **2 application workflows** and **2 functional features**" in md
    assert "### Workflow & Feature Statistics" in md
    assert "| **Total Discovered Workflows** | **2** |" in md
    assert "| **Observed Workflows (Explicit Code / Routes)** | 2 | 100.0% |" in md
    assert "| **Inferred Workflows (Synthesized Journeys)** | 0 | 0.0% |" in md

    # 3. Interactive Workflow Architecture & Navigation Flow
    assert "## 2. Interactive Workflow Architecture & Visualizations" in md
    assert "flowchart TD" in md
    assert "subgraph Client" in md
    assert "subgraph State" in md
    assert "subgraph Services" in md
    assert "### Navigation & Routing Flow" in md
    assert "flowchart LR" in md
    assert 'Root["/ (Entry Point)"]' in md
    assert '/section/:section' in md

    # 4. Features & Capabilities Breakdown
    assert "## 3. Discovered Application Features & Capabilities Breakdown" in md
    assert "### Feature Catalog & Workflow Matrix" in md
    assert "| **`FEAT-001`** | **App UI Component** |" in md
    assert "✅ Verified (1 tests)" in md
    assert "| **`FEAT-002`** | **NgRx Reactive Side-Effect Dispatcher** |" in md
    assert "⚠️ Untested Gap" in md
    assert "### Detailed Feature Explanations" in md
    assert "#### [FEAT-001] App UI Component" in md
    assert "- **Description & Purpose:**" in md
    assert "- **Component Anchor:** `src/app/app.component.ts:8`" in md
    assert "- **Identifier / Flag:** `AppComponent`" in md
    assert "- **Evidence Status:** `Observed`" in md
    assert "Covered by `src/app/app.component.spec.ts`" in md
    assert "#### [FEAT-002] NgRx Reactive Side-Effect Dispatcher" in md
    assert "_No dedicated unit test detected (Coverage Gap)_" in md

    # 5. Workflow Catalog & Journeys
    assert "## 4. Discovered Workflow Catalog & Step-by-Step Journeys" in md
    assert "### [WF-001] Asynchronous Data Ingestion & State Pipeline" in md
    assert "- **Description:** End-to-end reactive state management workflow" in md
    assert "- **Evidence Status:** `Observed` | **Advisory Journey:** `False`" in md
    assert "- **Entry Point / Trigger:** `Action Dispatch (NgRx / State Store)`" in md
    assert "- **Execution Steps:**" in md
    assert "1. UI component dispatches action with intent and parameters" in md
    assert "- **Failure & Edge-Case Considerations:**" in md
    assert "Handling of unexpected network latency" in md
    assert "### [WF-002] Content Navigation & Screen Route Transition" in md
    assert "- **Entry Point / Trigger:** `/section/:section`" in md

    # 6. Integrations
    assert "## 5. State Management, Store & API Integrations" in md
    assert "_No third-party SDKs, databases, or external integrations detected in codebase._" in md

    # 7. Coverage Gaps & Recommendations
    assert "## 6. Workflow & Feature Coverage Gaps & Actionable Recommendations" in md
    assert "> [!WARNING]" in md
    assert "Identified 0 untested workflows and 1 untested features." in md
    assert "### Recommended Test Implementation Template" in md
    assert "describe('Application Feature & Workflow Verification'" in md

    # 8. Audit Trail
    assert "## 7. Audit Trail & Cryptographic Verification" in md
    assert "- **Immutable Evidence Reference:** `evidence.json` (SHA-256 verified)" in md
