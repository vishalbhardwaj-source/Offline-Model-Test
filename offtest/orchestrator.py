import os
import platform
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple
from offtest.checks.planner import CheckPlanner, get_tool_manifest
from offtest.core.evidence_store import EvidenceStore
from offtest.core.models import (
    BranchDiffRecord,
    BranchRecord,
    CheckResult,
    Finding,
    RunContext,
)
from offtest.coverage.evaluator import CoverageEvaluator
from offtest.discovery.app_mapper import ApplicationMapper
from offtest.intake.git_manager import GitManager
from offtest.intake.intake import RepositoryIntake
from offtest.inventory.engine import InventoryEngine
from offtest.reports.detailed import DetailedReportGenerator
from offtest.reports.issue_focused import IssueFocusedReportGenerator


class AssessmentOrchestrator:
    def __init__(
        self,
        repo_path_or_archive: str,
        base_branch: Optional[str] = "main",
        target_branch: Optional[str] = None,
        allow_scripts: bool = False,
        output_dir: Optional[str] = None,
    ):
        self.input_target = repo_path_or_archive
        self.base_branch = base_branch
        self.target_branch = target_branch
        self.allow_scripts = allow_scripts
        self.output_dir = Path(output_dir) if output_dir else Path(".offtest_runs")

    def run(self) -> Tuple[RunContext, Path, Path]:
        run_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

        # 1. Intake
        target_dir, is_temp = RepositoryIntake.prepare_target(self.input_target)
        repo_name = target_dir.name

        # 2. Git State
        git_mgr = GitManager(str(target_dir))
        git_state = git_mgr.get_repo_state()
        local_branches = git_mgr.list_local_branches(comparison_base=self.base_branch)

        # Diff against base branch if requested and available
        branch_diffs: List[BranchDiffRecord] = []
        if self.target_branch and self.base_branch and git_state.get("is_git"):
            diff = git_mgr.compare_branches(self.target_branch, self.base_branch)
            if diff:
                branch_diffs.append(diff)
        elif self.base_branch and git_state.get("active_branch") and git_state.get("active_branch") != self.base_branch:
            diff = git_mgr.compare_branches(git_state["active_branch"], self.base_branch)
            if diff:
                branch_diffs.append(diff)

        # 3. Inventory
        inv_engine = InventoryEngine(str(target_dir))
        files, inv_summary = inv_engine.scan()

        # 4. Application Mapping (routes, APIs, features, workflows, integrations)
        app_mapper = ApplicationMapper(target_dir, files)
        routes, apis, features, workflows, integrations = app_mapper.map_application()

        # 5. Check Planning & Execution
        check_planner = CheckPlanner(target_dir, files, allow_scripts=self.allow_scripts)
        active_b_name = git_state.get("active_branch") or "HEAD"
        check_results, findings = check_planner.execute_all(branch=active_b_name)

        # 6. Coverage Evaluation (7 Dimensions)
        selected_b_list = [self.target_branch] if self.target_branch else [b.name for b in local_branches]
        coverage_report = CoverageEvaluator.evaluate(
            files=files,
            workflows=workflows,
            features=features,
            branches=local_branches,
            selected_branches=selected_b_list,
            check_results=check_results,
        )

        # 7. Formulate Limitations and Assumptions
        limitations = [
            "Assessment runs in an offline isolated environment without external dependency retrieval.",
            "Static analysis cannot guarantee detection of runtime-only behavior or dynamic code paths.",
            "Undocumented APIs and implicit workflows may remain unclassified or marked as Inferred.",
        ]
        if not self.allow_scripts:
            limitations.append(
                "Repository-provided test suites and build scripts were blocked from execution per the script safety approval policy."
            )

        assumptions = [
            f"Execution running on platform '{platform.platform()}' with Python '{sys.version.split()[0]}'.",
            "Offline runner enforced environment isolation flags (PIP_NO_INDEX=1, npm_config_offline=true, proxy nullification).",
            "No remote network calls or remote git fetches performed during assessment.",
        ]

        # 8. Assemble Context
        context = RunContext(
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            repo_path=str(target_dir),
            repo_name=repo_name,
            commit_hash=git_state.get("commit_hash"),
            working_tree_clean=git_state.get("working_tree_clean", True),
            remotes=git_state.get("remotes", []),
            active_branch=git_state.get("active_branch"),
            comparison_base=self.base_branch,
            selected_branches=selected_b_list,
            platform=platform.platform(),
            python_version=sys.version.split()[0],
            offline_enforced=True,
            allow_scripts=self.allow_scripts,
            tools_manifest=get_tool_manifest(),
            inventory_summary=inv_summary,
            files=files,
            routes=routes,
            apis=apis,
            features=features,
            workflows=workflows,
            integrations=integrations,
            branches=local_branches,
            branch_diffs=branch_diffs,
            check_results=check_results,
            findings=findings,
            coverage=coverage_report,
            limitations=limitations,
            execution_assumptions=assumptions,
        )

        # 9. Save Evidence Store
        evidence_store = EvidenceStore(base_dir=str(self.output_dir))
        evidence_path = evidence_store.save_run(context)
        run_folder = evidence_path.parent

        # 10. Generate Reports
        detailed_gen = DetailedReportGenerator(context)
        detailed_md = detailed_gen.generate_markdown()
        detailed_report_path = run_folder / "REPORT_1_DETAILED.md"
        detailed_report_path.write_text(detailed_md, encoding="utf-8")

        issue_gen = IssueFocusedReportGenerator(context)
        issue_md = issue_gen.generate_markdown()
        issue_report_path = run_folder / "REPORT_2_ISSUES.md"
        issue_report_path.write_text(issue_md, encoding="utf-8")

        return context, detailed_report_path, issue_report_path
