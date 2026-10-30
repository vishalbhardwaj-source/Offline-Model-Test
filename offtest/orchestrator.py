import hashlib
import os
import platform
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple
from offtest.checks.flakiness import FlakinessRepeatSampler
from offtest.checks.planner import CheckPlanner, get_tool_manifest
from offtest.core.evidence_store import EvidenceStore, atomic_write_text
from offtest.core.models import (
    BranchDiffRecord,
    BranchRecord,
    CheckResult,
    CheckStatus,
    Finding,
    RunContext,
)
from offtest.coverage.evaluator import CoverageEvaluator
from offtest.discovery.app_mapper import ApplicationMapper
from offtest.discovery.rbac_and_schema import RBACAndSchemaExtractor
from offtest.generator.test_generator import ConstrainedTestGenerator
from offtest.intake.git_manager import GitManager
from offtest.intake.intake import RepositoryIntake, SecurityError
from offtest.inventory.engine import InventoryEngine
from offtest.inventory.sbom import SBOMGenerator
from offtest.adapters.registry import get_all_coverages
from offtest.checks.isolated_runner import verify_kernel_sandbox_environment
from offtest.reports.detailed import DetailedReportGenerator
from offtest.reports.issue_focused import IssueFocusedReportGenerator
from offtest.reports.workflow import WorkflowReportGenerator
from offtest.reports.sarif import SARIFReportGenerator
from offtest.intake.safety import redact_sensitive_data


class OrchestratorResult(tuple):
    """
    4-element tuple (context, detailed_report_path, issue_report_path, sarif_path)
    for seamless backward compatibility with unpacking, plus .workflow_report_path and branch attributes.
    """
    def __new__(cls, context, detailed_path, issue_path, sarif_path, workflow_path=None, **kwargs):
        return super().__new__(cls, (context, detailed_path, issue_path, sarif_path))

    def __init__(self, context, detailed_path, issue_path, sarif_path, workflow_path=None, **kwargs):
        self.context = context
        self.detailed_report_path = detailed_path
        self.issue_report_path = issue_path
        self.sarif_path = sarif_path
        self.workflow_report_path = workflow_path
        self.workflow_path = workflow_path
        self.detailed_hardcoded_path = kwargs.get("detailed_hardcoded_path")
        self.detailed_code_path = kwargs.get("detailed_code_path")
        self.issue_hardcoded_path = kwargs.get("issue_hardcoded_path")
        self.issue_code_path = kwargs.get("issue_code_path")


class AssessmentOrchestrator:
    def __init__(
        self,
        repo_path_or_archive: str,
        base_branch: Optional[str] = "main",
        target_branch: Optional[str] = None,
        allow_scripts: bool = False,
        output_dir: Optional[str] = None,
        detect_flaky: bool = False,
        quarantine_policy: str = "warn",
        generate_tests: bool = True,
        accept_no_kernel_isolation: bool = False,
        strip_sarif_snippets: bool = False,
        app_tier: str = "unknown",
        baseline_path: Optional[str] = None,
    ):
        self.input_target = repo_path_or_archive
        self.base_branch = base_branch
        self.target_branch = target_branch
        self.allow_scripts = allow_scripts
        self.output_dir = Path(output_dir) if output_dir else Path(".offtest_runs")
        self.detect_flaky = detect_flaky
        self.quarantine_policy = quarantine_policy
        self.generate_tests = generate_tests
        self.accept_no_kernel_isolation = accept_no_kernel_isolation
        self.strip_sarif_snippets = strip_sarif_snippets
        self.app_tier = (app_tier or "unknown").lower()
        self.baseline_path = Path(baseline_path) if baseline_path else None

    def run(self) -> Tuple[RunContext, Path, Path, Path]:
        target_path = Path(self.input_target) if isinstance(self.input_target, (str, Path)) and Path(self.input_target).exists() else None
        has_kernel_isolation, isolation_diag = verify_kernel_sandbox_environment(target_path)
        if self.allow_scripts and not has_kernel_isolation:
            if not self.accept_no_kernel_isolation:
                raise SecurityError(
                    f"Execution Refused: --allow-scripts was requested on a bare host without container/kernel-level network isolation ({isolation_diag}). "
                    "Pass --accept-no-kernel-isolation to acknowledge bare-host execution, or execute inside a container (docker run --network none ...)."
                )
            is_automated = (
                (os.environ.get("CI", "").lower() in ("true", "1") or os.environ.get("GITHUB_ACTIONS", "").lower() in ("true", "1"))
                or (not sys.stdin.isatty())
            ) and ("PYTEST_CURRENT_TEST" not in os.environ) and (os.environ.get("OFFTEST_TESTING") != "1")
            if is_automated:
                raise SecurityError(
                    "Execution Refused: accept_no_kernel_isolation is strictly rejected in CI / automated environments (non-interactive shell or CI flags detected). "
                    "Hardened container air-gap isolation is mandatory."
                )

        run_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        run_folder = self.output_dir / run_id
        run_folder.mkdir(parents=True, exist_ok=True)

        # 1. Intake
        target_dir, is_temp = RepositoryIntake.prepare_target(self.input_target)
        repo_name = target_dir.name

        # 2. Hardened Git State (protected from malicious .git/config)
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

        # Mark branches with completed diffs as diffed
        for b in local_branches:
            if any(d.branch_name == b.name for d in branch_diffs):
                b.status = "diffed"

        # 3. Inventory & Multi-Ecosystem Offline SBOM Generation
        inv_engine = InventoryEngine(str(target_dir))
        files, inv_summary = inv_engine.scan()

        # 3b. Unified ProjectIndex (parse once, shared AST, symbol table, call graph & reachability)
        from offtest.core.project_index import ProjectIndex
        project_index = ProjectIndex(target_dir, files)

        sbom_generator = SBOMGenerator(target_dir, files)
        sbom_report = sbom_generator.generate()

        # 4. Application Mapping (routes, APIs, features, workflows, integrations)
        app_mapper = ApplicationMapper(target_dir, files, project_index=project_index)
        routes, apis, features, workflows, integrations = app_mapper.map_application()

        # 4b. RBAC Permission Matrix & Offline OpenAPI 3.1 Synthesis
        rbac_schema_extractor = RBACAndSchemaExtractor(target_dir, files, routes, apis)
        rbac_matrix = rbac_schema_extractor.extract_rbac()
        openapi_spec = rbac_schema_extractor.synthesize_openapi(title=f"{repo_name} API")

        # 5. Check Planning & Execution (inside scrubbed isolated runner)
        check_planner = CheckPlanner(
            target_dir,
            files,
            allow_scripts=self.allow_scripts,
            accept_no_kernel_isolation=self.accept_no_kernel_isolation,
            project_index=project_index,
            app_tier=self.app_tier,
        )
        active_b_name = git_state.get("active_branch") or "HEAD"
        check_results, findings = check_planner.execute_all(branch=active_b_name)

        # 5b. Flakiness Repeat-Sampling & Quarantine Analysis
        flakiness_runner = FlakinessRepeatSampler(target_dir, quarantine_policy=self.quarantine_policy)
        flakiness_report = flakiness_runner.analyze_results(check_results, enabled=self.detect_flaky)

        # 5c. Test-Confirmation Feedback Loop & Dynamic Priority Recalibration
        from offtest.checks.planner import calibrate_findings_with_test_results
        findings = calibrate_findings_with_test_results(findings, check_results, flakiness_report=flakiness_report)

        # 5d. AST Branch Predicates & Constrained Test Generation
        if self.generate_tests:
            try:
                generator = ConstrainedTestGenerator(target_dir, files, project_index=project_index)
                generated_test_suite = generator.generate_suite(output_dir=run_folder)
            except Exception as e:
                # A crash in the tool's own generated tests is an analysis failure, not a defect in user code.
                check_results.append(
                    CheckResult(
                        tool_name="test-synthesizer",
                        tool_version="0.1.0",
                        check_name="Automated Test Synthesis",
                        check_type="synthesis",
                        command="synthesize_tests",
                        exit_code=2,
                        duration_sec=0.0,
                        status=CheckStatus.ANALYSIS_INCOMPLETE,
                        skip_or_blocked_reason=f"Analysis incomplete: test synthesis harness error ({e})",
                    )
                )
                from offtest.core.models import GeneratedTestSuite
                generated_test_suite = GeneratedTestSuite()
        else:
            from offtest.core.models import GeneratedTestSuite
            generated_test_suite = GeneratedTestSuite()

        # 6. Coverage Evaluation (7 Dimensions with explicit Git Branch naming)
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
            "Static analysis provides full AST depth for Python; regex heuristics apply for other languages.",
            "Undocumented APIs and implicit workflows without local guards are explicitly tagged as Unverified.",
            "On Windows 11 / bare-metal host platforms, process isolation enforces environment scrubbing and proxy sinkholing; physical/kernel air-gap requires containerization (Docker --network none) or OS-level packet filtering.",
        ]
        if not self.allow_scripts:
            limitations.append(
                "Repository-provided test suites and build scripts were blocked from execution per the script safety approval policy."
            )

        assumptions = [
            f"Execution running on platform '{platform.platform()}' with Python '{sys.version.split()[0]}'.",
            "IsolatedRunner enforced environment scrubbing (host secrets stripped) and proxy nullification.",
            "No remote network calls or remote git fetches performed during assessment.",
            f"Application Tier: {self.app_tier} (treated as {'internal' if self.app_tier == 'internal' else 'public'} for security gate evaluation).",
        ]

        # 8. Assemble Context
        context = RunContext(
            schema_version="1.1.0",
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
            network_isolation_mode="container_kernel_airgap" if has_kernel_isolation else "python_egress_guard_defense_in_depth",
            allow_scripts=self.allow_scripts,
            accept_no_kernel_isolation=self.accept_no_kernel_isolation,
            kernel_isolation_active=has_kernel_isolation,
            app_tier=self.app_tier,
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
            # Extended features
            sbom=sbom_report,
            rbac_matrix=rbac_matrix,
            openapi_spec=openapi_spec,
            flakiness=flakiness_report,
            generated_test_suite=generated_test_suite,
            language_coverages=get_all_coverages(),
            skipped_generated_bundle_count=getattr(getattr(check_planner, "static_checker", None), "skipped_bundle_count", 0),
        )

        # 9. Save Evidence Store & Cryptographic Integrity Checksum (SHA-256)
        evidence_store = EvidenceStore(base_dir=str(self.output_dir))
        evidence_path = evidence_store.save_run(context)
        evidence_sha = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        atomic_write_text(run_folder / "evidence.json.sha256", f"{evidence_sha}  evidence.json\n")

        # 10. Generate Reports & SARIF 2.1.0 Export (Pre-persistence Redaction Barrier + Atomic Writes)
        detailed_gen = DetailedReportGenerator(context)
        detailed_md = redact_sensitive_data(detailed_gen.generate_markdown())
        detailed_report_path = run_folder / "REPORT_1_DETAILED.md"
        atomic_write_text(detailed_report_path, detailed_md, encoding="utf-8")

        # Detailed Report Split Branches (1A Hardcoded, 1B Code Defects)
        detailed_hardcoded_md = redact_sensitive_data(detailed_gen.generate_hardcoded_markdown())
        detailed_hardcoded_path = run_folder / "REPORT_1A_DETAILED_HARDCODED.md"
        atomic_write_text(detailed_hardcoded_path, detailed_hardcoded_md, encoding="utf-8")

        detailed_code_md = redact_sensitive_data(detailed_gen.generate_code_defects_markdown())
        detailed_code_path = run_folder / "REPORT_1B_DETAILED_CODE_DEFECTS.md"
        atomic_write_text(detailed_code_path, detailed_code_md, encoding="utf-8")

        # Issue Report Unified & Split Branches (2A Hardcoded, 2B Code Defects)
        issue_gen = IssueFocusedReportGenerator(context)
        issue_md = redact_sensitive_data(issue_gen.generate_markdown())
        issue_report_path = run_folder / "REPORT_2_ISSUES.md"
        atomic_write_text(issue_report_path, issue_md, encoding="utf-8")

        issue_hardcoded_md = redact_sensitive_data(issue_gen.generate_hardcoded_markdown())
        issue_hardcoded_path = run_folder / "REPORT_2A_ISSUES_HARDCODED.md"
        atomic_write_text(issue_hardcoded_path, issue_hardcoded_md, encoding="utf-8")

        issue_code_md = redact_sensitive_data(issue_gen.generate_code_defects_markdown())
        issue_code_path = run_folder / "REPORT_2B_ISSUES_CODE_DEFECTS.md"
        atomic_write_text(issue_code_path, issue_code_md, encoding="utf-8")

        workflow_gen = WorkflowReportGenerator(context)
        workflow_md = redact_sensitive_data(workflow_gen.generate_markdown())
        workflow_report_path = run_folder / "REPORT_3_WORKFLOWS.md"
        atomic_write_text(workflow_report_path, workflow_md, encoding="utf-8")

        sarif_gen = SARIFReportGenerator(context, strip_snippets=self.strip_sarif_snippets, baseline_path=self.baseline_path)
        sarif_path = run_folder / "results.sarif"
        sarif_gen.save_sarif(sarif_path)

        return OrchestratorResult(
            context,
            detailed_report_path,
            issue_report_path,
            sarif_path,
            workflow_path=workflow_report_path,
            detailed_hardcoded_path=detailed_hardcoded_path,
            detailed_code_path=detailed_code_path,
            issue_hardcoded_path=issue_hardcoded_path,
            issue_code_path=issue_code_path,
        )
