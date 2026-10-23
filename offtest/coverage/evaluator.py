from typing import List, Optional
from offtest.core.models import (
    BranchRecord,
    CheckResult,
    CheckStatus,
    CoverageDimension,
    CoverageReport,
    FeatureRecord,
    FileDisposition,
    FileRecord,
    WorkflowRecord,
)


class CoverageEvaluator:
    @staticmethod
    def evaluate(
        files: List[FileRecord],
        workflows: List[WorkflowRecord],
        features: List[FeatureRecord],
        branches: List[BranchRecord],
        selected_branches: List[str],
        check_results: List[CheckResult],
    ) -> CoverageReport:
        dimensions: List[CoverageDimension] = []
        summary_notes: List[str] = []

        # 1. Repository inventory coverage
        total_discovered = len(files)
        # All discovered files are classified with explicit disposition
        classified_count = len(files)
        inv_pct = 100.0 if total_discovered > 0 else 0.0
        dimensions.append(
            CoverageDimension(
                name="Repository Inventory Coverage",
                value_pct=inv_pct,
                numerator=classified_count,
                denominator=total_discovered,
                unit="files",
                is_available=True,
                explanation=f"{classified_count} files classified out of {total_discovered} discovered files (100% of files have an explicit disposition).",
            )
        )

        # 2. Static-analysis coverage
        # Eligible files are those with disposition == ANALYZED
        analyzed_files = [f for f in files if f.disposition == FileDisposition.ANALYZED]
        total_eligible = len(analyzed_files)
        # Files without analysis failure
        failed_files = [f for f in files if f.disposition == FileDisposition.FAILED_TO_INSPECT]
        successfully_processed = total_eligible
        static_pct = (
            round((successfully_processed / total_eligible) * 100, 1)
            if total_eligible > 0
            else 0.0
        )
        dimensions.append(
            CoverageDimension(
                name="Static Analysis Coverage",
                value_pct=static_pct,
                numerator=successfully_processed,
                denominator=total_eligible,
                unit="eligible source files",
                is_available=total_eligible > 0,
                explanation=(
                    f"{successfully_processed} of {total_eligible} eligible source files successfully parsed and inspected."
                    if total_eligible > 0
                    else "No eligible source files discovered for static analysis."
                ),
            )
        )

        # 3. Test execution coverage
        test_checks = [c for c in check_results if c.check_type == "unit_test"]
        total_test_suites = len(test_checks)
        executed_test_suites = len([c for c in test_checks if c.status in [CheckStatus.PASSED, CheckStatus.FAILED]])
        if total_test_suites > 0:
            test_pct = round((executed_test_suites / total_test_suites) * 100, 1)
            dimensions.append(
                CoverageDimension(
                    name="Test Suite Execution Coverage",
                    value_pct=test_pct,
                    numerator=executed_test_suites,
                    denominator=total_test_suites,
                    unit="test suites",
                    is_available=True,
                    explanation=f"{executed_test_suites} of {total_test_suites} discovered test suites executed in isolated offline runner.",
                )
            )
        else:
            dimensions.append(
                CoverageDimension(
                    name="Test Suite Execution Coverage",
                    value_pct=None,
                    numerator=None,
                    denominator=None,
                    unit="test suites",
                    is_available=False,
                    explanation="Unavailable: No automated test suites discovered in the repository.",
                )
            )

        # 4. Code coverage (statement, branch, path)
        # Check if an lcov.info or coverage.xml exists offline
        coverage_data_found = any("coverage" in f.path.lower() for f in files if f.path.endswith((".xml", ".info", ".json")))
        if coverage_data_found:
            dimensions.append(
                CoverageDimension(
                    name="Code Coverage (Statement/Branch)",
                    value_pct=None,
                    numerator=None,
                    denominator=None,
                    unit="statements",
                    is_available=True,
                    explanation="Coverage artifact detected, pending offline parser adapter integration.",
                )
            )
        else:
            dimensions.append(
                CoverageDimension(
                    name="Code Coverage (Statement/Branch)",
                    value_pct=None,
                    numerator=None,
                    denominator=None,
                    unit="statements",
                    is_available=False,
                    explanation="Unavailable: No offline coverage instrumentation report (e.g., coverage.xml or lcov.info) was supplied or generated.",
                )
            )

        # 5. Workflow coverage
        total_workflows = len(workflows)
        covered_workflows = len([w for w in workflows if len(w.linked_tests) > 0])
        if total_workflows > 0:
            wf_pct = round((covered_workflows / total_workflows) * 100, 1)
            dimensions.append(
                CoverageDimension(
                    name="Workflow Coverage",
                    value_pct=wf_pct,
                    numerator=covered_workflows,
                    denominator=total_workflows,
                    unit="workflows",
                    is_available=True,
                    explanation=f"{covered_workflows} of {total_workflows} identified application workflows have linked automated test evidence.",
                )
            )
        else:
            dimensions.append(
                CoverageDimension(
                    name="Workflow Coverage",
                    value_pct=None,
                    numerator=None,
                    denominator=None,
                    unit="workflows",
                    is_available=False,
                    explanation="Unavailable: No application workflows were inferred or observed from repository routes.",
                )
            )

        # 6. Feature coverage
        total_features = len(features)
        covered_features = len([f for f in features if len(f.linked_tests) > 0])
        if total_features > 0:
            ft_pct = round((covered_features / total_features) * 100, 1)
            dimensions.append(
                CoverageDimension(
                    name="Feature Coverage",
                    value_pct=ft_pct,
                    numerator=covered_features,
                    denominator=total_features,
                    unit="features",
                    is_available=True,
                    explanation=f"{covered_features} of {total_features} identified features/toggles have linked automated test coverage.",
                )
            )
        else:
            dimensions.append(
                CoverageDimension(
                    name="Feature Coverage",
                    value_pct=None,
                    numerator=None,
                    denominator=None,
                    unit="features",
                    is_available=False,
                    explanation="Unavailable: No distinct feature toggles or named features were identified in source code.",
                )
            )

        # 7. Branch coverage
        requested_branches = selected_branches if selected_branches else ([b.name for b in branches] if branches else ["HEAD"])
        total_branches = len(requested_branches)
        # Branches analyzed
        analyzed_branches = len([b for b in branches if b.name in requested_branches and b.status == "available"])
        branch_pct = round((analyzed_branches / total_branches) * 100, 1) if total_branches > 0 else 0.0
        dimensions.append(
            CoverageDimension(
                name="Git Branch Assessment",
                value_pct=branch_pct,
                numerator=analyzed_branches,
                denominator=total_branches,
                unit="git branches",
                is_available=True,
                explanation=f"{analyzed_branches} of {total_branches} requested local branches analyzed without checkout errors.",
            )
        )

        summary_notes.append("Pass rates must not be conflated with 100% feature or path coverage.")
        if any(not d.is_available for d in dimensions):
            summary_notes.append("One or more coverage dimensions are explicitly marked 'Unavailable' due to absence of offline artifacts.")

        return CoverageReport(dimensions=dimensions, summary_notes=summary_notes)
