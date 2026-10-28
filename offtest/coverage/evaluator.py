import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
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


@dataclass
class LineSuspicion:
    file_path: str
    line_number: int
    score: float  # Ochiai score between 0.0 and 1.0
    failing_tests_count: int
    passing_tests_count: int


def compute_ochiai_scores(
    failed_lines: Dict[Tuple[str, int], int],
    passed_lines: Dict[Tuple[str, int], int],
    total_failed: int,
) -> List[LineSuspicion]:
    """
    Computes Ochiai spectrum-based fault localization scores:
    Ochiai = failed(line) / sqrt(total_failed * (failed(line) + passed(line)))
    Scores range from 0.0 to 1.0; lines with higher scores are prioritized fault candidates.
    """
    if total_failed <= 0:
        return []
    all_lines = set(failed_lines.keys()) | set(passed_lines.keys())
    results: List[LineSuspicion] = []
    for f_path, line_no in all_lines:
        n_fail = failed_lines.get((f_path, line_no), 0)
        n_pass = passed_lines.get((f_path, line_no), 0)
        denom = math.sqrt(total_failed * (n_fail + n_pass))
        score = (n_fail / denom) if denom > 0 else 0.0
        if score > 0.0:
            results.append(
                LineSuspicion(
                    file_path=f_path,
                    line_number=line_no,
                    score=round(score, 4),
                    failing_tests_count=n_fail,
                    passing_tests_count=n_pass,
                )
            )
    results.sort(key=lambda s: s.score, reverse=True)
    return results


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

        # 1. Repository inventory disposition (reported as breakdown, percentages reserved for verifiable test dimensions)
        total_discovered = len(files)
        analyzed_count = len([f for f in files if f.disposition == FileDisposition.ANALYZED])
        excluded_count = len([f for f in files if f.disposition == FileDisposition.EXCLUDED])
        generated_count = len([f for f in files if f.disposition == FileDisposition.GENERATED])
        binary_count = len([f for f in files if f.disposition == FileDisposition.BINARY])
        unsupported_count = len([f for f in files if f.disposition == FileDisposition.UNSUPPORTED])
        failed_count = len([f for f in files if f.disposition == FileDisposition.FAILED_TO_INSPECT])

        dimensions.append(
            CoverageDimension(
                name="Repository Inventory Disposition",
                value_pct=None,
                numerator=analyzed_count,
                denominator=total_discovered,
                unit="total cataloged files",
                is_available=True,
                explanation=f"Cataloged {total_discovered} total repository files: {analyzed_count} analyzed, {excluded_count} excluded, {generated_count} generated, {binary_count} binary, {unsupported_count} unsupported, {failed_count} unreadable. (Percentages reserved for actionable test dimensions).",
            )
        )

        # 2. Static-analysis coverage (with per-analyzer attribution)
        analyzed_files = [f for f in files if f.disposition == FileDisposition.ANALYZED]
        total_eligible = len(analyzed_files)
        failed_files = [f for f in files if f.disposition == FileDisposition.FAILED_TO_INSPECT]
        successfully_processed = total_eligible
        static_pct = (
            round((successfully_processed / total_eligible) * 100, 1)
            if total_eligible > 0
            else 0.0
        )

        # Breakdown by analyzer
        py_cnt = len([f for f in analyzed_files if f.language == "Python"])
        html_cnt = len([f for f in analyzed_files if f.language == "HTML"])
        req_cnt = len([f for f in analyzed_files if f.language in ["Requirements", "JSON", "YAML", "TOML"]])
        js_cnt = len([f for f in analyzed_files if "JavaScript" in (f.language or "") or "TypeScript" in (f.language or "")])
        parts = []
        if py_cnt: parts.append(f"{py_cnt} Python (AST security & syntax parsing)")
        if html_cnt: parts.append(f"{html_cnt} HTML (DOM template & route mapper)")
        if req_cnt: parts.append(f"{req_cnt} Manifest/Config (SBOM & pin inspector)")
        if js_cnt: parts.append(f"{js_cnt} JS/TS (syntax & regex route extractor)")
        analyzer_desc = f": {', '.join(parts)}" if parts else ""

        dimensions.append(
            CoverageDimension(
                name="Static Analysis Coverage",
                value_pct=static_pct,
                numerator=successfully_processed,
                denominator=total_eligible,
                unit="eligible source files",
                is_available=total_eligible > 0,
                explanation=(
                    f"{successfully_processed} of {total_eligible} eligible source files inspected across offline analyzers{analyzer_desc}. 0 parse failures."
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

        # Check if test suites were executed (synthesized tests never count toward confirmed coverage)
        has_executed_tests = executed_test_suites > 0

        # 5. Workflow coverage
        total_workflows = len(workflows)
        covered_workflows = 0
        if has_executed_tests:
            covered_workflows = len([
                w for w in workflows
                if any(lt for lt in w.linked_tests if "synthesized" not in lt.lower())
            ])

        if total_workflows > 0:
            wf_pct = round((covered_workflows / total_workflows) * 100, 1)
            expl = (
                f"{covered_workflows} of {total_workflows} identified application workflows have linked automated test evidence."
                if has_executed_tests
                else f"0 of {total_workflows} application workflows confirmed covered (test suite execution was blocked or not run; synthesized tests are excluded from confirmed coverage)."
            )
            dimensions.append(
                CoverageDimension(
                    name="Workflow Coverage",
                    value_pct=wf_pct,
                    numerator=covered_workflows,
                    denominator=total_workflows,
                    unit="workflows",
                    is_available=True,
                    explanation=expl,
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
        covered_features = 0
        if has_executed_tests:
            covered_features = len([
                f for f in features
                if any(lt for lt in f.linked_tests if "synthesized" not in lt.lower())
            ])

        if total_features > 0:
            ft_pct = round((covered_features / total_features) * 100, 1)
            expl = (
                f"{covered_features} of {total_features} identified features/toggles have linked automated test coverage."
                if has_executed_tests
                else f"0 of {total_features} identified features/toggles confirmed covered (test suite execution was blocked or not run; synthesized tests are excluded from confirmed coverage)."
            )
            dimensions.append(
                CoverageDimension(
                    name="Feature Coverage",
                    value_pct=ft_pct,
                    numerator=covered_features,
                    denominator=total_features,
                    unit="features",
                    is_available=True,
                    explanation=expl,
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

        # 7. Git Branch Assessment
        requested_branches = selected_branches if selected_branches else ([b.name for b in branches] if branches else ["HEAD"])
        total_branches = len(requested_branches)
        # A branch only counts as assessed if it was actively scanned (current active branch) or diffed/assessed
        assessed_branches = len([
            b for b in branches
            if b.name in requested_branches and (b.is_current or b.status in ["assessed", "diffed"])
        ])
        branch_pct = round((assessed_branches / total_branches) * 100, 1) if total_branches > 0 else 0.0
        active_name = next((b.name for b in branches if b.is_current), "HEAD")
        unassessed_branches = [b.name for b in branches if b.name in requested_branches and not (b.is_current or b.status in ["assessed", "diffed"])]
        if unassessed_branches:
            unassessed_str = f"; {len(unassessed_branches)} unmerged branch(es) [{', '.join(unassessed_branches)}] not diffed or scanned"
        else:
            unassessed_str = ""
        dimensions.append(
            CoverageDimension(
                name="Git Branch Assessment",
                value_pct=branch_pct,
                numerator=assessed_branches,
                denominator=total_branches,
                unit="git branches",
                is_available=True,
                explanation=f"{assessed_branches} of {total_branches} requested local branches assessed ({active_name} scanned as active branch{unassessed_str}).",
            )
        )

        summary_notes.append("Pass rates must not be conflated with 100% feature or path coverage.")
        if any(not d.is_available for d in dimensions):
            summary_notes.append("One or more coverage dimensions are explicitly marked 'Unavailable' due to absence of offline artifacts.")

        return CoverageReport(dimensions=dimensions, summary_notes=summary_notes)

    @staticmethod
    def locate_faults_ochiai(
        failed_lines: Dict[Tuple[str, int], int],
        passed_lines: Dict[Tuple[str, int], int],
        total_failed: int,
    ) -> List[LineSuspicion]:
        return compute_ochiai_scores(failed_lines, passed_lines, total_failed)
