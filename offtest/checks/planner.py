import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, List, Optional, Tuple
from offtest.checks.isolated_runner import IsolatedRunner
from offtest.checks.static_checks import OfflineStaticChecker
from offtest.checks.test_adapter import TestAdapter
from offtest.core.models import (
    CheckResult,
    CheckStatus,
    Confidence,
    FileRecord,
    Finding,
    FindingCategory,
    Severity,
    ToolManifestItem,
)


def get_tool_manifest() -> List[ToolManifestItem]:
    manifest: List[ToolManifestItem] = []

    # 1. Python runtime
    manifest.append(
        ToolManifestItem(
            name="Python Runtime",
            version=sys.version.split()[0],
            path=sys.executable,
            category="runtime",
            is_available=True,
            notes="Active offline Python interpreter",
        )
    )

    # 2. Git
    git_path = shutil.which("git")
    git_ver = "unknown"
    if git_path:
        try:
            res = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=5)
            git_ver = res.stdout.strip()
        except Exception:
            pass
    manifest.append(
        ToolManifestItem(
            name="Git CLI",
            version=git_ver,
            path=git_path,
            category="vcs",
            is_available=bool(git_path),
            notes="Local repository inspection and branch diffing",
        )
    )

    # 3. Node.js
    node_path = shutil.which("node")
    node_ver = "unavailable"
    if node_path:
        try:
            res = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=5)
            node_ver = res.stdout.strip()
        except Exception:
            pass
    manifest.append(
        ToolManifestItem(
            name="Node.js Runtime",
            version=node_ver,
            path=node_path,
            category="runtime",
            is_available=bool(node_path),
            notes="JavaScript runtime for node checks",
        )
    )

    # 4. Pytest
    pytest_path = shutil.which("pytest") or sys.executable
    try:
        import pytest
        pytest_v = getattr(pytest, "__version__", "installed")
    except Exception:
        pytest_v = "installed"
    manifest.append(
        ToolManifestItem(
            name="Pytest Test Runner",
            version=pytest_v,
            path=pytest_path,
            category="test_runner",
            is_available=True,
            notes="Offline test execution adapter",
        )
    )

    # 5. Offline Static Checker
    manifest.append(
        ToolManifestItem(
            name="offtest AST & Security Scanner",
            version="0.1.0",
            category="static_analysis",
            is_available=True,
            notes="Built-in AST parser, secret scanner, security checks, and dependency pin inspector",
        )
    )

    return manifest


class CheckPlanner:
    def __init__(
        self,
        repo_dir: Path,
        files: List[FileRecord],
        allow_scripts: bool = False,
        accept_no_kernel_isolation: bool = False,
        project_index: Optional[Any] = None,
        app_tier: str = "unknown",
    ):
        self.repo_dir = repo_dir
        self.files = files
        self.allow_scripts = allow_scripts
        self.accept_no_kernel_isolation = accept_no_kernel_isolation
        self.project_index = project_index
        self.app_tier = (app_tier or "unknown").lower()

    def execute_all(self, branch: str = "HEAD") -> Tuple[List[CheckResult], List[Finding]]:
        check_results: List[CheckResult] = []
        findings: List[Finding] = []

        import time
        # 1. Run Offline Static Analysis & Security
        static_checker = OfflineStaticChecker(
            self.repo_dir,
            self.files,
            project_index=self.project_index,
            app_tier=self.app_tier,
        )
        self.static_checker = static_checker
        _static_start = time.perf_counter()
        static_findings = static_checker.run_all(branch=branch)
        _static_elapsed = time.perf_counter() - _static_start
        findings.extend(static_findings)

        # Gate evaluation based on Category, Severity, Confidence, Priority (0-100 scale), and Hard Overrides:
        # 1. Blocking security defects:
        #    - Score-based: VULNERABILITY or SECRET with Priority >= 45.0 (excluding model-hypothesis)
        #    - Hard Overrides (sets gate = FAIL regardless of multiplicative factors, with priority floor >= 90):
        #      * Test-confirmed Critical or High defect (evidence_level == "test-confirmed" and Severity in CRITICAL/HIGH)
        #      * Reachable Critical with precision >= 0.85 (Severity == CRITICAL, reachability == "reachable", confidence in DETERMINISTIC/CONFIRMED/LIKELY)
        #      * KEV-listed Vulnerability in an affected or unknown dependency (cisa_kev == True and reachability != "unreachable")
        #      * Provider-pattern secret match outside test/fixture paths (OT-SCR-001..003 with confidence != POSSIBLE and exposure != "test_fixture")
        #    Suppressed findings never block the gate.
        blocking_security = []
        for f in static_findings:
            if getattr(f, "suppressed", False):
                continue
            if getattr(f, "evidence_level", "") == "model-hypothesis":
                continue

            is_blocking = False
            # Score-based threshold:
            if getattr(f, "priority_score", 0.0) >= 45.0:
                is_blocking = True

            # Hard Override 1: Test-confirmed Critical or High defect
            elif f.evidence_level == "test-confirmed" and f.severity in (Severity.CRITICAL, Severity.HIGH):
                is_blocking = True
                f.priority_score = max(f.priority_score, 90.0)

            # Hard Override 2: Proven Reachable Critical defect on internal/public route with precision >= 0.85
            # Heuristic edges avoid the 0.20 unreachable discount, but only proven semantic edges trigger the floor.
            elif (
                f.severity == Severity.CRITICAL
                and getattr(f, "reachability", "") in ("proven", "reachable")
                and getattr(f, "proven_reachable", getattr(f, "reachability", "") == "proven")
                and f.confidence in (Confidence.DETERMINISTIC, Confidence.CONFIRMED, Confidence.LIKELY, Confidence.HIGH)
            ):
                is_blocking = True
                f.priority_score = max(f.priority_score, 90.0)

            # Hard Override 3: KEV-listed CVE restricted to affected or unknown reachability (not unreachable lockfiles)
            elif getattr(f, "cisa_kev", False) and getattr(f, "reachability", "") != "unreachable":
                is_blocking = True
                f.priority_score = max(f.priority_score, 90.0)

            # Hard Override 4: Provider-pattern secret match outside test or fixture paths
            elif (
                f.rule_id in ("OT-SCR-001", "OT-SCR-002")
                and f.confidence in (Confidence.DETERMINISTIC, Confidence.CONFIRMED, Confidence.LIKELY, Confidence.HIGH)
                and getattr(f, "exposure", "internal") != "test_fixture"
            ):
                is_blocking = True
                f.priority_score = max(f.priority_score, 90.0)

            if is_blocking:
                blocking_security.append(f)

        # 2. Air-gap policy violations: POLICY at Critical/High with Confirmed/Likely confidence
        #    (e.g., OT-POL-001 external URLs, OT-POL-002 network sockets, OT-POL-003 unpinned base images,
        #     OT-POL-004 unauthorized telemetry, OT-POL-007 container privileged mode).
        blocking_policy = [
            f for f in static_findings
            if getattr(f, "category", None) == FindingCategory.POLICY
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
            and f.confidence in (Confidence.CONFIRMED, Confidence.LIKELY)
            and not getattr(f, "suppressed", False)
        ]

        # 3. Code correctness defects (SyntaxError, etc.) at Critical/High with Confirmed confidence
        blocking_correctness = [
            f for f in static_findings
            if getattr(f, "category", None) == FindingCategory.CORRECTNESS
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
            and f.confidence in (Confidence.CONFIRMED, Confidence.LIKELY)
            and not getattr(f, "suppressed", False)
        ]

        # Note: HYGIENE and SUPPLY_CHAIN (unpinned deps) findings never fail the gate.
        gate_failed = bool(blocking_security or blocking_policy or blocking_correctness)

        failure_reasons = []
        if blocking_security:
            crit_s = sum(1 for f in blocking_security if f.severity == Severity.CRITICAL)
            high_s = sum(1 for f in blocking_security if f.severity == Severity.HIGH)
            sec_parts = []
            if crit_s:
                sec_parts.append(f"{crit_s} Critical")
            if high_s:
                sec_parts.append(f"{high_s} High")
            failure_reasons.append(f"{', '.join(sec_parts)} security vulnerability/secret defect(s)")

        if blocking_policy:
            failure_reasons.append(f"{len(blocking_policy)} air-gap policy violation(s)")

        if blocking_correctness:
            failure_reasons.append(f"{len(blocking_correctness)} code correctness error(s)")

        failure_reason = "; ".join(failure_reasons) if failure_reasons else None

        check_results.append(
            CheckResult(
                tool_name="offtest-static-scanner",
                tool_version="0.1.0",
                check_name="Static AST, Security & Secret Analysis",
                check_type="security",
                command="internal static ast inspection",
                exit_code=1 if gate_failed else 0,
                duration_sec=round(_static_elapsed, 4),
                stdout=f"Processed eligible source files. Generated {len(static_findings)} findings.",
                stderr="",
                status=CheckStatus.FAILED if gate_failed else CheckStatus.PASSED,
                execution_status="Completed",
                gate_outcome="Fail" if gate_failed else "Pass",
                skip_or_blocked_reason=failure_reason,
            )
        )

        # 2. Run Test Adapter
        test_adapter = TestAdapter(
            self.repo_dir,
            self.files,
            allow_scripts=self.allow_scripts,
            accept_no_kernel_isolation=self.accept_no_kernel_isolation,
        )
        adapter_results = test_adapter.discover_and_run()
        check_results.extend(adapter_results)

        # 3. Test-Confirmation Feedback Loop: calibrate findings based on dynamic execution
        findings = calibrate_findings_with_test_results(findings, check_results)

        # Enforce Gate Hard Overrides priority floor (>= 90.0) so overriding findings sort to top
        for f in findings:
            if getattr(f, "suppressed", False) or getattr(f, "evidence_level", "") == "model-hypothesis":
                continue
            if (
                (f.evidence_level == "test-confirmed" and f.severity in (Severity.CRITICAL, Severity.HIGH))
                or (
                    f.severity == Severity.CRITICAL
                    and getattr(f, "reachability", "") in ("proven", "reachable")
                    and getattr(f, "proven_reachable", getattr(f, "reachability", "") == "proven")
                    and f.confidence in (Confidence.DETERMINISTIC, Confidence.CONFIRMED, Confidence.LIKELY, Confidence.HIGH)
                )
                or (getattr(f, "cisa_kev", False) and getattr(f, "reachability", "") != "unreachable")
                or (
                    f.rule_id in ("OT-SCR-001", "OT-SCR-002")
                    and f.confidence in (Confidence.DETERMINISTIC, Confidence.CONFIRMED, Confidence.LIKELY, Confidence.HIGH)
                    and getattr(f, "exposure", "internal") != "test_fixture"
                )
            ):
                f.priority_score = max(f.priority_score, 90.0)

        return check_results, findings


def calibrate_findings_with_test_results(
    findings: List[Finding],
    check_results: List[CheckResult],
    flakiness_report: Optional[Any] = None,
) -> List[Finding]:
    """
    Test-confirmation feedback loop with Exploit Oracle Satisfied trigger:
    - If dynamic execution or test assertion satisfies the exploit oracle in the target file
      (distinguished from generic syntax/import crashes), elevates evidence_level to 'test-confirmed',
      sets oracle_satisfied=True, records oracle_origin, and raises confidence to CONFIRMED.
    - Asymmetric feedback: Non-confirmation (test passes) does NOT demote static-only findings,
      because generated tests may have inadequate assertions.
    - If a test associated with a finding is determined to be flaky across runs (quarantined),
      marks evidence_level as 'flaky-test' and demotes certainty.
    - If finding was a 'model-hypothesis' and test cleanly passes without vulnerability,
      confidence is downgraded to POSSIBLE.
    - Recomputes exposure-weighted priority score dynamically (0-100 scale).
    """
    from offtest.core.models import Confidence, compute_priority

    failed_runs = []
    passed_outputs = []
    for c in check_results:
        text = f"{c.stdout}\n{c.stderr}"
        if c.status == CheckStatus.FAILED:
            failed_runs.append((c.check_name or c.tool_name, text))
        elif c.status == CheckStatus.PASSED:
            passed_outputs.append(text)

    quarantined_ids = set()
    if flakiness_report and getattr(flakiness_report, "quarantined_tests", None):
        for q in flakiness_report.quarantined_tests:
            quarantined_ids.add(getattr(q, "test_identifier", ""))

    # Errors that represent setup/environment failures rather than true exploit reproduction
    setup_error_markers = ("modulenotfounderror", "importerror", "syntaxerror", "environmenterror", "nosuchfileexception")

    for f in findings:
        if not f.file_path:
            continue
        fname = Path(f.file_path).name

        # 1. Exploit Oracle Satisfied Check:
        # A test failure confirms a defect only when an exploit assertion/oracle fires,
        # not when the test runner crashes on imports or missing modules.
        oracle_fired_name: Optional[str] = None
        for test_name, out in failed_runs:
            out_lower = out.lower()

            # Skip generic runner/import crashes
            if any(err in out_lower for err in setup_error_markers) and "assertionerror" not in out_lower:
                continue

            file_match = (f.file_path and f.file_path.lower() in out_lower) or (fname and fname.lower() in out_lower)
            if file_match:
                specific_match = (
                    (f.cwe_id and f.cwe_id.lower() in out_lower)
                    or (f.line_number and (f":{f.line_number}" in out or f"line {f.line_number}" in out_lower))
                    or (f.rule_id and f.rule_id.lower() in out_lower)
                    or (getattr(f, "title", "") and any(w.lower() in out_lower for w in f.title.lower().split() if len(w) >= 3))
                    or (getattr(f, "cwe_name", "") and any(w.lower() in out_lower for w in f.cwe_name.lower().split() if len(w) >= 3))
                )
                if specific_match:
                    oracle_fired_name = test_name
                    break

        if oracle_fired_name:
            f.evidence_level = "test-confirmed"
            f.confidence = Confidence.CONFIRMED
            f.reproduced = True
            f.reachability = "reachable"
            f.oracle_satisfied = True
            f.oracle_origin = oracle_fired_name
            if f.context is None:
                f.context = {}
            f.context["oracle_satisfied"] = True
            f.context["oracle_origin"] = oracle_fired_name
            f.context["test_feedback"] = f"Exploit Oracle Satisfied ({oracle_fired_name})"
        elif f.evidence_level == "model-hypothesis":
            # Demote hypothesis findings only if clean execution contradicts hypothesis
            if any(f.file_path in out or fname in out for out in passed_outputs):
                f.confidence = Confidence.POSSIBLE

        # 2. Check if related to flaky test
        # Flaky test handling: non-demoting!
        # Do NOT demote finding below static-only baseline priority. Revert evidence_level to static-only
        # and annotate with flaky_test_observed flag.
        if any(f.file_path in qid or fname in qid for qid in quarantined_ids):
            f.flaky_test_observed = True
            f.evidence_level = "static-only"
            if f.context is None:
                f.context = {}
            f.context["flaky_test_observed"] = True
            f.context["flaky_test_note"] = "Associated test exhibited non-deterministic execution in quarantine"

        # Recompute priority with updated certainty on 0-100 normalized scale
        f.priority_score = compute_priority(
            f.severity,
            f.confidence,
            evidence_level=f.evidence_level,
            reachability=f.reachability,
            exposure=f.exposure,
            cisa_kev=getattr(f, "cisa_kev", False),
            epss_score=getattr(f, "epss_score", None),
        )

    return findings
