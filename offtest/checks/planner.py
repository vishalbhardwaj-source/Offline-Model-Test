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
    def __init__(self, repo_dir: Path, files: List[FileRecord], allow_scripts: bool = False, project_index: Optional[Any] = None):
        self.repo_dir = repo_dir
        self.files = files
        self.allow_scripts = allow_scripts
        self.project_index = project_index

    def execute_all(self, branch: str = "HEAD") -> Tuple[List[CheckResult], List[Finding]]:
        check_results: List[CheckResult] = []
        findings: List[Finding] = []

        import time
        # 1. Run Offline Static Analysis & Security
        static_checker = OfflineStaticChecker(self.repo_dir, self.files, project_index=self.project_index)
        _static_start = time.perf_counter()
        static_findings = static_checker.run_all(branch=branch)
        _static_elapsed = time.perf_counter() - _static_start
        findings.extend(static_findings)

        # Gate evaluation based on Category, Severity, and Certainty:
        # 1. Blocking security defects: VULNERABILITY or SECRET at Critical/High with Confirmed/Likely confidence.
        # (Possible-confidence and suppressed findings do not block gate)
        blocking_security = [
            f for f in static_findings
            if getattr(f, "category", FindingCategory.VULNERABILITY) in (FindingCategory.VULNERABILITY, FindingCategory.SECRET)
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
            and f.confidence in (Confidence.CONFIRMED, Confidence.LIKELY)
            and not getattr(f, "suppressed", False)
        ]

        # 2. Air-gap policy violations: POLICY at Critical/High with Confirmed/Likely confidence
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
        test_adapter = TestAdapter(self.repo_dir, self.files, allow_scripts=self.allow_scripts)
        adapter_results = test_adapter.discover_and_run()
        check_results.extend(adapter_results)

        return check_results, findings
