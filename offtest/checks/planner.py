import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple
from offtest.checks.isolated_runner import IsolatedRunner
from offtest.checks.static_checks import OfflineStaticChecker
from offtest.checks.test_adapter import TestAdapter
from offtest.core.models import CheckResult, CheckStatus, FileRecord, Finding, ToolManifestItem


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
    def __init__(self, repo_dir: Path, files: List[FileRecord], allow_scripts: bool = False):
        self.repo_dir = repo_dir
        self.files = files
        self.allow_scripts = allow_scripts

    def execute_all(self, branch: str = "HEAD") -> Tuple[List[CheckResult], List[Finding]]:
        check_results: List[CheckResult] = []
        findings: List[Finding] = []

        import time
        # 1. Run Offline Static Analysis & Security
        static_checker = OfflineStaticChecker(self.repo_dir, self.files)
        _static_start = time.perf_counter()
        static_findings = static_checker.run_all(branch=branch)
        _static_elapsed = time.perf_counter() - _static_start
        findings.extend(static_findings)

        crit_count = len([f for f in static_findings if f.severity.value == "Critical"])
        high_count = len([f for f in static_findings if f.severity.value == "High"])
        has_critical_or_high = (crit_count + high_count) > 0

        failure_reason = None
        if has_critical_or_high:
            reasons = []
            if crit_count > 0:
                reasons.append(f"{crit_count} Critical")
            if high_count > 0:
                reasons.append(f"{high_count} High")
            failure_reason = f"{', '.join(reasons)} security defect(s) detected"

        check_results.append(
            CheckResult(
                tool_name="offtest-static-scanner",
                tool_version="0.1.0",
                check_name="Static AST, Security & Secret Analysis",
                check_type="security",
                command="internal static ast inspection",
                exit_code=1 if has_critical_or_high else 0,
                duration_sec=round(_static_elapsed, 4),
                stdout=f"Processed eligible source files. Generated {len(static_findings)} findings.",
                stderr="",
                status=CheckStatus.FAILED if has_critical_or_high else CheckStatus.PASSED,
                execution_status="Completed",
                gate_outcome="Fail" if has_critical_or_high else "Pass",
                skip_or_blocked_reason=failure_reason,
            )
        )

        # 2. Run Test Adapter
        test_adapter = TestAdapter(self.repo_dir, self.files, allow_scripts=self.allow_scripts)
        adapter_results = test_adapter.discover_and_run()
        check_results.extend(adapter_results)

        return check_results, findings
