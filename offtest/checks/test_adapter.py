import sys
from pathlib import Path
from typing import List
from offtest.checks.isolated_runner import IsolatedRunner
from offtest.core.models import CheckResult, CheckStatus, FileRecord


def _detect_pytest_version() -> str:
    try:
        import pytest
        return getattr(pytest, "__version__", "installed")
    except Exception:
        return "installed"


class TestAdapter:
    __test__ = False

    def __init__(self, repo_dir: Path, files: List[FileRecord], allow_scripts: bool = False):
        self.repo_dir = repo_dir
        self.files = files
        self.allow_scripts = allow_scripts
        self.runner = IsolatedRunner(self.repo_dir)

    def discover_and_run(self) -> List[CheckResult]:
        results: List[CheckResult] = []

        test_files = [f for f in self.files if f.category == "test"]
        has_python_tests = any(f.language == "Python" for f in test_files)
        has_js_tests = any(f.language in ["JavaScript", "TypeScript"] for f in test_files)
        has_package_json = any(f.path == "package.json" for f in self.files)

        # 1. Python tests discovery
        if has_python_tests:
            cmd = [sys.executable, "-m", "pytest", "-q", "--offline"]
            if not self.allow_scripts:
                results.append(
                    CheckResult(
                        tool_name="pytest",
                        tool_version=_detect_pytest_version(),
                        check_name="Python Pytest Suite",
                        check_type="unit_test",
                        command="python -m pytest",
                        exit_code=0,
                        duration_sec=0.0,
                        stdout="",
                        stderr="",
                        status=CheckStatus.BLOCKED,
                        execution_status="Blocked",
                        gate_outcome="Blocked",
                        skip_or_blocked_reason="Untrusted repository script execution blocked by default. Pass '--allow-scripts' to approve running project test suite.",
                    )
                )
            else:
                # Run with offline isolated runner (shield repo from .pytest_cache and __pycache__)
                pytest_cmd = [
                    sys.executable, "-B", "-m", "pytest", "-v",
                    "-p", "no:cacheprovider",
                ]
                code, out, err, dur = self.runner.run(pytest_cmd)
                exec_status = "Completed" if code in [0, 1] else "Error"
                gate = "Pass" if code == 0 else "Fail"
                results.append(
                    CheckResult(
                        tool_name="pytest",
                        tool_version=_detect_pytest_version(),
                        check_name="Python Pytest Suite",
                        check_type="unit_test",
                        command="python -m pytest -v",
                        exit_code=code,
                        duration_sec=dur,
                        stdout=out,
                        stderr=err,
                        status=CheckStatus.PASSED if code == 0 else CheckStatus.FAILED,
                        execution_status=exec_status,
                        gate_outcome=gate,
                    )
                )

        # 2. Node/JS tests discovery
        if has_js_tests or has_package_json:
            if not self.allow_scripts:
                results.append(
                    CheckResult(
                        tool_name="npm",
                        tool_version="local",
                        check_name="Node.js npm test Suite",
                        check_type="unit_test",
                        command="npm test --offline",
                        exit_code=0,
                        duration_sec=0.0,
                        stdout="",
                        stderr="",
                        status=CheckStatus.BLOCKED,
                        skip_or_blocked_reason="Untrusted repository script execution blocked by default. Pass '--allow-scripts' to approve running project test suite.",
                    )
                )
            else:
                code, out, err, dur = self.runner.run(["npm", "test"])
                results.append(
                    CheckResult(
                        tool_name="npm",
                        tool_version="local",
                        check_name="Node.js npm test Suite",
                        check_type="unit_test",
                        command="npm test --offline",
                        exit_code=code,
                        duration_sec=dur,
                        stdout=out,
                        stderr=err,
                        status=CheckStatus.PASSED if code == 0 else CheckStatus.FAILED,
                    )
                )

        return results
