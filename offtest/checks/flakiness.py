import math
import shlex
import sys
import time
from pathlib import Path
from typing import List, Tuple
from offtest.checks.isolated_runner import IsolatedRunner
from offtest.core.models import (
    CheckResult,
    CheckStatus,
    FlakinessReport,
    QuarantinedTestRecord,
)


class FlakinessBisectionRunner:
    """Executes multi-run bisection testing to identify, measure, and quarantine flaky tests."""

    def __init__(self, repo_dir: Path, iterations: int = 3):
        self.repo_dir = repo_dir
        self.iterations = max(2, iterations)
        self.runner = IsolatedRunner(self.repo_dir)

    def evaluate_check(self, check: CheckResult) -> QuarantinedTestRecord:
        """Runs the given command N times to test for outcome stability."""
        durations: List[float] = []
        exit_codes: List[int] = []
        failures: List[str] = []

        try:
            if sys.platform == "win32":
                cmd_parts = shlex.split(check.command, posix=False)
            else:
                cmd_parts = shlex.split(check.command)
        except Exception:
            cmd_parts = check.command.split()

        for _ in range(self.iterations):
            code, out, err, dur = self.runner.run(cmd_parts)
            durations.append(round(dur, 4))
            exit_codes.append(code)
            if code != 0:
                snippet = (err.strip() or out.strip())[:200]
                if snippet and snippet not in failures:
                    failures.append(snippet)

        passed = sum(1 for c in exit_codes if c == 0)
        failed = sum(1 for c in exit_codes if c != 0)
        is_flaky = (passed > 0) and (failed > 0)

        # Calculate duration variance
        mean_dur = sum(durations) / len(durations) if durations else 0.0
        variance = sum((d - mean_dur) ** 2 for d in durations) / len(durations) if len(durations) > 1 else 0.0

        return QuarantinedTestRecord(
            test_identifier=check.check_name,
            total_runs=self.iterations,
            passed_runs=passed,
            failed_runs=failed,
            is_flaky=is_flaky,
            durations_sec=durations,
            variance_sec=round(variance, 6),
            failure_messages=failures,
        )

    def analyze_results(self, test_checks: List[CheckResult], enabled: bool = True) -> FlakinessReport:
        if not enabled or not test_checks:
            return FlakinessReport(enabled=enabled)

        quarantined: List[QuarantinedTestRecord] = []
        det_pass = 0
        det_fail = 0
        flaky_count = 0

        for chk in test_checks:
            if chk.status in [CheckStatus.SKIPPED, CheckStatus.BLOCKED]:
                continue

            record = self.evaluate_check(chk)
            if record.is_flaky:
                flaky_count += 1
                quarantined.append(record)
            elif record.passed_runs == record.total_runs:
                det_pass += 1
            else:
                det_fail += 1

        return FlakinessReport(
            enabled=True,
            tested_count=len(test_checks),
            deterministic_passed_count=det_pass,
            deterministic_failed_count=det_fail,
            quarantined_flaky_count=flaky_count,
            quarantined_tests=quarantined,
        )
