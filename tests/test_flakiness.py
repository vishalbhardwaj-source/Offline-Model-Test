import sys
from pathlib import Path
from offtest.checks.flakiness import FlakinessBisectionRunner
from offtest.core.models import CheckResult, CheckStatus


def test_flakiness_bisection_deterministic_pass(tmp_path: Path):
    runner = FlakinessBisectionRunner(tmp_path, iterations=3)
    check = CheckResult(
        tool_name="python",
        tool_version="3.12",
        check_name="Passing Test",
        check_type="unit_test",
        command=f"{sys.executable} -c pass",
        exit_code=0,
        duration_sec=0.01,
        status=CheckStatus.PASSED,
    )

    record = runner.evaluate_check(check)
    assert record.is_flaky is False
    assert record.passed_runs == 3
    assert record.failed_runs == 0


def test_flakiness_bisection_deterministic_fail(tmp_path: Path):
    runner = FlakinessBisectionRunner(tmp_path, iterations=3)
    check = CheckResult(
        tool_name="python",
        tool_version="3.12",
        check_name="Failing Test",
        check_type="unit_test",
        command=f"{sys.executable} -c import_syntax_error_xyz",
        exit_code=1,
        duration_sec=0.01,
        status=CheckStatus.FAILED,
    )

    record = runner.evaluate_check(check)
    assert record.is_flaky is False
    assert record.passed_runs == 0
    assert record.failed_runs == 3


def test_flakiness_report_aggregation(tmp_path: Path):
    runner = FlakinessBisectionRunner(tmp_path, iterations=2)
    checks = [
        CheckResult(
            tool_name="python",
            tool_version="3.12",
            check_name="Passing Test",
            check_type="unit_test",
            command=f"{sys.executable} -c pass",
            exit_code=0,
            duration_sec=0.01,
            status=CheckStatus.PASSED,
        )
    ]
    report = runner.analyze_results(checks, enabled=True)
    assert report.enabled is True
    assert report.tested_count == 1
    assert report.deterministic_passed_count == 1
    assert report.quarantined_flaky_count == 0
