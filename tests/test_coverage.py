from offtest.core.models import (
    BranchRecord,
    CheckResult,
    CheckStatus,
    FeatureRecord,
    FileDisposition,
    FileRecord,
    WorkflowRecord,
)
from offtest.coverage.evaluator import CoverageEvaluator


def test_coverage_dimensions():
    files = [
        FileRecord(
            path="app.py",
            size_bytes=100,
            sha256="abc",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Supported",
        ),
        FileRecord(
            path="data.bin",
            size_bytes=50,
            sha256="def",
            disposition=FileDisposition.BINARY,
            disposition_reason="Binary format",
        ),
    ]

    workflows = [
        WorkflowRecord(
            name="Login Workflow",
            description="User login",
            linked_tests=["test_auth.py"],
        )
    ]

    features = [
        FeatureRecord(
            name="Dark Mode",
            flag_key="FEATURE_DARK_MODE",
            file_path="app.py",
            linked_tests=[],
        )
    ]

    branches = [
        BranchRecord(name="main", is_current=True, is_base=True, status="available")
    ]

    checks = [
        CheckResult(
            tool_name="pytest",
            tool_version="1.0",
            check_name="Unit Tests",
            check_type="unit_test",
            command="pytest",
            exit_code=0,
            duration_sec=0.5,
            status=CheckStatus.PASSED,
        )
    ]

    report = CoverageEvaluator.evaluate(
        files=files,
        workflows=workflows,
        features=features,
        branches=branches,
        selected_branches=["main"],
        check_results=checks,
    )

    dims = {d.name: d for d in report.dimensions}

    # All 7 dimensions must exist!
    assert "Repository Inventory Disposition" in dims
    assert dims["Repository Inventory Disposition"].numerator == 1
    assert dims["Repository Inventory Disposition"].denominator == 2

    assert "Static Analysis Coverage" in dims
    assert dims["Static Analysis Coverage"].value_pct == 100.0

    assert "Test Suite Execution Coverage" in dims
    assert dims["Test Suite Execution Coverage"].value_pct == 100.0

    assert "Code Coverage (Statement/Branch)" in dims
    assert dims["Code Coverage (Statement/Branch)"].is_available is False  # Explicitly Unavailable!

    assert "Workflow Coverage" in dims
    assert dims["Workflow Coverage"].value_pct == 100.0

    assert "Feature Coverage" in dims
    assert dims["Feature Coverage"].value_pct == 0.0  # 0 of 1 linked

    assert "Git Branch Assessment" in dims
    assert dims["Git Branch Assessment"].value_pct == 100.0
