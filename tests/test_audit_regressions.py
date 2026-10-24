import ast
from pathlib import Path
from offtest.checks.flakiness import FlakinessRepeatSampler
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
from offtest.inventory.sbom import SBOMGenerator
from offtest.generator.test_generator import ConstrainedTestGenerator


def test_blocked_suite_yields_zero_flakiness(tmp_path: Path):
    """Verifies that a blocked check (e.g. pytest without --allow-scripts) produces 0 runs and 0 failed counts."""
    sampler = FlakinessRepeatSampler(tmp_path)
    blocked_check = CheckResult(
        tool_name="pytest",
        tool_version="8.0",
        check_name="Automated Unit Test Suite",
        check_type="unit_test",
        command="pytest",
        exit_code=1,
        duration_sec=0.0,
        status=CheckStatus.BLOCKED,
        skip_or_blocked_reason="Execution blocked: --allow-scripts flag was not specified",
    )
    report = sampler.analyze_results([blocked_check], enabled=True)
    assert report.quarantined_flaky_count == 0
    assert report.deterministic_failed_count == 0
    assert report.deterministic_passed_count == 0
    assert len(report.quarantined_tests) == 0


def test_synthesized_test_never_increases_coverage(tmp_path: Path):
    """Verifies that synthesized tests (without verified oracle execution) never increment workflow or feature coverage."""
    files = [
        FileRecord(
            path="app.py",
            size_bytes=100,
            sha256="abc",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Supported",
        )
    ]
    workflows = [
        WorkflowRecord(
            name="Checkout Workflow",
            description="Payment and checkout",
            linked_tests=["synthesized_test_branch_predicate_1.py"],
        )
    ]
    features = [
        FeatureRecord(
            name="Payment Feature",
            flag_key="FEATURE_PAYMENT_V2",
            file_path="app.py",
            linked_tests=["synthesized_test_branch_predicate_1.py"],
        )
    ]
    branches = [BranchRecord(name="main", is_current=True, is_base=True, status="assessed")]

    # Case A: Tests were blocked
    checks_blocked = [
        CheckResult(
            tool_name="pytest",
            tool_version="8.0",
            check_name="Unit Tests",
            check_type="unit_test",
            command="pytest",
            exit_code=1,
            duration_sec=0.0,
            status=CheckStatus.BLOCKED,
        )
    ]
    report_blocked = CoverageEvaluator.evaluate(
        files=files,
        workflows=workflows,
        features=features,
        branches=branches,
        selected_branches=["main"],
        check_results=checks_blocked,
    )
    dims_blocked = {d.name: d for d in report_blocked.dimensions}
    assert dims_blocked["Workflow Coverage"].numerator == 0
    assert dims_blocked["Workflow Coverage"].value_pct == 0.0
    assert dims_blocked["Feature Coverage"].numerator == 0
    assert dims_blocked["Feature Coverage"].value_pct == 0.0

    # Case B: Test suite executed, but only linked to synthesized test
    checks_passed = [
        CheckResult(
            tool_name="pytest",
            tool_version="8.0",
            check_name="Unit Tests",
            check_type="unit_test",
            command="pytest",
            exit_code=0,
            duration_sec=0.5,
            status=CheckStatus.PASSED,
        )
    ]
    report_passed = CoverageEvaluator.evaluate(
        files=files,
        workflows=workflows,
        features=features,
        branches=branches,
        selected_branches=["main"],
        check_results=checks_passed,
    )
    dims_passed = {d.name: d for d in report_passed.dimensions}
    # Synthesized tests must NOT count
    assert dims_passed["Workflow Coverage"].numerator == 0
    assert dims_passed["Workflow Coverage"].value_pct == 0.0
    assert dims_passed["Feature Coverage"].numerator == 0
    assert dims_passed["Feature Coverage"].value_pct == 0.0


def test_dimension_1_disposition_breakdown():
    """Verifies that Dimension 1 reports analyzed_count out of total discovered files with full disposition breakdown."""
    files = [
        FileRecord(path="a.py", size_bytes=10, sha256="1", disposition=FileDisposition.ANALYZED, disposition_reason="code"),
        FileRecord(path="b.py", size_bytes=10, sha256="2", disposition=FileDisposition.ANALYZED, disposition_reason="code"),
        FileRecord(path="c.bin", size_bytes=10, sha256="3", disposition=FileDisposition.BINARY, disposition_reason="asset"),
        FileRecord(path="d.log", size_bytes=10, sha256="4", disposition=FileDisposition.EXCLUDED, disposition_reason="excluded"),
    ]
    report = CoverageEvaluator.evaluate(
        files=files,
        workflows=[],
        features=[],
        branches=[BranchRecord(name="main", is_current=True, is_base=True, status="assessed")],
        selected_branches=["main"],
        check_results=[],
    )
    dims = {d.name: d for d in report.dimensions}
    dim1 = dims["Repository Inventory Disposition"]
    # Total = 4, analyzed = 2, excluded = 1, binary = 1
    assert dim1.numerator == 2
    assert dim1.denominator == 4
    assert dim1.value_pct is None
    assert "2 analyzed, 1 excluded, 0 generated, 1 binary" in dim1.explanation


def test_unmerged_non_base_branch_not_assessed():
    """Verifies that an unmerged local branch without diff/scan is not reported as assessed."""
    branches = [
        BranchRecord(name="main", is_current=True, is_base=True, status="assessed"),
        BranchRecord(name="feature/checkout", is_current=False, is_base=False, status="unassessed"),
    ]
    report = CoverageEvaluator.evaluate(
        files=[],
        workflows=[],
        features=[],
        branches=branches,
        selected_branches=["main", "feature/checkout"],
        check_results=[],
    )
    dims = {d.name: d for d in report.dimensions}
    dim7 = dims["Git Branch Assessment"]
    assert dim7.numerator == 1
    assert dim7.denominator == 2
    assert dim7.value_pct == 50.0
    assert "feature/checkout" in dim7.explanation


def test_unpinned_dependencies_appear_in_sbom(tmp_path: Path):
    """Verifies that unpinned dependencies (uvicorn, pydantic) are captured in SBOM with is_approximate_range=True."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("fastapi==0.110.0\nuvicorn\npydantic\n", encoding="utf-8")

    files = [
        FileRecord(
            path="requirements.txt",
            size_bytes=len(req_file.read_bytes()),
            sha256="req123",
            language="Requirements",
            category="config",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Config",
        )
    ]

    generator = SBOMGenerator(tmp_path, files)
    sbom = generator.generate()

    assert sbom.total_dependencies == 3
    comp_map = {c.name: c for c in sbom.components}

    assert "fastapi" in comp_map
    assert comp_map["fastapi"].version == "0.110.0"
    assert comp_map["fastapi"].is_approximate_range is False

    assert "uvicorn" in comp_map
    assert comp_map["uvicorn"].version == "unspecified"
    assert comp_map["uvicorn"].is_approximate_range is True

    assert "pydantic" in comp_map
    assert comp_map["pydantic"].version == "unspecified"
    assert comp_map["pydantic"].is_approximate_range is True


def test_windows_git_hardening_prevents_fsmonitor_and_hooks(tmp_path: Path):
    """Verifies that GitManager suppresses malicious core.fsmonitor and hooks on Windows."""
    import subprocess
    from offtest.intake.git_manager import GitManager

    # Initialize a test git repository
    res = subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
    if res.returncode != 0:
        return

    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), capture_output=True)
    (tmp_path / "init.txt").write_text("hello", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), capture_output=True)

    marker = tmp_path / "attack_marker.txt"
    attack_script = tmp_path / "malicious.bat"
    attack_script.write_text(f'echo hacked > "{marker}"\n', encoding="utf-8")

    # Plant malicious fsmonitor in .git/config
    git_cfg = tmp_path / ".git" / "config"
    with open(git_cfg, "a", encoding="utf-8") as f:
        attack_path_fwd = str(attack_script).replace("\\", "/")
        f.write(f'\n[core]\n    fsmonitor = "{attack_path_fwd}"\n')

    # Plant malicious hook in .git/hooks/
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_file = hooks_dir / "post-checkout"
    marker_fwd = str(marker).replace("\\", "/")
    hook_file.write_text(f'#!/bin/sh\necho hacked > "{marker_fwd}"\n', encoding="utf-8")

    # Test GitManager with hardened flags
    gm = GitManager(str(tmp_path))
    gm._run_git(["status"])
    assert not marker.exists(), "Hardened GitManager unexpectedly executed malicious core.fsmonitor!"

    gm._run_git(["checkout", "-b", "hardened_branch"])
    assert not marker.exists(), "Hardened GitManager unexpectedly executed malicious .git/hooks/post-checkout!"


def test_target_directory_immutability_before_and_after_assessment(tmp_path: Path):
    """Verifies that running an assessment never mutates the target codebase (bit-for-bit identical)."""
    import hashlib
    import os
    from offtest.orchestrator import AssessmentOrchestrator

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (repo_dir / "requirements.txt").write_text("pytest==8.0.0\n", encoding="utf-8")
    tests_dir = repo_dir / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_simple.py").write_text("def test_ok(): assert 1 == 1\n", encoding="utf-8")

    def snapshot_dir(d: Path):
        snap = {}
        for root, _, files in os.walk(d):
            for f in files:
                p = Path(root) / f
                rel = p.relative_to(d).as_posix()
                snap[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
        return snap

    snap_before = snapshot_dir(repo_dir)

    # 1. Run without scripts
    orch1 = AssessmentOrchestrator(str(repo_dir), allow_scripts=False, output_dir=str(tmp_path / "out1"))
    orch1.run()
    snap_after1 = snapshot_dir(repo_dir)
    assert snap_before == snap_after1, f"Target directory was mutated during allow_scripts=False run: {set(snap_after1.keys()) ^ set(snap_before.keys())}"

    # 2. Run with scripts approved
    orch2 = AssessmentOrchestrator(str(repo_dir), allow_scripts=True, output_dir=str(tmp_path / "out2"))
    orch2.run()
    snap_after2 = snapshot_dir(repo_dir)
    assert snap_before == snap_after2, f"Target directory was mutated during allow_scripts=True run: {set(snap_after2.keys()) ^ set(snap_before.keys())}"


def test_aws_example_key_downgraded_to_informational(tmp_path: Path):
    """Verifies that documented AWS sample keys (e.g. AKIAIOSFODNN7EXAMPLE) are downgraded to Informational."""
    from offtest.checks.static_checks import OfflineStaticChecker
    from offtest.core.models import FileDisposition, FileRecord, Severity

    app_file = tmp_path / "sample.py"
    app_file.write_text('DOC_KEY = "AKIAIOSFODNN7EXAMPLE"\nREAL_LOOKING_KEY = "AKIA1234567890ABCDEF"\n', encoding="utf-8")

    files = [
        FileRecord(
            path="sample.py",
            size_bytes=len(app_file.read_bytes()),
            sha256="s123",
            language="Python",
            category="source",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Source",
        )
    ]

    checker = OfflineStaticChecker(tmp_path, files)
    findings = checker.run_all()

    example_findings = [f for f in findings if "Example Key" in f.title]
    real_findings = [f for f in findings if "AWS Access Key ID" in f.title]

    assert len(example_findings) == 1
    assert example_findings[0].severity == Severity.INFORMATIONAL
    assert "Example Key" in example_findings[0].title

    assert len(real_findings) == 1
    assert real_findings[0].severity == Severity.CRITICAL


def test_sandbox_home_redirection_shields_ssh_and_aws(tmp_path: Path):
    """Verifies that IsolatedRunner redirects USERPROFILE/HOME to a sandbox directory to shield host secrets."""
    import os
    import sys
    import tempfile
    from offtest.checks.isolated_runner import IsolatedRunner

    runner = IsolatedRunner(tmp_path)
    # Check what child sees for HOME and USERPROFILE
    probe = [
        sys.executable, "-c",
        "import os, sys; print('HOME=' + (os.environ.get('USERPROFILE') or os.environ.get('HOME', '')))"
    ]
    code, stdout, stderr, dur = runner.run(probe)
    assert code == 0
    assert "HOME=" in stdout
    assert str(runner.sandbox_home) in stdout
    assert str(runner.sandbox_home) != str(Path.home())


