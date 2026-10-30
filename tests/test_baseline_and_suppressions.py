import json
import tempfile
from pathlib import Path
from click.testing import CliRunner

from offtest.cli import assess
from offtest.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    RunContext,
    Severity,
)
from offtest.reports.detailed import DetailedReportGenerator
from offtest.reports.sarif import SARIFReportGenerator


def _make_context(findings):
    return RunContext(
        run_id="run-test-01",
        repo_path=".",
        repo_name="test-repo",
        platform="Windows",
        python_version="3.12.0",
        findings=findings,
    )


def test_sarif_baseline_state_classification():
    # 1. Create a prior baseline SARIF file
    prior_sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "offtest"}},
                "results": [
                    {
                        "ruleId": "OT-SEC-001",
                        "partialFingerprints": {
                            "logicalLocationKey": "src/api/auth.py:OT-SEC-001:login"
                        },
                        "baselineState": "new",
                    }
                ],
            }
        ],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        baseline_file = Path(tmpdir) / "baseline.sarif"
        baseline_file.write_text(json.dumps(prior_sarif), encoding="utf-8")

        # Create two findings: one matching baseline, one new
        f1 = Finding(
            id="F-001",
            title="Hardcoded JWT Secret",
            impact="Unauthorized tokens can be forged",
            evidence="secret = 'mysecret'",
            suggested_action="Use env var",
            rule_id="OT-SEC-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            file_path="src/api/auth.py",
            line_number=20,
            partial_fingerprints={"logicalLocationKey": "src/api/auth.py:OT-SEC-001:login"},
        )
        f2 = Finding(
            id="F-002",
            title="SQL Injection Vulnerability",
            impact="Database compromise",
            evidence="cursor.execute('SELECT * FROM ' + table)",
            suggested_action="Use parameterized queries",
            rule_id="OT-SEC-002",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file_path="src/api/data.py",
            line_number=45,
            partial_fingerprints={"logicalLocationKey": "src/api/data.py:OT-SEC-002:query"},
        )

        ctx = _make_context([f1, f2])
        sarif_gen = SARIFReportGenerator(ctx, baseline_path=baseline_file)
        sarif_data = sarif_gen.generate_sarif()

        results = sarif_data["runs"][0]["results"]
        assert len(results) == 2

        res1 = next(r for r in results if r["ruleId"] == "OT-SEC-001")
        assert res1["baselineState"] == "unchanged"
        assert f1.baseline_state == "unchanged"

        res2 = next(r for r in results if r["ruleId"] == "OT-SEC-002")
        assert res2["baselineState"] == "new"
        assert f2.baseline_state == "new"


def test_detailed_report_suppression_and_baseline_section():
    f_active = Finding(
        id="F-003",
        title="Unverified SSL Context",
        impact="MitM risk",
        evidence="ssl.create_default_context()",
        suggested_action="Enable verification",
        rule_id="OT-SEC-003",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        suppressed=True,
        suppression_reason="Intentional for internal test mock (expires=2099-12-31)",
        file_path="tests/mock_ssl.py",
        line_number=12,
    )
    f_expired = Finding(
        id="F-004",
        title="Hardcoded Password",
        impact="Credential compromise",
        evidence="password = 'admin'",
        suggested_action="Move to vault",
        rule_id="OT-SEC-004",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        suppressed=False,
        suppression_reason="Suppression expired on 2024-01-01",
        file_path="config/db.py",
        line_number=8,
        baseline_state="unchanged",
    )

    ctx = _make_context([f_active, f_expired])
    gen = DetailedReportGenerator(ctx)
    md = gen.generate_markdown()

    assert "## 10. Audit, Suppressions & Baseline Review" in md
    assert "Expired Inline Suppression(s) Detected!" in md
    assert "Suppression expired on 2024-01-01" in md
    assert "Active Suppressed Findings" in md
    assert "Intentional for internal test mock" in md
    assert "Baseline State Review" in md
    assert "unchanged / grandfathered finding(s)" in md


def test_cli_baseline_suppresses_ci_gate_failure():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir) / "test_repo"
        repo_dir.mkdir()
        # Vulnerable file
        vuln_py = repo_dir / "vuln.py"
        vuln_py.write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")

        # First run to produce SARIF baseline
        out_baseline = Path(tmpdir) / "baseline.sarif"
        res1 = runner.invoke(assess, [str(repo_dir), "--sarif-out", str(out_baseline)])
        assert res1.exit_code == 1  # Fails CI gate because of os.system High severity finding
        assert out_baseline.exists()

        # Second run passing --baseline pointing to the generated SARIF
        res2 = runner.invoke(assess, [str(repo_dir), "--baseline", str(out_baseline)])
        # The unchanged finding should now be grandfathered and not fail the CI gate!
        assert res2.exit_code == 0
        assert "Baseline active" in res2.output
        assert "grandfathered; excluded from blocking CI gate" in res2.output
