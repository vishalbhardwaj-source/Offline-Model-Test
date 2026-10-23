import json
import tempfile
import zipfile
from pathlib import Path
from offtest.checks.isolated_runner import IsolatedRunner
from offtest.core.config import OfflineConfig
from offtest.intake.intake import RepositoryIntake, SecurityError
from offtest.orchestrator import AssessmentOrchestrator


def test_zero_credential_leak_in_reports_and_evidence():
    """Verifies that hardcoded secrets never leak into generated reports or evidence JSON."""
    with tempfile.TemporaryDirectory() as fixture_dir, tempfile.TemporaryDirectory() as runs_dir:
        repo_path = Path(fixture_dir)
        raw_secret_key = "sk-proj-SUPERSECRETKEY1234567890abcdef"
        raw_db_password = "super_classified_db_pass_987"
        raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.classified_signature_bytes_123"

        config_file = repo_path / "config.py"
        config_file.write_text(
            f"""
API_KEY = "{raw_secret_key}"
DB_URI = "postgres://admin:{raw_db_password}@db.internal:5432/main"
TOKEN = "{raw_jwt}"
""",
            encoding="utf-8"
        )

        orchestrator = AssessmentOrchestrator(
            repo_path_or_archive=str(repo_path),
            base_branch="main",
            allow_scripts=False,
            output_dir=runs_dir,
            generate_tests=False,
        )

        context, det_path, iss_path, sarif_path = orchestrator.run()

        # 1. Inspect Detailed Report
        det_text = det_path.read_text(encoding="utf-8")
        assert raw_secret_key not in det_text
        assert raw_db_password not in det_text
        assert raw_jwt not in det_text
        assert "[REDACTED_SECRET]" in det_text

        # 2. Inspect Issue-Focused Report
        iss_text = iss_path.read_text(encoding="utf-8")
        assert raw_secret_key not in iss_text
        assert raw_db_password not in iss_text
        assert raw_jwt not in iss_text
        assert "[REDACTED_SECRET]" in iss_text

        # 3. Inspect Evidence Store JSON
        evidence_file = det_path.parent / "evidence.json"
        assert evidence_file.exists()
        evidence_text = evidence_file.read_text(encoding="utf-8")
        assert raw_secret_key not in evidence_text
        assert raw_db_password not in evidence_text
        assert raw_jwt not in evidence_text
        assert "[REDACTED_SECRET]" in evidence_text


def test_network_isolation_and_telemetry_blocking():
    """Verifies that IsolatedRunner injects offline proxy nullification and telemetry opt-out flags."""
    runner = IsolatedRunner(Path("."))
    
    # Check that environment overrides are present
    overrides = OfflineConfig.OFFLINE_ENV_OVERRIDES
    assert overrides["PIP_NO_INDEX"] == "1"
    assert overrides["npm_config_offline"] == "true"
    assert overrides["HTTP_PROXY"] == "http://127.0.0.1:0"
    assert overrides["HTTPS_PROXY"] == "http://127.0.0.1:0"
    assert overrides["NO_PROXY"] == ""  # Ensure no bypass of the proxy
    assert overrides["DO_NOT_TRACK"] == "1"
    assert overrides["NEXT_TELEMETRY_DISABLED"] == "1"


def test_archive_path_traversal_leak_prevention(tmp_path: Path):
    """Verifies that malicious zip files attempting path traversal are rejected before extraction."""
    malicious_zip = tmp_path / "exploit.zip"
    with zipfile.ZipFile(malicious_zip, "w") as z:
        # Attempt to write outside target directory
        z.writestr("../../../../../../../../../../../../../tmp/leak.txt", "stolen_data")

    try:
        RepositoryIntake.prepare_target(str(malicious_zip))
        assert False, "Should have raised SecurityError on Zip Slip attempt"
    except SecurityError as se:
        assert "Malicious archive member detected" in str(se)
