import subprocess
import tempfile
from pathlib import Path
from offtest.core.evidence_store import EvidenceStore
from offtest.orchestrator import AssessmentOrchestrator
from offtest.reports.detailed import DetailedReportGenerator
from offtest.reports.issue_focused import IssueFocusedReportGenerator


def create_fixture_repo(target_dir: Path):
    # Initialize a local git repository
    subprocess.run(["git", "init"], cwd=str(target_dir), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@offline.local"], cwd=str(target_dir), capture_output=True)
    subprocess.run(["git", "config", "user.name", "Offline Tester"], cwd=str(target_dir), capture_output=True)

    # Server file with FastAPI routes
    server_py = target_dir / "server.py"
    server_py.write_text(
        """
import os
from fastapi import FastAPI

app = FastAPI()
DEBUG = True

@app.get("/")
def read_root():
    return {"status": "online"}

@app.get("/api/v1/auth/login")
def login_route():
    return {"token": "jwt"}

if os.getenv("FEATURE_BETA_V2") == "1":
    print("Beta feature enabled")
""",
        encoding="utf-8",
    )

    # Requirements
    req_file = target_dir / "requirements.txt"
    req_file.write_text("fastapi==0.100.0\nuvicorn\n", encoding="utf-8")

    # Tests
    test_file = target_dir / "test_app.py"
    test_file.write_text(
        """
def test_sample():
    assert True
""",
        encoding="utf-8",
    )

    # Git commit
    subprocess.run(["git", "add", "."], cwd=str(target_dir), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(target_dir), capture_output=True, check=True)


def test_end_to_end_assessment():
    with tempfile.TemporaryDirectory() as fixture_dir, tempfile.TemporaryDirectory() as runs_dir:
        fix_path = Path(fixture_dir)
        create_fixture_repo(fix_path)

        orchestrator = AssessmentOrchestrator(
            repo_path_or_archive=str(fix_path),
            base_branch="main",
            allow_scripts=False,
            output_dir=runs_dir,
        )

        context, det_path, iss_path, sarif_path = orchestrator.run()

        # Check outputs
        assert det_path.exists()
        assert iss_path.exists()
        assert sarif_path.exists()
        wf_path = Path(det_path).parent / "REPORT_3_WORKFLOWS.md"
        assert wf_path.exists()

        det_content = det_path.read_text(encoding="utf-8")
        iss_content = iss_path.read_text(encoding="utf-8")
        wf_content = wf_path.read_text(encoding="utf-8")

        # Verify Report 3 structure
        assert "Application Workflow & Journey Report" in wf_content
        assert "Executive Workflow Summary" in wf_content

        # Verify Report 1 structure
        assert "## 1. Executive Summary" in det_content
        assert "## 2. Repository Inventory" in det_content
        assert "## 3. Application Map & Structure" in det_content
        assert "## 4. Branch and Change Analysis" in det_content
        assert "## 5. Checks & Test Execution Results" in det_content
        assert "## 6. Discovered Findings & Vulnerabilities" in det_content
        assert "## 7. Coverage Assessment & Gaps" in det_content
        assert "## 8. Reproducibility Details" in det_content
        assert "## 9. Explicit Limitations" in det_content

        # Verify Report 2 structure
        assert "Actionable Issue-Focused Assessment Report" in iss_content
        assert "Blocked & Unverified Checks" in iss_content
        assert "Key Coverage Gaps" in iss_content

        # Verify script safety guard blocked tests when allow_scripts=False
        assert any(c.status.value == "Blocked" for c in context.check_results)

        # Verify Reproduction from Evidence Store (Acceptance criterion 9)
        store = EvidenceStore(base_dir=runs_dir)
        loaded = store.load_run(context.run_id)
        assert loaded.run_id == context.run_id

        repro_det = DetailedReportGenerator(loaded).generate_markdown()
        assert repro_det == det_content
