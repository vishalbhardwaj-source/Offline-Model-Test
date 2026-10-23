import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from offtest.checks.isolated_runner import IsolatedRunner
from offtest.core.config import OfflineConfig
from offtest.core.models import APIRecord, EvidenceStatus, FileDisposition, FileRecord, RouteRecord
from offtest.discovery.rbac_and_schema import RBACAndSchemaExtractor
from offtest.intake.git_manager import GitManager
from offtest.intake.intake import RepositoryIntake, SecurityError


def test_adversarial_tar_symlink_escape(tmp_path: Path):
    """Verifies that a tar archive containing a symlink pointing outside the sandbox is rejected."""
    tar_path = tmp_path / "symlink_escape.tar.gz"
    
    with tarfile.open(tar_path, "w:gz") as t:
        # Create a malicious symlink pointing to root / parent
        symlink_member = tarfile.TarInfo(name="escape_link")
        symlink_member.type = tarfile.SYMTYPE
        symlink_member.linkname = "../../outside_target"
        t.addfile(symlink_member)

    try:
        RepositoryIntake.prepare_target(str(tar_path))
        assert False, "Should have raised SecurityError for symlink escape"
    except SecurityError as se:
        assert "symlink" in str(se).lower() or "outside sandbox" in str(se).lower()


def test_adversarial_decompression_bomb(tmp_path: Path, monkeypatch):
    """Verifies that archives exceeding decompression safety caps are rejected."""
    # Set a small test cap to verify threshold enforcement without large memory allocation
    monkeypatch.setattr(OfflineConfig, "ARCHIVE_MAX_FILE_SIZE_BYTES", 1000)
    
    bomb_zip = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb_zip, "w") as z:
        z.writestr("large_file.bin", b"A" * 2000)

    try:
        RepositoryIntake.prepare_target(str(bomb_zip))
        assert False, "Should have raised SecurityError on decompression bomb"
    except SecurityError as se:
        assert "exceeds" in str(se).lower()


def test_adversarial_malicious_git_config(tmp_path: Path):
    """Verifies that running GitManager on a repo with malicious .git/config does not execute code."""
    repo_dir = tmp_path / "malicious_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    
    # Init clean git repo
    subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), capture_output=True)
    
    # Inject malicious .git/config commands
    git_config = repo_dir / ".git" / "config"
    with open(git_config, "a", encoding="utf-8") as f:
        f.write("""
[core]
    fsmonitor = "echo MALICIOUS_FSMONITOR_EXECUTED"
    pager = "echo MALICIOUS_PAGER_EXECUTED"
[diff "exploit"]
    textconv = "echo MALICIOUS_TEXTCONV_EXECUTED"
""")

    gm = GitManager(str(repo_dir))
    code, stdout, stderr = gm._run_git(["status"])
    
    # Hardened git invocation must not execute fsmonitor or pager
    assert "MALICIOUS_FSMONITOR_EXECUTED" not in stdout
    assert "MALICIOUS_PAGER_EXECUTED" not in stdout
    assert "MALICIOUS_TEXTCONV_EXECUTED" not in stdout


def test_adversarial_host_environment_scrubbing(tmp_path: Path):
    """Verifies that IsolatedRunner scrubs host secrets from the child process os.environ."""
    # Set a mock host secret in parent environment
    os.environ["AWS_SECRET_ACCESS_KEY"] = "super_classified_host_aws_key_123"
    os.environ["GITHUB_TOKEN"] = "ghp_host_secret_token_456"

    runner = IsolatedRunner(tmp_path, timeout_sec=5)
    
    # Python script printing all environment variable keys
    probe_script = [
        sys.executable,
        "-c",
        "import os; print(','.join(os.environ.keys()))",
    ]
    code, out, err, dur = runner.run(probe_script)

    env_keys = out.strip().split(",")
    assert "AWS_SECRET_ACCESS_KEY" not in env_keys
    assert "GITHUB_TOKEN" not in env_keys
    assert "HTTP_PROXY" in env_keys  # Offline override must be present
    assert "GOSUMDB" in env_keys     # Go checksum database override must be present


def test_adversarial_unguarded_route_is_unverified(tmp_path: Path):
    """Verifies that routes without explicit local guards are marked UNVERIFIED, not Anonymous."""
    app_file = tmp_path / "routes.py"
    app_file.write_text("""
@app.get("/internal/financial/records")
def financial_records():
    return {"secret": "data"}
""", encoding="utf-8")

    files = [
        FileRecord(
            path="routes.py",
            size_bytes=len(app_file.read_bytes()),
            sha256="abc",
            language="Python",
            category="source",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Source",
        )
    ]
    routes = [
        RouteRecord(path="/internal/financial/records", method="GET", file_path="routes.py", line_number=2)
    ]

    extractor = RBACAndSchemaExtractor(tmp_path, files, routes, [])
    matrix = extractor.extract_rbac()

    perm = matrix.permissions[0]
    assert perm.status == EvidenceStatus.UNVERIFIED
    assert "Unverified (No local guard)" in perm.required_roles
    assert "Anonymous" not in perm.required_roles
