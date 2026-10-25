import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
import pytest
from offtest.checks.isolated_runner import _audit_mounts
from offtest.checks.static_checks import OfflineStaticChecker
from offtest.core.evidence_store import EvidenceStore, get_evidence_signing_key
from offtest.core.models import (
    Confidence,
    EvidenceStatus,
    FileDisposition,
    FileRecord,
    Finding,
    RunContext,
    Severity,
)
from offtest.core.safe_fs import safe_walk
from offtest.intake.safety import redact_data_structure, redact_sensitive_data


def test_pre_serialization_redaction_handles_json_escapes():
    """
    Verifies Round 9 #2: String values on models/dictionaries are redacted BEFORE
    serialization, correctly scrubbing secrets that contain JSON escape characters (\\n, \\", \\u00XX)
    without corrupting the resulting JSON document.
    """
    nested_data = {
        "regular_text": "hello world",
        "secret_with_newline": "AKIA1234567890ABCDEF\nnext_line_content",
        "secret_with_quotes": 'Authorization: "AKIA1234567890ABCDEF"',
        "secret_in_list": [
            "benign_item",
            "AKIA1234567890ABCDEF",
        ],
        "nested_dict": {
            "token": "AKIA1234567890ABCDEF",
        },
    }

    sanitized = redact_data_structure(nested_data)
    assert "AKIA1234567890ABCDEF" not in str(sanitized)
    assert sanitized["nested_dict"]["token"] == "[REDACTED_SECRET]"
    assert "[REDACTED_SECRET]" in sanitized["secret_with_newline"]

    # Verify JSON serialization does not break
    serialized = json.dumps(sanitized)
    parsed = json.loads(serialized)
    assert parsed["nested_dict"]["token"] == "[REDACTED_SECRET]"


def test_evidence_hmac_tamper_evidence(tmp_path: Path):
    """
    Verifies Round 9 #6: EvidenceStore creates both evidence.json.sha256 and evidence.json.hmac.
    """
    store = EvidenceStore(base_dir=str(tmp_path))
    ctx = RunContext.model_construct(
        run_id="run_test_hmac_123",
        findings=[],
        check_results=[],
        workflows=[],
        routes=[],
        apis=[],
        features=[],
        integrations=[],
        branches=[],
        branch_diffs=[],
    )

    evidence_file = store.save_run(ctx)
    assert evidence_file.is_file()

    sha_file = tmp_path / "run_test_hmac_123" / "evidence.json.sha256"
    hmac_file = tmp_path / "run_test_hmac_123" / "evidence.json.hmac"

    assert sha_file.is_file()
    assert hmac_file.is_file()

    # Verify HMAC content
    final_bytes = evidence_file.read_bytes()
    expected_key = get_evidence_signing_key()
    expected_hmac = hmac.new(expected_key, final_bytes, hashlib.sha256).hexdigest()

    hmac_content = hmac_file.read_text(encoding="utf-8")
    assert expected_hmac in hmac_content


def test_mount_audit_rejects_unauthorized_writable_tmpfs(monkeypatch, tmp_path: Path):
    """
    Verifies Round 9 Gate Audit: Loose tmpfs mounts (e.g. writable tmpfs mounted over /etc)
    are strictly rejected. Approved scratch paths (/tmp, /dev, /dev/shm, /run) and container runtime
    files (/etc/hosts, /etc/resolv.conf) are properly validated.
    """
    import offtest.checks.isolated_runner as iso_mod

    # 1. Standard Docker hardened container layout with /dev tmpfs should PASS
    docker_hardened_mountinfo = """36 35 0:33 / / ro,relatime - overlay overlay ro,lowerdir=...
37 36 0:34 / /repo ro,relatime - ext4 /dev/sdb ro
38 36 0:35 / /out rw,relatime - ext4 /dev/sdc rw
39 36 0:36 / /dev rw,nosuid,size=65536k,mode=755 - tmpfs tmpfs rw
40 36 0:37 / /dev/shm rw,nosuid,nodev,noexec - tmpfs tmpfs rw
41 36 0:38 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw
42 36 0:39 / /dev/mqueue rw,nosuid,nodev,noexec - mqueue mqueue rw
43 36 0:40 / /etc/hosts ro,relatime - ext4 /dev/sdb ro
44 36 0:41 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw
"""
    m_valid_file = tmp_path / "mountinfo_docker_hardened"
    m_valid_file.write_text(docker_hardened_mountinfo, encoding="utf-8")

    monkeypatch.setattr(iso_mod, "Path", lambda p: m_valid_file if str(p) == "/proc/self/mountinfo" else Path(p))
    ok, diag = _audit_mounts(Path("/repo"))
    assert ok is True, f"Failed on standard Docker mount layout: {diag}"

    # 2. Writable tmpfs mounted over /etc (unauthorized writable mount) must FAIL
    hostile_mountinfo = """36 35 0:33 / / ro,relatime - overlay overlay ro,lowerdir=...
37 36 0:34 / /repo ro,relatime - ext4 /dev/sdb ro
38 36 0:35 / /out rw,relatime - ext4 /dev/sdc rw
39 36 0:36 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw
40 36 0:37 / /etc rw,nosuid,nodev - tmpfs tmpfs rw
"""
    m_file = tmp_path / "mountinfo_hostile_tmpfs"
    m_file.write_text(hostile_mountinfo, encoding="utf-8")

    monkeypatch.setattr(iso_mod, "Path", lambda p: m_file if str(p) == "/proc/self/mountinfo" else Path(p))
    ok, diag = _audit_mounts(Path("/repo"))
    assert ok is False
    assert "Unauthorized writable tmpfs mount detected at '/etc'" in diag


def test_remote_index_in_requirements_and_constraints(tmp_path: Path):
    """
    Verifies Round 9 #4: Static checks detect remote package indexes (--index-url, --find-links)
    in requirements.txt and constraints.txt.
    """
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("--index-url https://pypi.org/simple\nflask==2.3.2\n", encoding="utf-8")

    const_file = tmp_path / "constraints.txt"
    const_file.write_text("--find-links https://wheels.example.com\nrequests==2.31.0\n", encoding="utf-8")

    files = [
        FileRecord(
            path="requirements.txt",
            size_bytes=len(req_file.read_bytes()),
            sha256="hash_req",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Config",
        ),
        FileRecord(
            path="constraints.txt",
            size_bytes=len(const_file.read_bytes()),
            sha256="hash_const",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Config",
        ),
    ]

    checker = OfflineStaticChecker(tmp_path, files)
    findings = checker.run_all()

    remote_index_findings = [f for f in findings if "Remote Package Index" in f.title]
    assert len(remote_index_findings) == 2
    assert any("requirements.txt" in f.file_path for f in remote_index_findings)
    assert any("constraints.txt" in f.file_path for f in remote_index_findings)
    assert all(f.severity == Severity.HIGH for f in remote_index_findings)


def test_gitmodules_and_cargo_and_registry_detectors(tmp_path: Path):
    """
    Verifies Round 9 #4: Scanners detect remote references in .gitmodules, Cargo.toml,
    and external registries in .npmrc / pip.conf.
    """
    gitmod = tmp_path / ".gitmodules"
    gitmod.write_text('[submodule "ext"]\n  path = ext\n  url = https://github.com/remote/repo.git\n', encoding="utf-8")

    cargo = tmp_path / "Cargo.toml"
    cargo.write_text('[dependencies]\nmy_crate = { git = "https://github.com/rust/crate.git" }\nlocal_esc = { path = "../../escaped" }\n', encoding="utf-8")

    npmrc = tmp_path / ".npmrc"
    npmrc.write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")

    files = [
        FileRecord(path=".gitmodules", size_bytes=100, sha256="h1", disposition=FileDisposition.ANALYZED, disposition_reason="Config"),
        FileRecord(path="Cargo.toml", size_bytes=100, sha256="h2", disposition=FileDisposition.ANALYZED, disposition_reason="Config"),
        FileRecord(path=".npmrc", size_bytes=100, sha256="h3", disposition=FileDisposition.ANALYZED, disposition_reason="Config"),
    ]

    checker = OfflineStaticChecker(tmp_path, files)
    findings = checker.run_all()

    titles = [f.title for f in findings]
    assert any("Remote Submodule URL in .gitmodules" in t for t in titles)
    assert any("Remote Git Dependency in Cargo.toml" in t for t in titles)
    assert any("Escaping Path Dependency in Cargo.toml" in t for t in titles)
    assert any("External Package Registry Configured in .npmrc" in t for t in titles)


def test_excessive_requirements_recursion_depth(tmp_path: Path):
    """
    Verifies Round 9 #4: Excessive recursion in nested -r requirements (depth > 5) is detected and blocked.
    """
    # Create chain of 7 nested requirements
    for i in range(1, 8):
        next_file = f"req_{i+1}.txt" if i < 7 else "requests==2.31.0\n"
        content = f"-r {next_file}\n" if i < 7 else next_file
        (tmp_path / f"req_{i}.txt").write_text(content, encoding="utf-8")

    files = [
        FileRecord(path="req_1.txt", size_bytes=50, sha256="h_rec", disposition=FileDisposition.ANALYZED, disposition_reason="Config")
    ]

    checker = OfflineStaticChecker(tmp_path, files)
    findings = checker.run_all()

    recursion_findings = [f for f in findings if "Excessive Recursion Depth" in f.title]
    assert len(recursion_findings) == 1
    assert recursion_findings[0].severity == Severity.HIGH
