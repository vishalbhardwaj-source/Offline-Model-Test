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


def test_raw_socket_egress_blocked_in_child_sandbox():
    """
    Verifies that raw TCP, UDP, and DNS outbound attempts are strictly blocked
    inside the IsolatedRunner child environment, while loopback remains allowed.
    """
    import sys
    runner = IsolatedRunner(Path("."), timeout_sec=5)

    # 1. Raw TCP connection to remote IP must fail with PermissionError / non-zero code
    tcp_cmd = [sys.executable, "-c", "import socket; s = socket.create_connection(('1.1.1.1', 53), timeout=2); s.close()"]
    c_tcp, out_tcp, err_tcp, _ = runner.run(tcp_cmd)
    assert c_tcp != 0
    assert "AIR-GAP ENFORCEMENT" in err_tcp or "blocked" in err_tcp.lower()

    # 2. Raw UDP transmission to remote IP must fail with PermissionError / non-zero code
    udp_cmd = [sys.executable, "-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'data', ('8.8.8.8', 53)); s.close()"]
    c_udp, out_udp, err_udp, _ = runner.run(udp_cmd)
    assert c_udp != 0
    assert "AIR-GAP ENFORCEMENT" in err_udp or "blocked" in err_udp.lower()

    # 3. External DNS resolution must fail with socket.gaierror / non-zero code
    dns_cmd = [sys.executable, "-c", "import socket; socket.getaddrinfo('example.com', 80)"]
    c_dns, out_dns, err_dns, _ = runner.run(dns_cmd)
    assert c_dns != 0
    assert "AIR-GAP ENFORCEMENT" in err_dns or "blocked" in err_dns.lower()

    # 4. Local loopback socket must succeed (required for local mock / test servers)
    loopback_code = (
        "import socket\n"
        "s = socket.socket()\n"
        "s.bind(('127.0.0.1', 0))\n"
        "s.listen(1)\n"
        "port = s.getsockname()[1]\n"
        "c = socket.socket()\n"
        "c.connect(('127.0.0.1', port))\n"
        "c.close()\n"
        "s.close()\n"
        "print('LOOPBACK_SUCCESS')\n"
    )
    loop_cmd = [sys.executable, "-c", loopback_code]
    c_loop, out_loop, err_loop, _ = runner.run(loop_cmd)
    assert c_loop == 0
    assert "LOOPBACK_SUCCESS" in out_loop


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


def test_allow_scripts_safety_gate_refusal_on_bare_host(tmp_path: Path):
    """Verifies that --allow-scripts refuses to run on bare host unless --accept-no-kernel-isolation is provided."""
    dummy_repo = tmp_path / "dummy_repo"
    dummy_repo.mkdir()
    (dummy_repo / "server.py").write_text("x = 1\n", encoding="utf-8")

    # 1. Running with allow_scripts=True on bare host without acceptance must raise SecurityError
    orchestrator = AssessmentOrchestrator(
        repo_path_or_archive=str(dummy_repo),
        allow_scripts=True,
        accept_no_kernel_isolation=False,
    )
    try:
        orchestrator.run()
        assert False, "Should have raised SecurityError on bare host --allow-scripts without acceptance"
    except SecurityError as se:
        assert "Execution Refused" in str(se)
        assert "--accept-no-kernel-isolation" in str(se)

    # 2. Running with accept_no_kernel_isolation=True must proceed
    orchestrator_approved = AssessmentOrchestrator(
        repo_path_or_archive=str(dummy_repo),
        allow_scripts=True,
        accept_no_kernel_isolation=True,
        generate_tests=False,
    )
    context, _, _, _ = orchestrator_approved.run()
    assert context.allow_scripts is True
    assert context.accept_no_kernel_isolation is True


def test_hmac_secret_fingerprinting():
    """Verifies that secret fingerprints use keyed HMAC-SHA256 and resist rainbow-table attacks."""
    from offtest.intake.safety import compute_secret_fingerprint

    secret = "secret_db_pass_123"
    # Deterministic with same installation/salt
    fp1 = compute_secret_fingerprint(secret, salt=b"key_a")
    fp2 = compute_secret_fingerprint(secret, salt=b"key_a")
    assert fp1 == fp2

    # Different salt/key yields different hash (prevents global rainbow-table attacks)
    fp3 = compute_secret_fingerprint(secret, salt=b"key_b")
    assert fp1 != fp3


def test_pathological_ast_nesting_handling(tmp_path: Path):
    """Verifies that deeply nested hostile syntax does not crash the static analyzer."""
    from offtest.checks.static_checks import OfflineStaticChecker
    from offtest.core.models import FileRecord, FileDisposition

    deep_nesting = "x = " + ("(" * 400) + "1" + (")" * 400)
    test_file = tmp_path / "nested.py"
    test_file.write_text(deep_nesting, encoding="utf-8")

    file_rec = FileRecord(
        path="nested.py",
        size_bytes=len(deep_nesting),
        language="Python",
        sha256="dummy_sha",
        disposition=FileDisposition.ANALYZED,
        disposition_reason="Source code eligible for analysis",
    )
    checker = OfflineStaticChecker(tmp_path, [file_rec])
    # Must complete without crashing the runner process
    findings = checker.run_all()
    assert isinstance(findings, list)


import pytest


@pytest.mark.xfail(strict=True, reason="Documented bare-metal limitation: OS kernel-level container (--network none) required to block unpatched python -I -S interpreter")
def test_unpatched_interpreter_bypass_documented_gap():
    """
    Documents known bare-metal boundary: an unpatched interpreter spawned with -I -S
    bypasses sitecustomize and can reach the host network unless in an OS container.
    """
    import sys
    runner = IsolatedRunner(Path("."), timeout_sec=3)
    cmd = [sys.executable, "-I", "-S", "-c", "import socket; s = socket.create_connection(('1.1.1.1', 53), timeout=1); s.close()"]
    exit_code, _, _, _ = runner.run(cmd)
    # On bare metal with open network, exit_code is 0 (connect succeeds).
    # In strict xfail mode, this test must fail (exit_code != 0 must be False), proving the gap is documented!
    assert exit_code != 0, "Expected bare host to allow connection unless inside kernel sandbox"


@pytest.mark.xfail(strict=True, reason="Documented bare-metal limitation: OS filesystem jail / container required to block raw absolute path traversal")
def test_absolute_path_host_file_read_documented_gap(tmp_path: Path):
    """
    Documents known bare-metal boundary: absolute path reads to host filesystem bypass
    USERPROFILE/HOME environment redirection unless in an OS container.
    """
    import sys
    # Create canary file at a known path
    canary = tmp_path / "host_canary.txt"
    canary.write_text("HOST_SECRET", encoding="utf-8")

    runner = IsolatedRunner(Path("."), timeout_sec=3)
    read_cmd = [sys.executable, "-c", f"from pathlib import Path; print(Path(r'{str(canary)}').read_text())"]
    exit_code, stdout, _, _ = runner.run(read_cmd)
    # On bare host, absolute path can be read.
    assert "HOST_SECRET" not in stdout, "Expected absolute path read to fail under filesystem jail"
