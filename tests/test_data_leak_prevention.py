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
    marker_file = dummy_repo / "executed_marker.txt"
    test_script = dummy_repo / "run_me.py"
    test_script.write_text(f"from pathlib import Path; Path(r'{str(marker_file)}').write_text('EXECUTED')", encoding="utf-8")

    # 1. Running with allow_scripts=True on bare host omitting accept_no_kernel_isolation must raise SecurityError specifically
    orchestrator_omitted = AssessmentOrchestrator(
        repo_path_or_archive=str(dummy_repo),
        allow_scripts=True,
        # accept_no_kernel_isolation is intentionally omitted to verify default safety behavior
    )
    with pytest.raises(SecurityError) as exc_info:
        orchestrator_omitted.run()
    assert "Execution Refused" in str(exc_info.value)
    assert "--accept-no-kernel-isolation" in str(exc_info.value)
    assert marker_file.exists() is False, "Refusal must happen before any repository scripts are executed"

    # 2. Explicitly setting accept_no_kernel_isolation=False also raises SecurityError
    orchestrator_explicit_false = AssessmentOrchestrator(
        repo_path_or_archive=str(dummy_repo),
        allow_scripts=True,
        accept_no_kernel_isolation=False,
    )
    with pytest.raises(SecurityError) as exc_info2:
        orchestrator_explicit_false.run()
    assert "Execution Refused" in str(exc_info2.value)

    # 3. Running with accept_no_kernel_isolation=True must proceed
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


import os
import pytest

_has_network_isolation = (
    os.environ.get("OFFTEST_NETWORK_ISOLATION", "").lower() in ("1", "true", "yes")
    or os.environ.get("OFFTEST_KERNEL_ISOLATION", "").lower() in ("1", "true", "yes")
)

_has_fs_isolation = (
    os.environ.get("OFFTEST_FILESYSTEM_ISOLATION", "").lower() in ("1", "true", "yes")
    or os.environ.get("OFFTEST_KERNEL_ISOLATION", "").lower() in ("1", "true", "yes")
)


@pytest.mark.xfail(
    condition=not _has_network_isolation,
    strict=True,
    reason="Documented bare-metal limitation: OS kernel-level network isolation (--network none) required to block unpatched python -I -S interpreter",
)
def test_unpatched_interpreter_bypass_documented_gap():
    """
    Documents known bare-metal boundary: an unpatched interpreter spawned with -I -S
    bypasses sitecustomize and can reach host sockets unless in an OS container.
    Uses non-loopback listener probe to verify network isolation without external dependencies.
    """
    import socket
    import sys
    import threading

    # Bind to 0.0.0.0 and connect to the host's non-loopback interface address.
    # In a --network none container or isolated namespace, non-loopback interfaces do not exist or are unreachable,
    # deterministically blocking connection without requiring external internet traffic.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("0.0.0.0", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    host_ip = None
    try:
        candidate = socket.gethostbyname(socket.gethostname())
        if candidate and not candidate.startswith("127."):
            host_ip = candidate
    except Exception:
        pass

    if not host_ip:
        try:
            s_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_probe.connect(("10.255.255.255", 1))
            candidate = s_probe.getsockname()[0]
            s_probe.close()
            if candidate and not candidate.startswith("127."):
                host_ip = candidate
        except Exception:
            pass

    if not host_ip:
        # No non-loopback interface could be resolved (e.g. offline machine or network unshared).
        # Deterministically treat as blocked without crashing or skipping silently.
        srv.close()
        exit_code = 1
    else:
        def _accept():
            try:
                conn, _ = srv.accept()
                conn.close()
            except Exception:
                pass

        t = threading.Thread(target=_accept, daemon=True)
        t.start()

        runner = IsolatedRunner(Path("."), timeout_sec=3)
        cmd = [sys.executable, "-I", "-S", "-c", f"import socket; s = socket.create_connection(('{host_ip}', {port}), timeout=1); s.close()"]
        exit_code, _, _, _ = runner.run(cmd)
        srv.close()

    # On bare metal with active host network, exit_code is 0 (connect succeeds).
    # Under real network isolation, exit_code != 0 (connection blocked).
    assert exit_code != 0, "Expected bare host to allow connection unless inside kernel sandbox"


@pytest.mark.xfail(
    condition=not _has_fs_isolation,
    strict=True,
    reason="Documented bare-metal limitation: OS filesystem jail / container required to block raw absolute path traversal",
)
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


def test_unc_path_rejection_prevents_smb_leak():
    """
    Verifies that UNC and SMB network paths are rejected immediately before
    invoking filesystem APIs (which would trigger outbound SMB/NTLM traffic on ports 445/139).
    """
    unc_paths = [
        r"\\attacker.evil.com\share\repo",
        r"//remote-server/payload.zip",
        r"\\?\UNC\malicious-host\archive.tar.gz",
        r"//?/UNC/leak/test",
        r"\??\UNC\host\share",
        r"/\attacker\payload",
        r"\/attacker\share",
        r"\\corporate-share@SSL\repo",
        "file://remote-smb-host/share/repo",
    ]
    for unc in unc_paths:
        with pytest.raises(SecurityError) as exc_info:
            RepositoryIntake.prepare_target(unc)
        assert "UNC / SMB" in str(exc_info.value)


def test_sarif_snippet_stripping_option():
    """Verifies that SARIFReportGenerator can strip raw code snippets to prevent exfiltration."""
    from offtest.reports.sarif import SARIFReportGenerator
    from offtest.core.models import Finding, Severity, Confidence, RunContext

    finding = Finding(
        id="FIND-9999",
        title="Test Secret Found",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        impact="Secret in source code",
        evidence="Line 42: const SECRET = 'sk-proj-superclassifiedkey'",
        file_path="src/config.ts",
        line_number=42,
        suggested_action="Rotate secret immediately.",
    )
    ctx = RunContext.model_construct(findings=[finding])

    # 1. Default keeps sanitized evidence
    sarif_default = SARIFReportGenerator(ctx, strip_snippets=False).generate_sarif()
    msg_default = sarif_default["runs"][0]["results"][0]["message"]["text"]
    assert "Line 42" in msg_default

    # 2. Strip snippets enabled replaces with placeholder
    sarif_stripped = SARIFReportGenerator(ctx, strip_snippets=True).generate_sarif()
    msg_stripped = sarif_stripped["runs"][0]["results"][0]["message"]["text"]
    assert "[CODE SNIPPET STRIPPED FOR AIR-GAP EXPORT]" in msg_stripped
    assert "sk-proj" not in msg_stripped


def test_fail_closed_redaction():
    """Verifies that redaction fails closed if an internal exception occurs."""
    from offtest.intake.safety import redact_sensitive_data, RedactionError
    import unittest.mock as mock

    # Normal redaction works
    assert redact_sensitive_data("API_KEY = 'sk-proj-12345678901234567890'") != ""

    # When regex engine or internal routine raises, RedactionError is raised
    with mock.patch("re.compile", side_effect=RuntimeError("Simulated engine fault")):
        with pytest.raises(RedactionError) as exc:
            redact_sensitive_data("Some text with potential secret sk-proj-12345678901234567890")
        assert "failing closed" in str(exc.value)


