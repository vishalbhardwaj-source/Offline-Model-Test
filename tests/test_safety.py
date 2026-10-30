from offtest.intake.safety import (
    calculate_shannon_entropy,
    compute_secret_fingerprint,
    redact_sensitive_data,
    scan_for_secrets,
)


def test_redact_sensitive_data_aws():
    raw_aws = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    redacted = redact_sensitive_data(raw_aws)
    assert "EXAMPLEKEY" not in redacted
    assert "[REDACTED_SECRET]" in redacted

    raw_token = "api_key = 'abcdef1234567890abcdef'"
    redacted_token = redact_sensitive_data(raw_token)
    assert "[REDACTED_SECRET]" in redacted_token


def test_redact_github_and_openai_and_slack_tokens():
    raw = (
        "GITHUB_TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'\n"
        "OPENAI_KEY = 'sk-proj-1234567890abcdefghijklmnopqrstuvwxyz'\n"
        "SLACK_BOT = 'xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx'\n"
    )
    redacted = redact_sensitive_data(raw)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in redacted
    assert "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx" not in redacted
    assert redacted.count("[REDACTED_SECRET]") == 3


def test_redact_jwt_and_private_keys():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doz_g6_bcfP0B_c_V-1234567890abcdef"
    private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y8v9z...SUPERSECRETKEYDATA...==\n"
        "-----END RSA PRIVATE KEY-----"
    )
    text = f"token: {jwt}\nkey:\n{private_key}"
    redacted = redact_sensitive_data(text)
    assert "doz_g6_bcfP0B" not in redacted
    assert "SUPERSECRETKEYDATA" not in redacted
    assert "[REDACTED_SECRET]" in redacted


def test_scan_for_secrets():
    content = """
    # Configuration
    DATABASE_URL = "postgres://user:super_secret_pw@localhost:5432/mydb"
    DEBUG = False
    """
    hits = scan_for_secrets(content, "config.py")
    assert len(hits) >= 1
    assert hits[0][0] == 3  # line 3
    assert "Hardcoded Secret" in hits[0][1]
    assert "super_secret_pw" not in hits[0][2]
    assert "[REDACTED_SECRET]" in hits[0][2]
    assert len(hits[0][3]) == 16  # SHA-256 fingerprint


def test_shannon_entropy_calculation():
    # Low entropy: repetitive characters
    low = calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert low < 1.0

    # High entropy: random hex/base64 key
    high = calculate_shannon_entropy("4f8a9b2c3d1e0f7e6a5b4c3d2e1f0a9b")
    assert high > 3.5

    # Fingerprint deduplication determinism
    fp1 = compute_secret_fingerprint("my_super_secret_token_123")
    fp2 = compute_secret_fingerprint("my_super_secret_token_123")
    assert fp1 == fp2
    assert len(fp1) == 16


def test_env_var_and_reference_not_flagged_as_secret():
    """Verifies that dynamic lookups like os.environ.get and process.env are not flagged as hardcoded secrets."""
    content = """
    username = os.environ.get("UI_TEST_USERNAME")
    password = os.environ.get("UI_TEST_PASSWORD")
    token = process.env.AUTH_TOKEN
    key = ${API_KEY}
    """
    hits = scan_for_secrets(content, "auth.py")
    assert len(hits) == 0


def test_evidence_store_round_trip_with_code_snippets_and_quotes(tmp_path):
    """Verifies that evidence containing quotes, backslashes, and code does not corrupt evidence.json."""
    import json
    from offtest.core.evidence_store import EvidenceStore
    from offtest.core.models import RunContext, Finding, Severity, Confidence, EvidenceStatus

    store = EvidenceStore(base_dir=str(tmp_path))
    finding = Finding.model_construct(
        id="FIND-TEST-001",
        rule_id="OT-SEC-008",
        file_path="uitest_engine/security/auth.py",
        line_number=38,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence_status=EvidenceStatus.OBSERVED,
        title="Test finding with code evidence",
        impact="Credential exposure",
        description='Evidence with quotes and escapes: password = os.environ.get("UI_TEST_PASSWORD")',
        evidence='Line 38 [detector: Hardcoded Secret (Plaintext Password Assignment)]: password = os.environ.get("UI_TEST_PASSWORD")',
        suggested_action="Review environment variables.",
        check_tool="offtest-secret-scanner",
        cwe_id="CWE-798",
    )
    ctx = RunContext.model_construct(
        run_id="run_regression_code_quotes",
        findings=[finding],
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

    # Re-verify JSON can be cleanly parsed
    loaded = json.loads(evidence_file.read_text(encoding="utf-8"))
    assert loaded["run_id"] == "run_regression_code_quotes"
    assert len(loaded["findings"]) == 1
    assert "findings" in loaded
