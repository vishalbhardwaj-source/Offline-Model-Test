from offtest.intake.safety import redact_sensitive_data, scan_for_secrets


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
