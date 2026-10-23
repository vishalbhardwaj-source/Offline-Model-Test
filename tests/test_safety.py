from offtest.intake.safety import redact_sensitive_data, scan_for_secrets


def test_redact_sensitive_data():
    raw_aws = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    redacted = redact_sensitive_data(raw_aws)
    assert "EXAMPLEKEY" not in redacted
    assert "[REDACTED_SECRET]" in redacted

    raw_token = "api_key = 'abcdef1234567890abcdef'"
    redacted_token = redact_sensitive_data(raw_token)
    assert "[REDACTED_SECRET]" in redacted_token


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
