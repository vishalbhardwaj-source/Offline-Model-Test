import re
from typing import Tuple
from offtest.core.config import OfflineConfig


def redact_sensitive_data(text: str) -> str:
    """
    Redacts discovered credentials, tokens, and passwords in text before writing to reports or logs.
    """
    if not text:
        return ""
    
    redacted = text
    for pattern in OfflineConfig.SENSITIVE_PATTERNS:
        # If pattern has groups, redact the sensitive value group
        def _replace_match(match: re.Match) -> str:
            full = match.group(0)
            if match.lastindex and match.lastindex >= 1:
                sensitive = match.group(match.lastindex)
                return full.replace(sensitive, "[REDACTED_SECRET]")
            return "[REDACTED_SECRET]"
            
        redacted = pattern.sub(_replace_match, redacted)
        
    return redacted


def scan_for_secrets(content: str, file_path: str) -> list[Tuple[int, str, str]]:
    """
    Scans content line-by-line for sensitive data.
    Returns a list of (line_number, match_type, redacted_preview).
    """
    findings = []
    lines = content.splitlines()
    for idx, line in enumerate(lines, start=1):
        for pattern in OfflineConfig.SENSITIVE_PATTERNS:
            match = pattern.search(line)
            if match:
                preview = redact_sensitive_data(line.strip())
                findings.append((idx, "Hardcoded Secret / Credential", preview))
                break
    return findings
