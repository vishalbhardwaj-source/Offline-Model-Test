import hashlib
import math
import re
from collections import Counter
from typing import List, Optional, Tuple
from offtest.core.config import OfflineConfig


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits for a given string."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def compute_secret_fingerprint(secret: str, salt: str = "offtest-audit-salt") -> str:
    """Computes a one-way deterministic cryptographic fingerprint for finding deduplication."""
    return hashlib.sha256(f"{salt}:{secret.strip()}".encode("utf-8")).hexdigest()[:16]


def redact_sensitive_data(text: str) -> str:
    """
    Redacts discovered credentials, tokens, and passwords in text before writing to reports or logs.
    """
    if not text:
        return ""
    
    redacted = text
    for pattern in OfflineConfig.SENSITIVE_PATTERNS:
        def _replace_match(match: re.Match) -> str:
            full = match.group(0)
            if match.lastindex and match.lastindex >= 1:
                sensitive = match.group(match.lastindex)
                return full.replace(sensitive, "[REDACTED_SECRET]")
            return "[REDACTED_SECRET]"
            
        redacted = pattern.sub(_replace_match, redacted)
        
    return redacted


def scan_for_secrets(content: str, file_path: str) -> List[Tuple[int, str, str, str]]:
    """
    Scans content line-by-line for sensitive data using both regex patterns and Shannon entropy.
    Returns a list of (line_number, match_type, redacted_preview, secret_fingerprint).
    """
    findings = []
    lines = content.splitlines()

    # Generic high-entropy token pattern (e.g. hex/base64 strings)
    candidate_token_pattern = re.compile(r"""['"]([A-Za-z0-9_\-\.]{24,80})['"]""")

    for idx, line in enumerate(lines, start=1):
        matched = False

        # 1. Known high-confidence regex patterns
        for pattern in OfflineConfig.SENSITIVE_PATTERNS:
            match = pattern.search(line)
            if match:
                raw_secret = match.group(match.lastindex) if (match.lastindex and match.lastindex >= 1) else match.group(0)
                fingerprint = compute_secret_fingerprint(raw_secret)
                preview = redact_sensitive_data(line.strip())
                findings.append((idx, "Hardcoded Secret / Credential", preview, fingerprint))
                matched = True
                break

        # 2. Shannon entropy check for non-standard / custom secrets
        if not matched:
            for token_m in candidate_token_pattern.finditer(line):
                token = token_m.group(1)
                entropy = calculate_shannon_entropy(token)
                # High entropy threshold for passwords / keys (>= 4.5 bits)
                if entropy >= 4.5:
                    fingerprint = compute_secret_fingerprint(token)
                    preview = line.strip().replace(token, "[REDACTED_SECRET]")
                    findings.append((idx, f"High-Entropy Secret Token (entropy {entropy:.2f})", preview, fingerprint))
                    break

    return findings
