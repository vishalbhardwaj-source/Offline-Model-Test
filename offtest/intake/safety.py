import hashlib
import hmac
import math
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple, Union
from offtest.core.config import OfflineConfig

_INSTALL_KEY_FILE = Path(tempfile.gettempdir()) / ".offtest_hmac_install_key"


def _get_installation_hmac_key() -> bytes:
    try:
        if _INSTALL_KEY_FILE.exists():
            data = _INSTALL_KEY_FILE.read_bytes()
            if len(data) >= 16:
                return data
        key = os.urandom(32)
        _INSTALL_KEY_FILE.write_bytes(key)
        return key
    except Exception:
        return b"offtest-default-fallback-installation-key-32b"


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits for a given string."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def compute_secret_fingerprint(secret: str, salt: Optional[Union[str, bytes]] = None) -> str:
    """
    Computes a one-way deterministic HMAC-SHA256 fingerprint for finding deduplication.
    Uses a per-installation machine key to prevent dictionary/rainbow-table brute forcing
    of low-entropy secrets from generated reports.
    """
    if salt is not None:
        key = salt.encode("utf-8") if isinstance(salt, str) else salt
    else:
        key = _get_installation_hmac_key()
    return hmac.new(key, secret.strip().encode("utf-8"), hashlib.sha256).hexdigest()[:16]


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
        # Cap line length to prevent ReDoS / memory exhaustion on minified or hostile lines
        if len(line) > 10_000:
            line = line[:10_000]

        matched = False

        # 1. Known high-confidence regex patterns
        for det_name, pattern in OfflineConfig.SENSITIVE_DETECTORS:
            match = pattern.search(line)
            if match:
                raw_secret = match.group(match.lastindex) if (match.lastindex and match.lastindex >= 1) else match.group(0)
                fingerprint = compute_secret_fingerprint(raw_secret)
                preview = redact_sensitive_data(line.strip())
                # Check for documented public sample AWS keys (e.g. AKIAIOSFODNN7EXAMPLE)
                if "AKIA" in raw_secret and ("EXAMPLE" in raw_secret or raw_secret == "AKIAIOSFODNN7EXAMPLE"):
                    det_label = "Documented AWS Example Key (AKIA...EXAMPLE)"
                else:
                    det_label = f"Hardcoded Secret ({det_name})"
                findings.append((idx, det_label, preview, fingerprint))
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
                    findings.append((idx, f"High-Entropy Secret Token (Shannon Entropy {entropy:.2f} bits)", preview, fingerprint))
                    break

    return findings
