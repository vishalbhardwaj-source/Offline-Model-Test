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
    Redacts discovered credentials, tokens, passwords, and high-entropy strings
    in text before writing to reports, logs, or passing to/from model layers.
    """
    if not text:
        return ""
    
    redacted = text
    # 1. Regex pattern scrubbing
    for pattern in OfflineConfig.SENSITIVE_PATTERNS:
        def _replace_match(match: re.Match) -> str:
            full = match.group(0)
            if match.lastindex and match.lastindex >= 1:
                sensitive = match.group(match.lastindex)
                return full.replace(sensitive, "[REDACTED_SECRET]")
            return "[REDACTED_SECRET]"
            
        redacted = pattern.sub(_replace_match, redacted)

    # 2. Shannon entropy scrubbing for high-entropy tokens
    candidate_token_pattern = re.compile(r"""(?<=['"])([A-Za-z0-9_\-\.]{24,80})(?=['"])""")
    for token_m in candidate_token_pattern.finditer(redacted):
        token = token_m.group(1)
        if "[REDACTED" not in token and calculate_shannon_entropy(token) >= 4.5:
            redacted = redacted.replace(token, "[REDACTED_SECRET]")
        
    return redacted


def scrub_model_io(text: str) -> str:
    """
    Scrubs both inputs to the model and outputs from the model to prevent
    secret exfiltration or echoing secrets from context.
    """
    return redact_sensitive_data(text)


def sanitize_prompt_context(untrusted_text: str, source_label: str = "repo_content") -> str:
    """
    Sanitizes untrusted repository text (comments, docstrings, README) before passing to local models.
    Guards against prompt injection by wrapping content in non-executable data fences,
    neutralizing instruction-override tokens, and preventing prompt-driven execution control.
    """
    if not untrusted_text:
        return ""

    scrubbed = redact_sensitive_data(untrusted_text)
    
    # Neutralize instruction hijack tokens
    override_patterns = [
        re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"system\s*:", re.IGNORECASE),
        re.compile(r"assistant\s*:", re.IGNORECASE),
        re.compile(r"\[/?INST\]", re.IGNORECASE),
        re.compile(r"<\|im_(?:start|end)\|>", re.IGNORECASE),
    ]
    for p in override_patterns:
        scrubbed = p.sub("[FILTERED_PROMPT_INJECTION_TOKEN]", scrubbed)

    return f'<untrusted_repo_content source="{source_label}">\n{scrubbed}\n</untrusted_repo_content>'


def verify_model_weights_manifest(model_path: Union[str, Path], expected_sha256: str) -> bool:
    """
    Verifies that local AI model weights / runtime files match pinned cryptographic hashes
    prior to execution, securing the air-gapped supply chain.
    """
    p = Path(model_path)
    if not p.is_file():
        return False
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest().lower() == expected_sha256.lower().strip()


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
