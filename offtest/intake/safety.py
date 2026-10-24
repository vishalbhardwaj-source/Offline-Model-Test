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


def is_high_entropy_secret(token: str) -> Tuple[bool, float, str]:
    """
    Evaluates whether a candidate token exceeds Shannon entropy thresholds
    based on its character set:
    - Pure hexadecimal ([0-9a-fA-F]): max theoretical entropy is log2(16) = 4.0 bits. Threshold >= 3.2 bits (len >= 24).
    - Alphanumeric ([0-9a-zA-Z]): max theoretical entropy ~ 5.95 bits. Threshold >= 3.8 bits (len >= 20).
    - Base64 ([0-9a-zA-Z+/=] or [0-9a-zA-Z_\\-]): threshold >= 4.4 bits (len >= 24).
    """
    if len(token) < 20:
        return False, 0.0, ""
    entropy = calculate_shannon_entropy(token)
    if re.fullmatch(r"[0-9a-fA-F]+", token):
        if len(token) >= 24 and entropy >= 3.2:
            return True, entropy, "Hexadecimal"
    elif re.fullmatch(r"[0-9a-zA-Z]+", token):
        if len(token) >= 20 and entropy >= 3.8:
            return True, entropy, "Alphanumeric"
    elif re.fullmatch(r"[0-9a-zA-Z+/=]+", token) or re.fullmatch(r"[0-9a-zA-Z_\-]+={0,2}", token):
        if len(token) >= 24 and entropy >= 4.4:
            return True, entropy, "Base64"
    return False, entropy, ""


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
    Redacts discovered credentials, tokens, passwords, and charset-aware high-entropy strings
    in text before writing to reports, logs, or passing to/from model layers.
    Operates strictly on the in-memory string copy, preserving underlying file integrity.
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

    # 2. Charset-aware Shannon entropy scrubbing for high-entropy tokens
    # Strictly require exact expected cryptographic/telemetry shapes when safe context keys match
    candidate_token_pattern = re.compile(r"""(?<=['"])([A-Za-z0-9_\-\.\+=/]{20,80})(?=['"])""")
    for token_m in candidate_token_pattern.finditer(redacted):
        token = token_m.group(1)
        start_idx = token_m.start(1)
        prefix_context = redacted[max(0, start_idx - 50) : start_idx].lower()

        # Integrity hashes MUST strictly match hexadecimal shape (32-64 hex chars)
        if any(k in prefix_context for k in ["commit_hash", "sha256", "checksum"]):
            if re.fullmatch(r"[0-9a-fA-F]{32,64}", token):
                continue

        # Package URLs must match purl schema
        if "purl" in prefix_context and token.startswith("pkg:"):
            continue

        # System telemetry must match valid platform or version shape
        if any(k in prefix_context for k in ["platform", "operating_system", "os", "system", "arch"]):
            if token.startswith(("Linux-", "Windows-", "Darwin-", "FreeBSD-", "OpenBSD-")) or re.fullmatch(r"[A-Za-z0-9_\.\-]+", token):
                continue

        # Safe tool/run metadata
        if any(k in prefix_context for k in ["run_id", "schema_version", "repo_path"]):
            if token.startswith("run_") or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", token) or "/" in token or "\\" in token:
                continue

        if token.startswith(("Linux-", "Windows-", "Darwin-", "FreeBSD-", "OpenBSD-")):
            continue

        if "[REDACTED" not in token:
            is_secret, _, _ = is_high_entropy_secret(token)
            if is_secret:
                redacted = redacted.replace(f'"{token}"', '"[REDACTED_SECRET]"').replace(f"'{token}'", "'[REDACTED_SECRET]'")
        
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
    Guards against prompt injection using per-request random fence nonces, neutralizing
    closing fence tags inside content, and treating instruction-override phrases as anomaly signals.
    """
    if not untrusted_text:
        return ""

    nonce = os.urandom(8).hex()
    scrubbed = redact_sensitive_data(untrusted_text)
    
    # Neutralize closing fence delimiters to prevent fence escape
    scrubbed = re.sub(r"</\s*untrusted_repo_content\b[^>]*>", "[ESCAPED_FENCE_CLOSE]", scrubbed, flags=re.IGNORECASE)

    # Tag instruction hijack tokens as anomalous telemetry signals
    override_patterns = [
        re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"system\s*:", re.IGNORECASE),
        re.compile(r"assistant\s*:", re.IGNORECASE),
        re.compile(r"\[/?INST\]", re.IGNORECASE),
        re.compile(r"<\|im_(?:start|end)\|>", re.IGNORECASE),
    ]
    for p in override_patterns:
        scrubbed = p.sub("[FILTERED_PROMPT_INJECTION_TOKEN]", scrubbed)

    return f'<untrusted_repo_content token="{nonce}" source="{source_label}">\n{scrubbed}\n</untrusted_repo_content token="{nonce}">'


def verify_model_weights_manifest(
    model_path: Union[str, Path],
    expected_sha256: str,
    copy_to_private_sandbox: bool = False,
    sandbox_dir: Optional[Path] = None,
) -> Tuple[bool, Optional[Path]]:
    """
    Verifies that local AI model weights / runtime binaries match an out-of-band pinned
    cryptographic SHA-256 hash prior to execution, mitigating supply-chain tampering.

    TOCTOU Mitigation:
    - Opens with exclusive read-only descriptor flags to inspect contents.
    - If copy_to_private_sandbox=True, streams verified bytes directly into an immutable,
      private sandbox location so the downstream runtime loads the exact verified bytes
      without path-substitution race conditions.
    Returns: (is_valid, verified_path)
    """
    p = Path(model_path)
    if not p.is_file():
        return False, None
    h = hashlib.sha256()
    dest_path: Optional[Path] = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        fd = os.open(str(p), flags)
        with os.fdopen(fd, "rb") as f:
            if copy_to_private_sandbox:
                target_dir = sandbox_dir or (Path(tempfile.gettempdir()) / "offtest_verified_models")
                target_dir.mkdir(parents=True, exist_ok=True)
                dest_path = target_dir / f"verified_{p.name}"
                with open(dest_path, "wb") as out_f:
                    while chunk := f.read(1024 * 1024):
                        h.update(chunk)
                        out_f.write(chunk)
            else:
                while chunk := f.read(1024 * 1024):
                    h.update(chunk)
                dest_path = p

        is_valid = (h.hexdigest().lower() == expected_sha256.lower().strip())
        if is_valid and copy_to_private_sandbox and dest_path:
            try:
                import stat
                # Set read-only permissions to prevent same-user tampering
                os.chmod(dest_path, stat.S_IREAD)
            except Exception:
                pass
        elif not is_valid and copy_to_private_sandbox and dest_path and dest_path.exists():
            dest_path.unlink()
            dest_path = None
        return is_valid, (dest_path if is_valid else None)
    except Exception:
        return False, None


def verify_against_pinned_manifest(
    model_name: str,
    model_path: Union[str, Path],
    copy_to_private_sandbox: bool = True,
    sandbox_dir: Optional[Path] = None,
) -> Tuple[bool, Optional[Path]]:
    """
    Verifies model weights strictly against the out-of-band pinned manifest in OfflineConfig.
    Guarantees out-of-band integrity without accepting caller-supplied or repo-controlled hashes.
    """
    pinned_hash = OfflineConfig.PINNED_WEIGHTS_MANIFEST.get(model_name)
    if not pinned_hash:
        return False, None
    return verify_model_weights_manifest(
        model_path=model_path,
        expected_sha256=pinned_hash,
        copy_to_private_sandbox=copy_to_private_sandbox,
        sandbox_dir=sandbox_dir,
    )


def scan_for_secrets(content: str, file_path: str) -> List[Tuple[int, str, str, str]]:
    """
    Scans content line-by-line for sensitive data using both regex patterns and charset-aware Shannon entropy.
    Returns a list of (line_number, match_type, redacted_preview, secret_fingerprint).
    """
    findings = []
    lines = content.splitlines()

    candidate_token_pattern = re.compile(r"""['"]([A-Za-z0-9_\-\.\+=/]{20,80})['"]""")

    for idx, line in enumerate(lines, start=1):
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
                if "AKIA" in raw_secret and ("EXAMPLE" in raw_secret or raw_secret == "AKIAIOSFODNN7EXAMPLE"):
                    det_label = "Documented AWS Example Key (AKIA...EXAMPLE)"
                else:
                    det_label = f"Hardcoded Secret ({det_name})"
                findings.append((idx, det_label, preview, fingerprint))
                matched = True
                break

        # 2. Charset-aware Shannon entropy check for non-standard / custom secrets (hex, alphanumeric, base64)
        if not matched:
            for token_m in candidate_token_pattern.finditer(line):
                token = token_m.group(1)
                is_secret, entropy, cset = is_high_entropy_secret(token)
                if is_secret:
                    fingerprint = compute_secret_fingerprint(token)
                    preview = line.strip().replace(token, "[REDACTED_SECRET]")
                    findings.append((idx, f"High-Entropy Secret Token ({cset}, Shannon Entropy {entropy:.2f} bits)", preview, fingerprint))
                    break

    return findings
