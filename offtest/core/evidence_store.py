import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import Optional
from offtest.core.models import RunContext
from offtest.intake.safety import redact_data_structure, redact_sensitive_data


def get_evidence_signing_key() -> bytes:
    """
    Retrieves or generates the HMAC key used to cryptographically seal evidence.json.
    - Honors OFFTEST_HMAC_KEY from host orchestrator environment.
    - Falls back to private per-installation key in user profile / tmp with 0o600 permissions.
    """
    env_key = os.environ.get("OFFTEST_HMAC_KEY")
    if env_key:
        return env_key.encode("utf-8")
    
    key_dir = Path(os.environ.get("OFFTEST_KEY_DIR", Path.home() / ".offtest"))
    key_file = key_dir / "signing.key"
    try:
        if key_file.exists():
            data = key_file.read_bytes()
            if len(data) >= 16:
                return data
        key_dir.mkdir(parents=True, exist_ok=True)
        key = os.urandom(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(key_file), flags, 0o600)
        with open(fd, "wb") as f:
            f.write(key)
        return key
    except Exception:
        # Ephemeral memory key fallback for read-only containers
        if not hasattr(get_evidence_signing_key, "_mem_key"):
            get_evidence_signing_key._mem_key = os.urandom(32)
        return get_evidence_signing_key._mem_key


def atomic_write_text(dest: Path, content: str, encoding: str = "utf-8") -> None:
    """
    Atomically writes content using a temporary file in the destination folder,
    flushes and fsyncs to disk, then replaces destination via os.replace.
    Guards against:
    - Pre-planted symlinks / junctions at destination (O_NOFOLLOW & pre-removal)
    - Unredacted partial writes
    - Overly permissive file modes (enforces 0o600 where supported)
    """
    import time
    import uuid
    
    # Pre-planting defense: refuse writing through existing symlinks
    if dest.is_symlink() or (sys.platform == "win32" and getattr(dest, "is_junction", lambda: False)()):
        try:
            dest.unlink()
        except OSError:
            pass

    temp_file = dest.with_name(f".{dest.name}.tmp_{os.getpid()}_{uuid.uuid4().hex[:6]}")
    success = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(temp_file), flags, 0o600)
        with open(fd, "w", encoding=encoding, newline="") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        
        # Enforce 0o600 permissions where supported
        if sys.platform != "win32":
            try:
                os.chmod(temp_file, 0o600)
            except OSError:
                pass

        # Windows sharing-violation retry loop (handles transient indexer/antivirus locks)
        for attempt in range(4):
            try:
                os.replace(temp_file, dest)
                success = True
                break
            except PermissionError:
                if attempt < 3:
                    time.sleep(0.05 * (attempt + 1))
                else:
                    raise
    finally:
        if not success and temp_file.exists():
            try:
                temp_file.unlink()
            except Exception:
                pass


class EvidenceStore:
    def __init__(self, base_dir: Optional[str] = None):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            self.base_dir = Path(".offtest_runs")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save_run(self, context: RunContext) -> Path:
        run_dir = self.base_dir / context.run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        evidence_file = run_dir / "evidence.json"
        
        # Round 9 Integrity & Redaction Barrier:
        # 1. Pre-serialization recursive redaction on Python data structure (prevents JSON escaping bypasses)
        raw_dict = context.model_dump()
        redacted_dict = redact_data_structure(raw_dict)
        
        # 2. Serialize to clean JSON string
        serialized_json = json.dumps(redacted_dict, indent=2)
        
        # 3. Post-serialization regex/entropy double barrier
        sanitized_json = redact_sensitive_data(serialized_json)
        
        # 4. Re-parse verification: Mathematically validate JSON syntax is uncorrupted
        json.loads(sanitized_json)
        
        # 5. Atomic write with O_NOFOLLOW and restrictive permissions (0o600)
        atomic_write_text(evidence_file, sanitized_json, encoding="utf-8")
        final_bytes = evidence_file.read_bytes()
        
        # 6. Cryptographic Evidence Integrity (SHA-256 + Keyed HMAC)
        sha256_digest = hashlib.sha256(final_bytes).hexdigest()
        atomic_write_text(run_dir / "evidence.json.sha256", f"{sha256_digest}  evidence.json\n")
        
        hmac_key = get_evidence_signing_key()
        hmac_digest = hmac.new(hmac_key, final_bytes, hashlib.sha256).hexdigest()
        atomic_write_text(run_dir / "evidence.json.hmac", f"{hmac_digest}  evidence.json\n")
            
        return evidence_file

    def load_run(self, run_id_or_path: str) -> RunContext:
        path = Path(run_id_or_path)

        if path.is_file():
            target_file = path
        elif (path / "evidence.json").is_file():
            target_file = path / "evidence.json"
        elif (self.base_dir / run_id_or_path / "evidence.json").is_file():
            target_file = self.base_dir / run_id_or_path / "evidence.json"
        else:
            # Fallback: scan working directory and known report folders for matching run_id
            clean_run_id = Path(run_id_or_path).name
            found_candidates = list(Path.cwd().glob(f"**/{clean_run_id}/evidence.json"))
            if not found_candidates:
                # Also search parent/workspace if cwd is subfolder
                found_candidates = list(Path.cwd().parent.glob(f"**/{clean_run_id}/evidence.json")) if Path.cwd().parent else []
            
            if found_candidates:
                target_file = found_candidates[0]
            else:
                raise FileNotFoundError(f"Run evidence not found for '{run_id_or_path}'")
                
        with open(target_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        return RunContext.model_validate(data)
