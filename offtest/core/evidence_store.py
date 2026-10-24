import json
import os
from pathlib import Path
from typing import Optional
from offtest.core.models import RunContext
from offtest.intake.safety import redact_sensitive_data


def atomic_write_text(dest: Path, content: str, encoding: str = "utf-8") -> None:
    """
    Atomically writes content using a temporary file in the destination folder,
    flushes and fsyncs to disk, then replaces destination via os.replace.
    Ensures that interrupted writes or RedactionErrors never leave partial or
    unredacted raw files on disk.
    """
    import uuid
    temp_file = dest.with_name(f".{dest.name}.tmp_{os.getpid()}_{uuid.uuid4().hex[:6]}")
    success = False
    try:
        with open(temp_file, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_file, dest)
        success = True
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
        
        # Enforce zero data leaks: redact all secrets from the serialized evidence JSON before persisting to disk
        raw_json = context.model_dump_json(indent=2)
        sanitized_json = redact_sensitive_data(raw_json)
        
        atomic_write_text(evidence_file, sanitized_json, encoding="utf-8")
            
        return evidence_file

    def load_run(self, run_id_or_path: str) -> RunContext:
        path = Path(run_id_or_path)
        if not path.is_file():
            # Check inside base_dir/run_id/evidence.json
            candidate = self.base_dir / run_id_or_path / "evidence.json"
            if candidate.is_file():
                path = candidate
            else:
                raise FileNotFoundError(f"Run evidence not found for '{run_id_or_path}'")
                
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        return RunContext.model_validate(data)
