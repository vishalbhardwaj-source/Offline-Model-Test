import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from offtest.core.config import OfflineConfig
from offtest.intake.safety import redact_sensitive_data


class IsolatedRunner:
    def __init__(self, work_dir: Path, timeout_sec: int = OfflineConfig.COMMAND_TIMEOUT_SEC):
        self.work_dir = work_dir
        self.timeout_sec = timeout_sec

    def run(
        self,
        command: List[str],
        env_extra: Optional[Dict[str, str]] = None,
        custom_cwd: Optional[Path] = None,
    ) -> Tuple[int, str, str, float]:
        """
        Runs a command with networking disabled through environment controls,
        enforcing a timeout and redacting secrets from output.
        Returns: (exit_code, stdout, stderr, duration_sec)
        """
        env = os.environ.copy()
        # Enforce offline overrides
        env.update(OfflineConfig.OFFLINE_ENV_OVERRIDES)
        if env_extra:
            env.update(env_extra)

        cwd = custom_cwd or self.work_dir

        start_time = time.perf_counter()
        try:
            proc = subprocess.run(
                command,
                cwd=str(cwd),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_sec,
            )
            duration = round(time.perf_counter() - start_time, 3)
            stdout = redact_sensitive_data(proc.stdout)
            stderr = redact_sensitive_data(proc.stderr)
            return proc.returncode, stdout, stderr, duration
        except subprocess.TimeoutExpired as te:
            duration = round(time.perf_counter() - start_time, 3)
            stdout = redact_sensitive_data(te.stdout or "")
            stderr = f"Execution timed out after {self.timeout_sec} seconds."
            return 124, stdout, stderr, duration
        except Exception as e:
            duration = round(time.perf_counter() - start_time, 3)
            return 1, "", f"Failed to execute command: {e}", duration
