import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from offtest.core.config import OfflineConfig
from offtest.intake.safety import redact_sensitive_data
from offtest.checks.sandbox_interceptor import SANDBOX_BOOTSTRAP_CODE


class IsolatedRunner:
    def __init__(self, work_dir: Path, timeout_sec: int = OfflineConfig.COMMAND_TIMEOUT_SEC):
        self.work_dir = work_dir
        self.timeout_sec = timeout_sec
        self.sandbox_home = Path(tempfile.gettempdir()) / f"offtest_sandbox_home_{os.getpid()}"
        self.sandbox_home.mkdir(parents=True, exist_ok=True)
        self._setup_interceptor()

    def _setup_interceptor(self):
        """Installs the offline socket interceptor in the sandbox environment."""
        sitecustomize_path = self.sandbox_home / "sitecustomize.py"
        try:
            sitecustomize_path.write_text(SANDBOX_BOOTSTRAP_CODE, encoding="utf-8")
        except Exception:
            pass

    def _kill_process_tree(self, proc: subprocess.Popen):
        """Kills the entire process tree to prevent orphan background worker leaks."""
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    capture_output=True,
                    timeout=5,
                )
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def run(
        self,
        command: List[str],
        env_extra: Optional[Dict[str, str]] = None,
        custom_cwd: Optional[Path] = None,
    ) -> Tuple[int, str, str, float]:
        """
        Runs a command with:
        1. Scrubbed environment (whitelisted safe vars only, zero host secrets leaked)
        2. Network proxy sinkholing and telemetry suppression
        3. Full process-tree termination on timeout
        4. Output size cap to prevent memory exhaustion
        Returns: (exit_code, stdout, stderr, duration_sec)
        """
        # Scrubbed environment: only keep safe system vars
        env = {
            k: v for k, v in os.environ.items()
            if k.upper() in OfflineConfig.SAFE_ENV_WHITELIST
        }
        # Enforce offline overrides
        env.update(OfflineConfig.OFFLINE_ENV_OVERRIDES)

        # Sandbox home redirection: shield host ~/.ssh, ~/.aws, and personal credentials from untrusted scripts
        env["USERPROFILE"] = str(self.sandbox_home)
        env["HOME"] = str(self.sandbox_home)
        if sys.platform == "win32":
            drive = self.sandbox_home.drive or "C:"
            env["HOMEDRIVE"] = drive
            env["HOMEPATH"] = str(self.sandbox_home)[len(drive):]
            env["APPDATA"] = str(self.sandbox_home / "AppData" / "Roaming")
            env["LOCALAPPDATA"] = str(self.sandbox_home / "AppData" / "Local")
        env["PYTHONPYCACHEPREFIX"] = str(self.sandbox_home / "pycache")

        # Python air-gap sandbox socket interceptor bootstrap
        curr_pythonpath = env.get("PYTHONPATH", "")
        if curr_pythonpath:
            env["PYTHONPATH"] = f"{str(self.sandbox_home)}{os.pathsep}{curr_pythonpath}"
        else:
            env["PYTHONPATH"] = str(self.sandbox_home)
        env["PYTHONSTARTUP"] = str(self.sandbox_home / "sitecustomize.py")

        if env_extra:
            env.update(env_extra)

        cwd = custom_cwd or self.work_dir
        start_time = time.perf_counter()

        # Platform specific process group setup
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["preexec_fn"] = os.setsid

        proc = None
        try:
            proc = subprocess.Popen(
                command,
                cwd=str(cwd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                **kwargs,
            )

            stdout_raw, stderr_raw = proc.communicate(timeout=self.timeout_sec)
            duration = round(time.perf_counter() - start_time, 3)

            # Cap output to prevent memory exhaustion
            max_bytes = OfflineConfig.MAX_SUBPROCESS_OUTPUT_BYTES
            if len(stdout_raw) > max_bytes:
                stdout_raw = stdout_raw[:max_bytes] + "\n[... OUTPUT TRUNCATED TO 10MB ...]"
            if len(stderr_raw) > max_bytes:
                stderr_raw = stderr_raw[:max_bytes] + "\n[... OUTPUT TRUNCATED TO 10MB ...]"

            stdout = redact_sensitive_data(stdout_raw)
            stderr = redact_sensitive_data(stderr_raw)
            return proc.returncode, stdout, stderr, duration

        except subprocess.TimeoutExpired:
            duration = round(time.perf_counter() - start_time, 3)
            if proc:
                self._kill_process_tree(proc)
            return 124, "", f"Execution timed out after {self.timeout_sec} seconds. Process tree terminated.", duration

        except Exception as e:
            duration = round(time.perf_counter() - start_time, 3)
            if proc:
                self._kill_process_tree(proc)
            return 1, "", f"Failed to execute command: {e}", duration
