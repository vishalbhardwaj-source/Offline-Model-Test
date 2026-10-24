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

# Windows Job Object bindings for robust child process tree containment
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    JobObjectExtendedLimitInformation = 9
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoCounters", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryLimit", ctypes.c_size_t),
            ("PeakJobMemoryLimit", ctypes.c_size_t),
        ]


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

    def _create_job_object(self) -> Optional[int]:
        """Creates a Windows Job Object configured to terminate all assigned child processes when closed."""
        if sys.platform != "win32":
            return None
        try:
            h_job = kernel32.CreateJobObjectW(None, None)
            if not h_job:
                return None
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            res = kernel32.SetInformationJobObject(
                h_job,
                JobObjectExtendedLimitInformation,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not res:
                kernel32.CloseHandle(h_job)
                return None
            return h_job
        except Exception:
            return None

    def _kill_process_tree(self, proc: subprocess.Popen, h_job: Optional[int] = None):
        """Kills the entire process tree using Windows Job Object or taskkill to prevent orphan process leaks."""
        try:
            if sys.platform == "win32":
                if h_job:
                    try:
                        kernel32.TerminateJobObject(h_job, 1)
                    except Exception:
                        pass
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

        # Environment profile redirection & host credential isolation:
        # Redirects USERPROFILE, HOME, and APPDATA to an ephemeral sandbox to protect host credentials (~/.ssh, ~/.aws)
        # Note: This performs environment-level isolation (protects environment-variable lookups), not kernel filesystem sandbox.
        env["USERPROFILE"] = str(self.sandbox_home)
        env["HOME"] = str(self.sandbox_home)
        if sys.platform == "win32":
            drive = self.sandbox_home.drive or "C:"
            env["HOMEDRIVE"] = drive
            env["HOMEPATH"] = str(self.sandbox_home)[len(drive):]
            env["APPDATA"] = str(self.sandbox_home / "AppData" / "Roaming")
            env["LOCALAPPDATA"] = str(self.sandbox_home / "AppData" / "Local")
        env["PYTHONPYCACHEPREFIX"] = str(self.sandbox_home / "pycache")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUSERBASE"] = str(self.sandbox_home / "userbase")

        # Python air-gap sandbox socket interceptor bootstrap
        # Fallback for user-site packages:
        # If pytest or test dependencies were installed with `pip install --user`,
        # redirecting PYTHONUSERBASE to the sandbox hides them unless the host user-site
        # is explicitly appended to PYTHONPATH.
        #
        # Architectural Trade-offs & Limitations:
        # 1. .pth files: Python does not process `.pth` files for directories on PYTHONPATH
        #    (only directories added by the `site` module execute `.pth` files). Editable
        #    installs (`pip install -e`) relying on `.pth` files in user-site may not resolve.
        # 2. Host Package Leakage: Exposing the host's user site allows sandbox code to import
        #    host user-site packages, weakening isolation from host-level environment contamination.
        #    For complete hermetic isolation, a dedicated runner virtual environment with pinned
        #    dependencies should be used.
        import site
        pythonpath_parts = [str(self.sandbox_home)]
        curr_pythonpath = env.get("PYTHONPATH", "")
        if curr_pythonpath:
            pythonpath_parts.append(curr_pythonpath)
        try:
            user_site = site.getusersitepackages()
            if user_site and Path(user_site).is_dir() and user_site not in pythonpath_parts:
                pythonpath_parts.append(user_site)
        except Exception:
            pass
        env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)
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
        h_job = self._create_job_object()
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

            # Bind Windows Job Object to child process to ensure child process tree is contained
            if h_job and sys.platform == "win32":
                try:
                    kernel32.AssignProcessToJobObject(h_job, proc._handle)
                except Exception:
                    pass

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
                self._kill_process_tree(proc, h_job=h_job)
            return 124, "", f"Execution timed out after {self.timeout_sec} seconds. Process tree terminated.", duration

        except Exception as e:
            duration = round(time.perf_counter() - start_time, 3)
            if proc:
                self._kill_process_tree(proc, h_job=h_job)
            return 1, "", f"Failed to execute command: {e}", duration
        finally:
            if h_job and sys.platform == "win32":
                try:
                    kernel32.CloseHandle(h_job)
                except Exception:
                    pass
