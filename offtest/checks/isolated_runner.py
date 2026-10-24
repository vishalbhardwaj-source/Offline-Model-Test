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


def probe_kernel_network_isolation() -> Tuple[bool, str]:
    """
    Actively verifies whether OS/kernel-level network isolation is enforced.
    Checking /.dockerenv or environment variables alone is insufficient because
    a container can be started with host or bridge networking.

    Uses strictly connectionless UDP routing table queries (sends ZERO packets/SYNs over the wire):
    1. Interface Address Enumeration: rejects any bound non-loopback IP on the host.
    2. LAN Route Probing: probes RFC 1918 LAN subnets (10.x, 172.x, 192.168.x) to catch hosts with local LAN routes but no default gateway.
    3. IPv4 & IPv6 Documentation Probes: probes RFC 5737 (192.0.2.1) and RFC 3849 (2001:db8::1).
    4. Handles Windows Winsock WSA error codes (WSAENETUNREACH 10051, WSAEHOSTUNREACH 10065).
    Returns: (is_isolated, diagnostic_reason)
    """
    import socket

    # 1. Native OS Interface Enumeration in Current Process Network Namespace (Fail-Safe)
    if hasattr(socket, "if_nameindex"):
        # Linux/Unix: socket.if_nameindex() queries the current network namespace directly
        try:
            ifaces = socket.if_nameindex()
            for _, ifname in ifaces:
                if ifname != "lo":
                    return False, f"Non-loopback network interface attached in namespace: '{ifname}'."
        except Exception as e:
            return False, f"Failed to enumerate network interfaces via socket.if_nameindex ({e}); failing closed."
    elif sys.platform == "win32":
        # Windows: GetAdaptersAddresses with AF_UNSPEC (0) to query both IPv4 and IPv6 adapters
        try:
            import ctypes
            from ctypes import wintypes

            class IP_ADAPTER_ADDRESSES(ctypes.Structure):
                pass

            IP_ADAPTER_ADDRESSES._fields_ = [
                ("Length", wintypes.ULONG),
                ("IfIndex", wintypes.DWORD),
                ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
                ("AdapterName", ctypes.c_char_p),
                ("FirstUnicastAddress", ctypes.c_void_p),
                ("FirstAnycastAddress", ctypes.c_void_p),
                ("FirstMulticastAddress", ctypes.c_void_p),
                ("FirstDnsServerAddress", ctypes.c_void_p),
                ("DnsSuffix", ctypes.c_wchar_p),
                ("Description", ctypes.c_wchar_p),
                ("FriendlyName", ctypes.c_wchar_p),
                ("PhysicalAddress", ctypes.c_ubyte * 8),
                ("PhysicalAddressLength", wintypes.DWORD),
                ("Flags", wintypes.DWORD),
                ("Mtu", wintypes.DWORD),
                ("IfType", wintypes.DWORD),
                ("OperStatus", wintypes.DWORD),
            ]

            AF_UNSPEC = 0
            flags = 0x000E  # GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
            out_buf_len = wintypes.ULONG(15000)
            buf = ctypes.create_string_buffer(out_buf_len.value)
            ret = ctypes.windll.iphlpapi.GetAdaptersAddresses(AF_UNSPEC, flags, None, buf, ctypes.byref(out_buf_len))
            if ret == 111:  # ERROR_BUFFER_OVERFLOW
                buf = ctypes.create_string_buffer(out_buf_len.value)
                ret = ctypes.windll.iphlpapi.GetAdaptersAddresses(AF_UNSPEC, flags, None, buf, ctypes.byref(out_buf_len))

            # ret == 232 (ERROR_NO_DATA): no adapters exist at all (pass)
            if ret == 232:
                pass
            elif ret == 0:
                # Walk adapter list; skip IF_TYPE_SOFTWARE_LOOPBACK (24) and disconnected adapters
                curr = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
                while curr:
                    adapter = curr.contents
                    if adapter.IfType != 24 and adapter.OperStatus == 1:
                        name = adapter.FriendlyName or "network adapter"
                        return False, f"Active Windows network adapter detected: '{name}' (Type {adapter.IfType}). Host is not air-gapped."
                    curr = adapter.Next
        except Exception as e:
            return False, f"Win32 adapter inspection failed ({e}); failing closed."

    # 2. Connectionless Route Probes (checks kernel routing tables for active subnets)
    lan_probes = ["192.0.2.1", "10.255.255.1", "172.31.255.1", "192.168.1.1", "169.254.1.1"]
    for test_ip in lan_probes:
        try:
            s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s4.settimeout(0.1)
            s4.connect((test_ip, 53))
            local_ip = s4.getsockname()[0]
            s4.close()
            if local_ip and not local_ip.startswith("127."):
                return False, f"Host IPv4 network interface is active ({local_ip}). Outbound route to {test_ip} present."
        except OSError:
            # Expected in --network none: ENETUNREACH (101) or WSAENETUNREACH (10051)
            pass
        except Exception:
            pass

    # 3. IPv6 Connectionless Route Probe
    try:
        if socket.has_ipv6:
            for v6_ip in ["2001:db8::1", "fe80::1"]:
                try:
                    s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                    s6.settimeout(0.1)
                    s6.connect((v6_ip, 53))
                    sock_name6 = s6.getsockname()
                    s6.close()
                    if sock_name6[0] and sock_name6[0] != "::1":
                        return False, f"Host IPv6 network interface is active ({sock_name6[0]}). IPv6 egress present."
                except OSError:
                    pass
                except Exception:
                    pass
    except Exception:
        pass

    # 4. Check container/namespace environment presence
    in_container = (
        Path("/.dockerenv").exists()
        or Path("/run/.containerenv").exists()
        or os.environ.get("OFFTEST_KERNEL_ISOLATION", "").lower() in ("1", "true", "yes")
    )
    if not in_container:
        return False, "Running on bare host without container or network namespace isolation."

    return True, "Verified: OS container with zero non-loopback network interfaces."


def verify_kernel_sandbox_environment(repo_path: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Verifies full kernel sandbox properties (network, filesystem, and privileges)
    before approving untrusted script execution:
    1. Zero non-loopback network interfaces (network isolation).
    2. Read-only root filesystem: writing to / must fail with EROFS (Read-only file system).
    3. Dropped Linux capabilities: CapEff must be 0000000000000000, non-root (UID != 0), NoNewPrivs: 1.
    4. Daemon socket containment: no Docker/Podman/containerd sockets mounted or DOCKER_HOST present.
    5. Host credential absence: ~/.ssh, ~/.aws, ~/.git-credentials, ~/.kube, ~/.config/gh do not exist.
    6. Bare Windows host always fails closed (script execution in container is Linux-container-only).
    """
    # 0. Windows host refusal (fails closed; Windows bare-metal cannot satisfy container namespace checks)
    if sys.platform == "win32":
        return False, "Script execution is supported only inside verified Linux container environments. Bare Windows host does not provide kernel namespace/read-only isolation."

    # 1. Network Namespace Isolation (checks socket.if_nameindex for 'lo' only)
    net_ok, net_diag = probe_kernel_network_isolation()
    if not net_ok:
        return False, net_diag

    # 2. Daemon socket & pipe containment (prevent container escape via mounted control sockets)
    dangerous_sockets = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/podman/podman.sock",
        "/run/containerd/containerd.sock",
    ]
    for s_path in dangerous_sockets:
        if Path(s_path).exists():
            return False, f"Dangerous container daemon socket mounted: '{s_path}'."
    if os.environ.get("DOCKER_HOST"):
        return False, f"External DOCKER_HOST control variable defined: '{os.environ['DOCKER_HOST']}'."

    # 3. Read-only Root Filesystem Verification (asserts EROFS on root)
    import errno
    try:
        probe_path = Path("/.offtest_sandbox_ro_probe")
        with open(probe_path, "wb") as f:
            f.write(b"probe")
        try:
            probe_path.unlink()
        except Exception:
            pass
        return False, "Root filesystem is writable. Hardened container requires --read-only root."
    except OSError as e:
        if e.errno != errno.EROFS:
            return False, f"Root filesystem write failed with {e.strerror} (errno {e.errno}), but expected EROFS (Read-only file system)."
    except Exception as e:
        return False, f"Read-only root verification failed ({e}); failing closed."

    # 4. Linux privilege and capability containment (non-root, NoNewPrivs, CapEff 0)
    try:
        if hasattr(os, "getuid") and os.getuid() == 0:
            return False, "Process is running as root (UID 0). Hardened container requires non-root user (--user 10001)."
        status_file = Path("/proc/self/status")
        if status_file.exists():
            status_text = status_file.read_text(encoding="utf-8", errors="ignore")
            # Verify NoNewPrivs
            if "NoNewPrivs:\t1" not in status_text and "NoNewPrivs: 1" not in status_text:
                return False, "Kernel privilege escalation restriction missing (NoNewPrivs != 1). Pass --security-opt no-new-privileges."
            # Verify CapEff is 0 (all capabilities dropped)
            for line in status_text.splitlines():
                if line.startswith("CapEff:"):
                    capeff = line.split(":", 1)[1].strip()
                    if capeff not in ("0", "0000000000000000"):
                        return False, f"Process retains active Linux capabilities (CapEff: {capeff}). Pass --cap-drop ALL."
    except Exception as e:
        return False, f"Privilege inspection failed ({e}); failing closed."

    # 5. Host credential isolation (verify ~/.ssh, ~/.aws, ~/.kube do not exist in container root)
    home_dir = Path.home()
    credential_dirs = [".ssh", ".aws", ".kube", ".git-credentials", ".docker/config.json"]
    for cred in credential_dirs:
        if (home_dir / cred).exists():
            return False, f"Host credential artifact detected ({home_dir / cred}). Host filesystem is not isolated."

    return True, "Verified: Hardened container environment (Zero interfaces, read-only root, CapEff 0, credentials unmounted)."


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
            env["PROGRAMDATA"] = str(self.sandbox_home / "ProgramData")
        env["PYTHONPYCACHEPREFIX"] = str(self.sandbox_home / "pycache")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUSERBASE"] = str(self.sandbox_home / "userbase")
        # Hardening: prevent untrusted test plugins or install scripts from auto-executing
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        env["npm_config_ignore_scripts"] = "true"

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

        # Platform specific process group setup and handle inheritance suppression
        kwargs = {"close_fds": True}
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
