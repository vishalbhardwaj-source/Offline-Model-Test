import re
from typing import Dict, List, Pattern, Set, Tuple


class OfflineConfig:
    # Operational timeouts and limits
    COMMAND_TIMEOUT_SEC: int = 60
    MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5MB max for text inspection
    MAX_SUBPROCESS_OUTPUT_BYTES: int = 10 * 1024 * 1024  # 10MB cap on stdout/stderr to prevent memory exhaustion

    # Archive safety limits (decompression bomb protection)
    ARCHIVE_MAX_FILES: int = 10_000
    ARCHIVE_MAX_FILE_SIZE_BYTES: int = 50 * 1024 * 1024  # 50MB single file max
    ARCHIVE_MAX_TOTAL_SIZE_BYTES: int = 500 * 1024 * 1024  # 500MB total extraction max
    ARCHIVE_MAX_COMPRESSION_RATIO: float = 100.0  # Max 100:1 ratio

    # Out-of-band pinned model weights manifest (cryptographic hashes pinned at configuration time)
    PINNED_WEIGHTS_MANIFEST: Dict[str, str] = {
        "qwen2.5-coder-7b-instruct.q4_k_m.gguf": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "llama-3.2-3b-instruct.q4_k_m.gguf": "b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef1",
    }

    # Safe environment variable whitelist (prevents host secret leaks into child processes)
    SAFE_ENV_WHITELIST: Set[str] = {
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "LANG",
        "LC_ALL",
        "TERM",
        "TZ",
        "COMSPEC",
        "PATHEXT",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONPYCACHEPREFIX",
    }

    # Default file exclusion patterns
    DEFAULT_EXCLUSIONS: List[str] = [
        r"^\.git([\\/].*)?$",
        r"^\.svn([\\/].*)?$",
        r"^\.hg([\\/].*)?$",
        r"^node_modules([\\/].*)?$",
        r"^\.venv([\\/].*)?$",
        r"^venv([\\/].*)?$",
        r"^env([\\/].*)?$",
        r"^__pycache__([\\/].*)?$",
        r"^\.pytest_cache([\\/].*)?$",
        r"^\.tox([\\/].*)?$",
        r"^\.offtest_runs([\\/].*)?$",
        r"^dist([\\/].*)?$",
        r"^build([\\/].*)?$",
        r"^\.next([\\/].*)?$",
        r"^\.nuxt([\\/].*)?$",
        r"^\.turbo([\\/].*)?$",
        r"^target([\\/].*)?$",  # Rust/Java target
        r"^bin([\\/].*)?$",
        r"^obj([\\/].*)?$",
    ]

    # Generated file markers
    GENERATED_PATTERNS: List[str] = [
        r"\.min\.(js|css)$",
        r"\.bundle\.(js|css)$",
        r"\.map$",
        r"_pb2\.py$",
        r"\.generated\.",
        r"package-lock\.json$",
        r"yarn\.lock$",
        r"pnpm-lock\.yaml$",
        r"poetry\.lock$",
        r"uv\.lock$",
        r"Cargo\.lock$",
        r"composer\.lock$",
        r"Gemfile\.lock$",
    ]

    # Sensitive data detectors and regex patterns for automatic redaction and secret scanning
    SENSITIVE_DETECTORS: List[Tuple[str, Pattern]] = [
        # AWS Access Key ID
        ("AWS Access Key ID Pattern [regex: AKIA...]", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        # AWS Secret Access Key
        ("AWS Secret Access Key Pattern", re.compile(r"(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{40})['\"]?")),
        # GitHub Personal Access Tokens
        ("GitHub Personal Access Token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b")),
        ("GitHub Fine-Grained Token", re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b")),
        # OpenAI / Anthropic / LLM API Keys
        ("LLM API Key (OpenAI/Anthropic)", re.compile(r"\b(sk-(?:proj-|live-)?[a-zA-Z0-9_\-]{20,})\b")),
        # Google API Keys
        ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
        # Slack API Tokens
        ("Slack API Token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,48})\b")),
        # Stripe API Keys
        ("Stripe API Key", re.compile(r"\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,})\b")),
        # JWT Tokens (JSON Web Tokens)
        ("JWT Authentication Token", re.compile(r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b")),
        # Authorization Headers
        ("HTTP Authorization Header", re.compile(r"(?i)(?:Authorization|Auth)\s*[:=]\s*['\"]?(?:Bearer|Basic)\s+([A-Za-z0-9_\-\.\:\=\+\/]{16,})['\"]?")),
        # Generic API key / Bearer token / Secret
        ("Generic API Key Assignment", re.compile(r"(?i)(api[_-]?key|secret|auth[_-]?token|bearer|client[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,80})['\"]?")),
        # Private key blocks (RSA, EC, DSA, OPENSSH, PGP)
        ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
        # Password assignments
        ("Plaintext Password Assignment", re.compile(r"(?i)(password|passwd|pwd|db_pass)\s*[:=]\s*['\"]?([^'\"\s\r\n]{6,64})['\"]?")),
        # Database / Service connection strings with password
        ("Database Connection URI Credential", re.compile(r"(?i)(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s\/]+:([^@\s\/]+)@")),
    ]
    SENSITIVE_PATTERNS: List[Pattern] = [p for _, p in SENSITIVE_DETECTORS]

    # Offline runner environment variables to strictly disable network resolution and outbound calls
    OFFLINE_ENV_OVERRIDES: Dict[str, str] = {
        # Package managers & Runtimes
        "PIP_NO_INDEX": "1",
        "npm_config_offline": "true",
        "YARN_OFFLINE": "true",
        "CARGO_NET_OFFLINE": "true",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GONOSUMDB": "*",
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "POETRY_VIRTUALENVS_CREATE": "false",
        "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
        "PUPPETEER_SKIP_CHROMIUM_DOWNLOAD": "true",
        # Telemetry & Analytics Opt-outs
        "DO_NOT_TRACK": "1",
        "NEXT_TELEMETRY_DISABLED": "1",
        "GATSBY_TELEMETRY_DISABLED": "1",
        "STRIPE_TELEMETRY_DISABLED": "1",
        "ASTRO_TELEMETRY_DISABLED": "1",
        "HOMEBREW_NO_ANALYTICS": "1",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        # Force all proxy traffic to local sinkhole (closed port)
        "HTTP_PROXY": "http://127.0.0.1:0",
        "HTTPS_PROXY": "http://127.0.0.1:0",
        "http_proxy": "http://127.0.0.1:0",
        "https_proxy": "http://127.0.0.1:0",
        "ALL_PROXY": "socks5://127.0.0.1:0",
        "all_proxy": "socks5://127.0.0.1:0",
        # Null out NO_PROXY so clients cannot bypass the sinkhole proxy
        "NO_PROXY": "",
        "no_proxy": "",
        "OFFLINE_MODE": "1",
    }
