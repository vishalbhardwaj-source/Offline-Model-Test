import re
from typing import Dict, List, Pattern


class OfflineConfig:
    # Operational timeouts
    COMMAND_TIMEOUT_SEC: int = 60
    MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5MB max for text inspection

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
    ]

    # Sensitive data regex patterns for automatic redaction and secret scanning
    SENSITIVE_PATTERNS: List[Pattern] = [
        # AWS Access Key ID
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        # AWS Secret Access Key
        re.compile(r"(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{40})['\"]?"),
        # GitHub Personal Access Tokens
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        # OpenAI / Anthropic / LLM API Keys
        re.compile(r"\b(sk-(?:proj-|live-)?[a-zA-Z0-9_\-]{20,})\b"),
        # Google API Keys
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        # Slack API Tokens
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,48})\b"),
        # Stripe API Keys
        re.compile(r"\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
        # JWT Tokens (JSON Web Tokens)
        re.compile(r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b"),
        # Authorization Headers
        re.compile(r"(?i)(?:Authorization|Auth)\s*[:=]\s*['\"]?(?:Bearer|Basic)\s+([A-Za-z0-9_\-\.\:\=\+\/]{16,})['\"]?"),
        # Generic API key / Bearer token / Secret
        re.compile(r"(?i)(api[_-]?key|secret|auth[_-]?token|bearer|client[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,80})['\"]?"),
        # Private key blocks (RSA, EC, DSA, OPENSSH, PGP)
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        # Password assignments
        re.compile(r"(?i)(password|passwd|pwd|db_pass)\s*[:=]\s*['\"]?([^'\"\s\r\n]{6,64})['\"]?"),
        # Database / Service connection strings with password
        re.compile(r"(?i)(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s\/]+:([^@\s\/]+)@"),
    ]

    # Offline runner environment variables to strictly disable network resolution and outbound calls
    OFFLINE_ENV_OVERRIDES: Dict[str, str] = {
        # Package managers & Runtimes
        "PIP_NO_INDEX": "1",
        "npm_config_offline": "true",
        "YARN_OFFLINE": "true",
        "CARGO_NET_OFFLINE": "true",
        "GOPROXY": "off",
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
