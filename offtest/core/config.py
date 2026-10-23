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

    # Sensitive data regex patterns for redaction
    SENSITIVE_PATTERNS: List[Pattern] = [
        # AWS Access Key ID
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        # AWS Secret Access Key
        re.compile(r"(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{40})['\"]?"),
        # Generic API key / Bearer token / Secret
        re.compile(r"(?i)(api[_-]?key|secret|auth[_-]?token|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,80})['\"]?"),
        # Private key headers
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        # Password assignments
        re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s\r\n]{6,64})['\"]?"),
        # Connection strings with password
        re.compile(r"(postgres|mysql|mongodb(?:\+srv)?):\/\/[^:\s\/]+:([^@\s\/]+)@"),
    ]

    # Offline runner environment variables to disable network attempts
    OFFLINE_ENV_OVERRIDES: Dict[str, str] = {
        "PIP_NO_INDEX": "1",
        "npm_config_offline": "true",
        "YARN_OFFLINE": "true",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HTTP_PROXY": "http://127.0.0.1:0",
        "HTTPS_PROXY": "http://127.0.0.1:0",
        "http_proxy": "http://127.0.0.1:0",
        "https_proxy": "http://127.0.0.1:0",
        "OFFLINE_MODE": "1",
    }
