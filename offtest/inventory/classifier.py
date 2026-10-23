import os
from pathlib import Path
from typing import Dict, Optional, Tuple
from offtest.core.config import OfflineConfig
from offtest.core.models import FileDisposition


EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript (JSX)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (TSX)",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "Sass",
    ".less": "Less",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".md": "Markdown",
    ".rst": "reStructuredText",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".bat": "Batch",
    ".cmd": "Batch",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C/C++ Header",
    ".cpp": "C++",
    ".hpp": "C++ Header",
    ".php": "PHP",
    ".rb": "Ruby",
    ".sql": "SQL",
    ".dockerfile": "Dockerfile",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svgz", ".webp", ".bmp",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar", ".bz2",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".mp3", ".wav", ".ogg", ".mp4", ".mov", ".avi", ".webm",
    ".pyc", ".pyd", ".class", ".o", ".a",
    ".db", ".sqlite", ".sqlite3"
}

TEST_PATTERNS = [
    "test_", "_test.", ".test.", ".spec.", "tests/", "test/", "__tests__/"
]

ENTRY_POINT_FILENAMES = {
    "main.py", "app.py", "wsgi.py", "asgi.py", "index.js", "server.js",
    "app.js", "main.js", "index.ts", "server.ts", "app.ts", "main.go",
    "main.rs", "Application.java"
}


def is_binary_file(file_path: Path) -> bool:
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        # Check first 2048 bytes for null character
        with open(file_path, "rb") as f:
            chunk = f.read(2048)
            if b"\x00" in chunk:
                return True
    except Exception:
        return False
    return False


def classify_file(rel_path: str, abs_path: Path) -> Tuple[FileDisposition, str, Optional[str], str]:
    """
    Returns (disposition, reason, language, category).
    Dispositions: analyzed, excluded, generated, binary, unsupported, failed_to_inspect
    """
    # 1. Check exclusions
    norm_path = rel_path.replace("\\", "/")
    for pattern in OfflineConfig.DEFAULT_EXCLUSIONS:
        import re
        if re.search(pattern, norm_path):
            return FileDisposition.EXCLUDED, f"Matched default exclusion pattern '{pattern}'", None, "excluded"

    # 2. Check accessibility
    try:
        if not abs_path.exists():
            return FileDisposition.FAILED_TO_INSPECT, "File does not exist or unreadable", None, "error"
        stat = abs_path.stat()
    except Exception as e:
        return FileDisposition.FAILED_TO_INSPECT, f"Cannot stat file: {e}", None, "error"

    # 3. Check binary
    if is_binary_file(abs_path):
        return FileDisposition.BINARY, "Identified as binary file format", None, "asset"

    # 4. Check generated
    for pattern in OfflineConfig.GENERATED_PATTERNS:
        import re
        if re.search(pattern, norm_path):
            return FileDisposition.GENERATED, f"Matched generated file pattern '{pattern}'", None, "generated"

    # 5. Check size limit
    if stat.st_size > OfflineConfig.MAX_FILE_SIZE_BYTES:
        return FileDisposition.EXCLUDED, f"File size ({stat.st_size} bytes) exceeds limit ({OfflineConfig.MAX_FILE_SIZE_BYTES} bytes)", None, "large_file"

    # 6. Check extension / language
    ext = abs_path.suffix.lower()
    name = abs_path.name.lower()
    
    if name == "dockerfile":
        language = "Dockerfile"
    elif name == "requirements.txt":
        language = "Requirements"
    else:
        language = EXTENSION_LANGUAGE_MAP.get(ext)

    # Category determination
    lower_norm = norm_path.lower()
    if any(tp in lower_norm for tp in TEST_PATTERNS):
        category = "test"
    elif name in ENTRY_POINT_FILENAMES:
        category = "entry_point"
    elif ext in [".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config", ".env.example"] or name == "requirements.txt":
        category = "config"
    elif ext in [".md", ".rst", ".txt"]:
        category = "doc"
    else:
        category = "source"

    # If language is recognized for analysis
    if language in ["Python", "JavaScript", "JavaScript (JSX)", "TypeScript", "TypeScript (TSX)", "HTML", "CSS", "JSON", "YAML", "Shell", "Requirements", "Dockerfile"]:
        return FileDisposition.ANALYZED, "Supported language or manifest for offline inspection", language, category

    if language is not None:
        return FileDisposition.UNSUPPORTED, f"Language '{language}' identified but offline parser adapter not enabled in this profile", language, category

    return FileDisposition.UNSUPPORTED, f"Unrecognized file format with extension '{ext}'", None, category
