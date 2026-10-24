import os
import stat
import sys
from pathlib import Path
from typing import Callable, Generator, List, Optional, Tuple
from offtest.intake.intake import is_unc_or_remote_path


def is_junction_or_reparse(path_or_str: str | Path) -> bool:
    """
    Determines whether a filesystem path is a directory junction or reparse point.
    Compatible across Python 3.10, 3.11, and 3.12+:
    - Uses os.path.isjunction when present (3.12+)
    - Falls back to os.path.islink
    - On Windows, inspects FILE_ATTRIBUTE_REPARSE_POINT (0x400) via os.lstat
    """
    p = str(path_or_str)
    
    # 1. Python 3.12+ native check
    isjunc = getattr(os.path, "isjunction", None)
    if isjunc is not None:
        try:
            if isjunc(p):
                return True
        except OSError:
            pass

    # 2. Standard symlink check
    try:
        if os.path.islink(p):
            return True
    except OSError:
        pass

    # 3. Windows reparse point attribute fallback (handles junctions on Python 3.10 and 3.11)
    if sys.platform == "win32":
        try:
            st = os.lstat(p)
            attrs = getattr(st, "st_file_attributes", 0)
            if attrs & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
                return True
        except OSError:
            pass

    return False


def safe_walk(
    top_dir: Path | str,
    on_suspicious_entry: Optional[Callable[[str, str, str], None]] = None,
) -> Generator[Tuple[str, List[str], List[str]], None, None]:
    """
    Centralized, hardened tree-walk generator that guarantees:
    1. Never descends into directory junctions, symlinks, or reparse points (prevents SMB triggers).
    2. Prunes VCS metadata (.git, .svn, .hg) at the directory boundary.
    3. Detects and reports suspicious links/junctions (e.g. targeting remote UNC shares)
       via the on_suspicious_entry callback instead of silently ignoring them.
    4. Safe across Python 3.10, 3.11, and 3.12+.
    """
    top = str(top_dir)

    top_resolved = os.path.realpath(top)

    for root, dirs, files in os.walk(top):
        # 1. Filter subdirectories
        safe_dirs: List[str] = []
        for d in dirs:
            if d in [".git", ".svn", ".hg"]:
                continue
            d_path = os.path.join(root, d)

            if is_junction_or_reparse(d_path):
                # Inspect target before pruning
                try:
                    target_link = os.readlink(d_path)
                    if is_unc_or_remote_path(target_link):
                        if on_suspicious_entry:
                            on_suspicious_entry(d_path, "junction", target_link)
                    else:
                        target_resolved = os.path.realpath(os.path.join(root, target_link))
                        if not target_resolved.startswith(top_resolved):
                            if on_suspicious_entry:
                                on_suspicious_entry(d_path, "escaping_symlink", target_link)
                except OSError:
                    pass
                # Never descend into junctions or symlinks
                continue
            safe_dirs.append(d)

        # Mutate dirs in-place to instruct os.walk not to descend into pruned directories
        dirs[:] = safe_dirs

        # 2. Filter file entries
        safe_files: List[str] = []
        for f in files:
            f_path = os.path.join(root, f)
            if is_junction_or_reparse(f_path):
                try:
                    target_link = os.readlink(f_path)
                    if is_unc_or_remote_path(target_link):
                        if on_suspicious_entry:
                            on_suspicious_entry(f_path, "symlink_file", target_link)
                        continue
                    else:
                        target_resolved = os.path.realpath(os.path.join(root, target_link))
                        if not target_resolved.startswith(top_resolved):
                            if on_suspicious_entry:
                                on_suspicious_entry(f_path, "escaping_symlink", target_link)
                            continue
                except OSError:
                    pass
            safe_files.append(f)

        yield root, dirs, safe_files
