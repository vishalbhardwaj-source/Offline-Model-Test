import os
import shutil
import stat
import tarfile
import tempfile
import urllib.parse
import zipfile
from pathlib import Path
from typing import Tuple
from offtest.core.config import OfflineConfig


class SecurityError(Exception):
    """Raised when an archive contains malicious paths, symlinks, bombs, or traversal attempts."""
    pass


def is_unc_or_remote_path(p: str) -> bool:
    r"""
    Detects UNC, SMB, and WebDAV remote network paths across all standard and alternate prefixes:
    - Standard UNC: \\host\share, //host/share, mixed /\host or \/host
    - Percent-encoded UNC: %5C%5Chost, %2F%2Fhost
    - NT / Win32 Device Namespaces: \\?\UNC\, \??\UNC\, \\.\UNC\
    - File URLs: file://host/share, file:////host/share (excluding local file:/// or file://localhost/)
    - WebDAV shares: \\host@SSL\share, \\host@port\share
    """
    raw = str(p).strip()
    if not raw:
        return False
    # Decode percent-encoding (e.g. %5C -> \, %2F -> /)
    raw = urllib.parse.unquote(raw)

    # Check alternate and standard prefixes
    for prefix in [r"\\", r"//", r"/\ ", r"\/", r"\??\UNC", r"\\.\UNC", r"\\?\UNC", r"/??/UNC", r"//./UNC", r"//?/UNC"]:
        if raw.startswith(prefix.strip()):
            return True
    # Check mixed slashes (e.g. /\host or \/host)
    if len(raw) >= 2 and raw[0] in ("\\", "/") and raw[1] in ("\\", "/"):
        return True
    # Check WebDAV SSL forms
    if "@SSL" in raw.upper() or "@80" in raw or "@443" in raw:
        if raw.startswith(("\\", "/")):
            return True
    # Check remote file:// URLs (including file:////host/share)
    if raw.lower().startswith("file:"):
        cleaned_file = raw.lower().replace("file:", "").lstrip("/")
        # If there is a network hostname after file: (not empty / not localhost / not a drive letter like c:)
        if cleaned_file and not cleaned_file.startswith("localhost/") and not (len(cleaned_file) > 1 and cleaned_file[1] == ":"):
            return True
    return False


def check_reparse_points_safely(path: Path) -> None:
    """
    Inspects link targets using os.lstat and os.readlink WITHOUT following them.
    Calling Path.resolve() on Windows can trigger an active SMB connection if a junction points to \\host.
    """
    curr = path
    while curr and curr != curr.parent:
        try:
            if curr.is_symlink():
                target_str = os.readlink(curr)
                if is_unc_or_remote_path(target_str):
                    raise SecurityError(f"Symlink points to prohibited UNC/SMB remote target: '{target_str}'")
        except OSError:
            pass
        curr = curr.parent


class RepositoryIntake:
    @staticmethod
    def prepare_target(path_or_archive: str) -> Tuple[Path, bool]:
        """
        Accepts a local repository path or offline archive (.zip, .tar.gz, .tgz).
        Returns (target_directory_path, is_temporary).
        Guards against:
        - UNC / SMB remote paths (pre- and post-resolution)
        - Zip Slip / path traversal
        - Symlink & hardlink escapes outside sandbox
        - Device nodes / FIFOs
        - Decompression bombs (file count, single file size, total size, compression ratio)
        """
        norm_path = str(path_or_archive).strip()
        # 1. Pre-resolution check: Prohibit remote UNC/SMB network paths (ports 445/139)
        if is_unc_or_remote_path(norm_path):
            raise SecurityError(
                f"UNC / SMB remote network paths are strictly prohibited in offline air-gap mode: '{path_or_archive}'"
            )

        # 1b. Inspect reparse points & symlinks WITHOUT following them (prevents SMB handshake during resolve)
        raw_p = Path(norm_path)
        check_reparse_points_safely(raw_p)

        target = raw_p.resolve()

        # 2. Post-resolution check: Prevent symlinks/junctions resolving to UNC/SMB targets (TOCTOU defense)
        if is_unc_or_remote_path(str(target)) or target.as_posix().startswith("//"):
            raise SecurityError(
                f"Path resolution resolves to a remote UNC/SMB network target: '{target}'"
            )

        if not target.exists():
            raise FileNotFoundError(f"Input path '{path_or_archive}' does not exist.")

        if target.is_dir():
            return target, False

        archive_size = target.stat().st_size
        temp_dir = Path(tempfile.mkdtemp(prefix="offtest_intake_")).resolve()

        try:
            if target.suffix == ".zip":
                with zipfile.ZipFile(target, "r") as z:
                    infolist = z.infolist()
                    if len(infolist) > OfflineConfig.ARCHIVE_MAX_FILES:
                        raise SecurityError(
                            f"Archive exceeds maximum file count limit ({len(infolist)} > {OfflineConfig.ARCHIVE_MAX_FILES})."
                        )

                    total_uncompressed = 0
                    for member in infolist:
                        # 1. Path Traversal Guard
                        resolved = (temp_dir / member.filename).resolve()
                        if not str(resolved).startswith(str(temp_dir)):
                            raise SecurityError(f"Malicious archive member detected (path traversal): {member.filename}")

                        # 2. Decompression Bomb Size Checks
                        if member.file_size > OfflineConfig.ARCHIVE_MAX_FILE_SIZE_BYTES:
                            raise SecurityError(
                                f"Single archive file exceeds max size limit ({member.file_size} bytes): {member.filename}"
                            )
                        total_uncompressed += member.file_size
                        if total_uncompressed > OfflineConfig.ARCHIVE_MAX_TOTAL_SIZE_BYTES:
                            raise SecurityError(
                                f"Archive total extracted size exceeds safety limit ({total_uncompressed} bytes)."
                            )

                    # Compression ratio check
                    if archive_size > 0 and (total_uncompressed / archive_size) > OfflineConfig.ARCHIVE_MAX_COMPRESSION_RATIO:
                        raise SecurityError(
                            f"Decompression bomb detected (compression ratio > {OfflineConfig.ARCHIVE_MAX_COMPRESSION_RATIO}:1)."
                        )

                    z.extractall(temp_dir)

            elif target.suffix in [".tar", ".gz", ".tgz"] or target.name.endswith(".tar.gz"):
                with tarfile.open(target, "r:*") as t:
                    members = t.getmembers()
                    if len(members) > OfflineConfig.ARCHIVE_MAX_FILES:
                        raise SecurityError(
                            f"Archive exceeds maximum file count limit ({len(members)} > {OfflineConfig.ARCHIVE_MAX_FILES})."
                        )

                    total_uncompressed = 0
                    for member in members:
                        # 1. Reject Device Files & FIFOs
                        if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                            raise SecurityError(f"Special device or FIFO file in archive rejected: {member.name}")

                        # 2. Path Traversal Guard
                        resolved = (temp_dir / member.name).resolve()
                        if not str(resolved).startswith(str(temp_dir)):
                            raise SecurityError(f"Malicious archive member detected (path traversal): {member.name}")

                        # 3. Symlink / Hardlink Escape Guard
                        if member.issym() or member.islnk():
                            link_target = (temp_dir / member.name).parent / member.linkname
                            link_resolved = link_target.resolve()
                            if not str(link_resolved).startswith(str(temp_dir)):
                                raise SecurityError(
                                    f"Malicious symlink/hardlink points outside sandbox: {member.name} -> {member.linkname}"
                                )

                        # 4. Decompression Bomb Size Checks
                        if member.size > OfflineConfig.ARCHIVE_MAX_FILE_SIZE_BYTES:
                            raise SecurityError(
                                f"Single archive file exceeds max size limit ({member.size} bytes): {member.name}"
                            )
                        total_uncompressed += member.size
                        if total_uncompressed > OfflineConfig.ARCHIVE_MAX_TOTAL_SIZE_BYTES:
                            raise SecurityError(
                                f"Archive total extracted size exceeds safety limit ({total_uncompressed} bytes)."
                            )

                    # Compression ratio check
                    if archive_size > 0 and (total_uncompressed / archive_size) > OfflineConfig.ARCHIVE_MAX_COMPRESSION_RATIO:
                        raise SecurityError(
                            f"Decompression bomb detected (compression ratio > {OfflineConfig.ARCHIVE_MAX_COMPRESSION_RATIO}:1)."
                        )

                    t.extractall(temp_dir)

            else:
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise ValueError(f"Input path '{path_or_archive}' is neither a directory nor a supported archive (.zip, .tar, .tar.gz).")

            return temp_dir, True

        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise
