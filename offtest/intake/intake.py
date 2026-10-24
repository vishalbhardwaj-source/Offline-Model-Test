import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Tuple
from offtest.core.config import OfflineConfig


class SecurityError(Exception):
    """Raised when an archive contains malicious paths, symlinks, bombs, or traversal attempts."""
    pass


class RepositoryIntake:
    @staticmethod
    def prepare_target(path_or_archive: str) -> Tuple[Path, bool]:
        """
        Accepts a local repository path or offline archive (.zip, .tar.gz, .tgz).
        Returns (target_directory_path, is_temporary).
        Guards against:
        - Zip Slip / path traversal
        - Symlink & hardlink escapes outside sandbox
        - Device nodes / FIFOs
        - Decompression bombs (file count, single file size, total size, compression ratio)
        """
        norm_path = str(path_or_archive).strip()
        # Prohibit remote UNC/SMB network paths to prevent outbound NTLM credential leaks (ports 445/139)
        if norm_path.startswith(("\\\\", "//", "\\\\?\\UNC\\", "//?/UNC/")):
            raise SecurityError(
                f"UNC / SMB remote network paths are strictly prohibited in offline air-gap mode: '{path_or_archive}'"
            )

        target = Path(path_or_archive).resolve()
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
