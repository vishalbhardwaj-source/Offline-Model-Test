import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Tuple


class RepositoryIntake:
    @staticmethod
    def prepare_target(path_or_archive: str) -> Tuple[Path, bool]:
        """
        Accepts a local repository path or offline archive (.zip, .tar.gz, .tgz).
        Returns (target_directory_path, is_temporary).
        If temporary, caller is responsible for cleanup or leaving it in isolated runs.
        """
        target = Path(path_or_archive).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Input path '{path_or_archive}' does not exist.")

        if target.is_dir():
            return target, False

        # If it is an archive, extract to temporary directory safely
        if target.suffix in [".zip", ".tar", ".gz", ".tgz"]:
            temp_dir = Path(tempfile.mkdtemp(prefix="offtest_intake_"))
            
            if target.suffix == ".zip":
                with zipfile.ZipFile(target, "r") as z:
                    for member in z.infolist():
                        # Prevent Zip Slip / path traversal
                        resolved = (temp_dir / member.filename).resolve()
                        if not str(resolved).startswith(str(temp_dir)):
                            raise SecurityError(f"Malicious archive member detected: {member.filename}")
                    z.extractall(temp_dir)
            else:
                with tarfile.open(target, "r:*") as t:
                    for member in t.getmembers():
                        resolved = (temp_dir / member.name).resolve()
                        if not str(resolved).startswith(str(temp_dir)):
                            raise SecurityError(f"Malicious archive member detected: {member.name}")
                    t.extractall(temp_dir)
                    
            return temp_dir, True

        raise ValueError(f"Input path '{path_or_archive}' is neither a directory nor a supported archive (.zip, .tar, .tar.gz).")
