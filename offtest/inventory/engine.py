import hashlib
import os
from pathlib import Path
from typing import Dict, List, Tuple
from offtest.core.models import FileDisposition, FileRecord, RepositoryInventorySummary
from offtest.inventory.classifier import classify_file


def compute_sha256(path: Path) -> str:
    """Computes byte-exact SHA-256 for repository files (including binary and model weights)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "error_reading_hash"


def count_lines(path: Path) -> int:
    try:
        count = 0
        with open(path, "rb") as f:
            for line in f:
                count += 1
        return count
    except Exception:
        return 0


class InventoryEngine:
    def __init__(self, repo_dir: str):
        self.repo_dir = Path(repo_dir).resolve()

    def scan(self) -> Tuple[List[FileRecord], RepositoryInventorySummary]:
        files: List[FileRecord] = []
        summary = RepositoryInventorySummary()
        lang_counts: Dict[str, int] = {}
        frameworks = set()
        build_systems = set()
        package_managers = set()
        entry_points = []
        test_files_count = 0

        for root, dirs, filenames in os.walk(self.repo_dir):
            # Prune VCS internals and NEVER descend into directory junctions or symlinks (prevents SMB triggers)
            safe_dirs = []
            for d in dirs:
                if d in [".git", ".svn", ".hg"]:
                    continue
                d_path = os.path.join(root, d)
                is_junc = False
                if hasattr(os.path, "isjunction"):
                    try:
                        is_junc = os.path.isjunction(d_path)
                    except OSError:
                        is_junc = True
                if os.path.islink(d_path) or is_junc:
                    # Do not descend into symlink or junction (fail closed on junctions)
                    continue
                safe_dirs.append(d)
            dirs[:] = safe_dirs

            rel_root = os.path.relpath(root, self.repo_dir)
            if rel_root == ".":
                rel_root = ""

            for fname in filenames:
                abs_file = Path(root) / fname
                # Guard against individual file symlinks targeting prohibited remote UNC paths
                if abs_file.is_symlink():
                    try:
                        link_target = os.readlink(abs_file)
                        from offtest.intake.intake import is_unc_or_remote_path
                        if is_unc_or_remote_path(link_target):
                            continue
                    except OSError:
                        pass
                rel_file = os.path.normpath(os.path.join(rel_root, fname)).replace("\\", "/")

                summary.total_files += 1

                disp, reason, lang, cat = classify_file(rel_file, abs_file)

                # Compute hash and size
                try:
                    size = abs_file.stat().st_size
                except Exception:
                    size = 0

                file_hash = compute_sha256(abs_file)
                line_count = count_lines(abs_file) if disp == FileDisposition.ANALYZED else None

                record = FileRecord(
                    path=rel_file,
                    size_bytes=size,
                    sha256=file_hash,
                    language=lang,
                    category=cat,
                    disposition=disp,
                    disposition_reason=reason,
                    line_count=line_count,
                )
                files.append(record)

                # Update summary statistics
                if disp == FileDisposition.ANALYZED:
                    summary.analyzed_count += 1
                elif disp == FileDisposition.EXCLUDED:
                    summary.excluded_count += 1
                elif disp == FileDisposition.GENERATED:
                    summary.generated_count += 1
                elif disp == FileDisposition.BINARY:
                    summary.binary_count += 1
                elif disp == FileDisposition.UNSUPPORTED:
                    summary.unsupported_count += 1
                elif disp == FileDisposition.FAILED_TO_INSPECT:
                    summary.failed_to_inspect_count += 1

                if lang:
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1

                if cat == "test":
                    test_files_count += 1
                elif cat == "entry_point":
                    entry_points.append(rel_file)

                # Detect build systems and package managers
                lower_name = fname.lower()
                if lower_name == "package.json":
                    build_systems.add("npm/Node.js")
                    package_managers.add("npm")
                elif lower_name == "yarn.lock":
                    package_managers.add("yarn")
                elif lower_name == "pnpm-lock.yaml":
                    package_managers.add("pnpm")
                elif lower_name in ["requirements.txt", "setup.py"]:
                    build_systems.add("Python Setuptools/Pip")
                    package_managers.add("pip")
                elif lower_name == "pyproject.toml":
                    build_systems.add("Python PEP 517 / Poetry / Flit")
                elif lower_name == "cargo.toml":
                    build_systems.add("Cargo")
                    package_managers.add("cargo")
                elif lower_name == "go.mod":
                    build_systems.add("Go Modules")
                    package_managers.add("go")
                elif lower_name == "pom.xml":
                    build_systems.add("Maven")
                    package_managers.add("mvn")
                elif lower_name in ["build.gradle", "build.gradle.kts"]:
                    build_systems.add("Gradle")
                    package_managers.add("gradle")
                elif lower_name == "makefile":
                    build_systems.add("GNU Make")
                elif lower_name == "dockerfile":
                    build_systems.add("Docker Container")

        # Framework heuristics from files discovered
        for f in files:
            path_lower = f.path.lower()
            if "fastapi" in path_lower:
                frameworks.add("FastAPI")
            if "flask" in path_lower:
                frameworks.add("Flask")
            if "django" in path_lower or "manage.py" in path_lower:
                frameworks.add("Django")
            if "next.config" in path_lower or "app/page." in path_lower or "pages/index." in path_lower:
                frameworks.add("Next.js")
            if "nuxt.config" in path_lower:
                frameworks.add("Nuxt.js")
            if "angular.json" in path_lower:
                frameworks.add("Angular")

        # Content inspections for frameworks in key config/source files
        for f in files:
            if f.path.endswith("package.json") and f.size_bytes < 500000:
                try:
                    with open(self.repo_dir / f.path, "r", encoding="utf-8", errors="ignore") as pf:
                        content = pf.read()
                        if '"express"' in content:
                            frameworks.add("Express")
                        if '"react"' in content:
                            frameworks.add("React")
                        if '"vue"' in content:
                            frameworks.add("Vue.js")
                        if '"@nestjs/core"' in content:
                            frameworks.add("NestJS")
                except Exception:
                    pass
            elif (f.path.endswith("requirements.txt") or f.path.endswith("pyproject.toml")) and f.size_bytes < 500000:
                try:
                    with open(self.repo_dir / f.path, "r", encoding="utf-8", errors="ignore") as rf:
                        content = rf.read().lower()
                        if "fastapi" in content:
                            frameworks.add("FastAPI")
                        if "flask" in content:
                            frameworks.add("Flask")
                        if "django" in content:
                            frameworks.add("Django")
                        if "starlette" in content:
                            frameworks.add("Starlette")
                except Exception:
                    pass

        summary.languages = lang_counts
        summary.frameworks = sorted(list(frameworks))
        summary.build_systems = sorted(list(build_systems))
        summary.package_managers = sorted(list(package_managers))
        summary.entry_points = sorted(entry_points)
        summary.test_files_count = test_files_count

        return files, summary
