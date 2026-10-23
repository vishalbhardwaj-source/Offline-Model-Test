import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from offtest.core.models import FileRecord, SBOMComponent, SBOMReport


class SBOMGenerator:
    """Generates an offline Software Bill of Materials (SBOM) in CycloneDX format from repository lockfiles."""

    def __init__(self, repo_dir: Path, files: List[FileRecord]):
        self.repo_dir = repo_dir
        self.files = files

    def generate(self) -> SBOMReport:
        components: List[SBOMComponent] = []
        file_map: Dict[str, FileRecord] = {f.path: f for f in self.files}

        # 1. NPM: package-lock.json (v2/v3 and v1)
        if "package-lock.json" in file_map:
            try:
                full_path = self.repo_dir / "package-lock.json"
                data = json.loads(full_path.read_text(encoding="utf-8", errors="ignore"))
                # v2/v3 packages
                packages = data.get("packages", {})
                if packages:
                    for pkg_key, pkg_info in packages.items():
                        if not pkg_key:  # root project
                            continue
                        name = pkg_info.get("name") or pkg_key.replace("node_modules/", "")
                        version = pkg_info.get("version", "unknown")
                        license_name = pkg_info.get("license")
                        is_direct = not pkg_key.startswith("node_modules/") or pkg_key.count("node_modules/") == 1
                        components.append(
                            SBOMComponent(
                                name=name,
                                version=version,
                                ecosystem="npm",
                                license=license_name,
                                purl=f"pkg:npm/{name}@{version}",
                                source_file="package-lock.json",
                                direct=is_direct,
                            )
                        )
                elif "dependencies" in data:  # v1 lockfile
                    for name, info in data["dependencies"].items():
                        version = info.get("version", "unknown")
                        components.append(
                            SBOMComponent(
                                name=name,
                                version=version,
                                ecosystem="npm",
                                purl=f"pkg:npm/{name}@{version}",
                                source_file="package-lock.json",
                                direct=True,
                            )
                        )
            except Exception:
                pass

        # 2. NPM: package.json (fallback if no lockfile or for direct deps)
        if "package.json" in file_map and not any(c.source_file == "package-lock.json" for c in components):
            try:
                full_path = self.repo_dir / "package.json"
                data = json.loads(full_path.read_text(encoding="utf-8", errors="ignore"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for name, ver in deps.items():
                    clean_ver = str(ver).lstrip("^~>=<")
                    components.append(
                        SBOMComponent(
                            name=name,
                            version=clean_ver,
                            ecosystem="npm",
                            purl=f"pkg:npm/{name}@{clean_ver}",
                            source_file="package.json",
                            direct=True,
                        )
                    )
            except Exception:
                pass

        # 3. Python: requirements.txt (or requirements/*.txt)
        req_pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([a-zA-Z0-9_\-\.]+)")
        for f in self.files:
            if "requirements" in f.path.lower() and f.path.endswith(".txt"):
                try:
                    full_path = self.repo_dir / f.path
                    lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith("-"):
                            continue
                        m = req_pattern.match(line)
                        if m:
                            name, version = m.group(1), m.group(2)
                            components.append(
                                SBOMComponent(
                                    name=name,
                                    version=version,
                                    ecosystem="pypi",
                                    purl=f"pkg:pypi/{name.lower()}@{version}",
                                    source_file=f.path,
                                    direct=True,
                                )
                            )
                except Exception:
                    pass

        # 4. Python: poetry.lock
        if "poetry.lock" in file_map:
            try:
                full_path = self.repo_dir / "poetry.lock"
                text = full_path.read_text(encoding="utf-8", errors="ignore")
                blocks = text.split("[[package]]")
                for block in blocks[1:]:
                    name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
                    ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
                    if name_m and ver_m:
                        name, version = name_m.group(1), ver_m.group(1)
                        components.append(
                            SBOMComponent(
                                name=name,
                                version=version,
                                ecosystem="pypi",
                                purl=f"pkg:pypi/{name.lower()}@{version}",
                                source_file="poetry.lock",
                                direct=True,
                            )
                        )
            except Exception:
                pass

        # 5. Rust: Cargo.lock
        if "Cargo.lock" in file_map:
            try:
                full_path = self.repo_dir / "Cargo.lock"
                text = full_path.read_text(encoding="utf-8", errors="ignore")
                blocks = text.split("[[package]]")
                for block in blocks[1:]:
                    name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
                    ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
                    if name_m and ver_m:
                        name, version = name_m.group(1), ver_m.group(1)
                        components.append(
                            SBOMComponent(
                                name=name,
                                version=version,
                                ecosystem="cargo",
                                purl=f"pkg:cargo/{name}@{version}",
                                source_file="Cargo.lock",
                                direct=True,
                            )
                        )
            except Exception:
                pass

        # Deduplicate components by (ecosystem, name, version)
        unique_components: List[SBOMComponent] = []
        seen = set()
        for c in components:
            key = (c.ecosystem, c.name.lower(), c.version)
            if key not in seen:
                seen.add(key)
                unique_components.append(c)

        direct_count = sum(1 for c in unique_components if c.direct)
        ecosystems = sorted(list({c.ecosystem for c in unique_components}))

        return SBOMReport(
            spec_version="CycloneDX-1.5",
            total_dependencies=len(unique_components),
            direct_dependencies=direct_count,
            ecosystems=ecosystems,
            components=unique_components,
        )
