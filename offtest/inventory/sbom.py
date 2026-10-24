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
                                is_approximate_range=False,
                            )
                        )
                elif "dependencies" in data:
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
                                is_approximate_range=False,
                            )
                        )
            except Exception:
                pass

        # 2. NPM: yarn.lock
        if "yarn.lock" in file_map:
            try:
                full_path = self.repo_dir / "yarn.lock"
                text = full_path.read_text(encoding="utf-8", errors="ignore")
                # Simple yarn block matching
                for block in text.split("\n\n"):
                    lines = block.strip().splitlines()
                    if lines and not lines[0].startswith("#"):
                        header = lines[0].strip().rstrip(":")
                        name_m = re.match(r'^"?(@?[^@\s"]+)', header)
                        ver_m = None
                        for l in lines[1:]:
                            if l.strip().startswith("version "):
                                ver_m = l.strip().split()[1].strip('"')
                                break
                        if name_m and ver_m:
                            name = name_m.group(1)
                            components.append(
                                SBOMComponent(
                                    name=name,
                                    version=ver_m,
                                    ecosystem="npm",
                                    purl=f"pkg:npm/{name}@{ver_m}",
                                    source_file="yarn.lock",
                                    direct=True,
                                    is_approximate_range=False,
                                )
                            )
            except Exception:
                pass

        # 3. NPM: pnpm-lock.yaml
        if "pnpm-lock.yaml" in file_map:
            try:
                full_path = self.repo_dir / "pnpm-lock.yaml"
                text = full_path.read_text(encoding="utf-8", errors="ignore")
                for line in text.splitlines():
                    # Match packages: /name@version:
                    m = re.match(r"^\s+/?(@?[^@\s:]+)@([^:\s]+):", line)
                    if m:
                        name, version = m.group(1), m.group(2)
                        components.append(
                            SBOMComponent(
                                name=name,
                                version=version,
                                ecosystem="npm",
                                purl=f"pkg:npm/{name}@{version}",
                                source_file="pnpm-lock.yaml",
                                direct=True,
                                is_approximate_range=False,
                            )
                        )
            except Exception:
                pass

        # 4. NPM: package.json (fallback if no lockfile or for direct deps)
        if "package.json" in file_map and not any(c.source_file in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"] for c in components):
            try:
                full_path = self.repo_dir / "package.json"
                data = json.loads(full_path.read_text(encoding="utf-8", errors="ignore"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for name, ver in deps.items():
                    clean_ver = str(ver).lstrip("^~>=<")
                    is_range = any(char in str(ver) for char in ["^", "~", ">", "<", "*"])
                    components.append(
                        SBOMComponent(
                            name=name,
                            version=clean_ver,
                            ecosystem="npm",
                            purl=f"pkg:npm/{name}@{clean_ver}",
                            source_file="package.json",
                            direct=True,
                            is_approximate_range=is_range,
                        )
                    )
            except Exception:
                pass

        # 5. Python: requirements.txt
        req_pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)\s*(?:(==|>=|<=|~=|>|<)\s*([a-zA-Z0-9_\-\.]+))?")
        for f in self.files:
            if "requirements" in f.path.lower() and f.path.endswith(".txt"):
                try:
                    full_path = self.repo_dir / f.path
                    lines = full_path.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith("-"):
                            continue
                        line = line.split("#")[0].strip()
                        m = req_pattern.match(line)
                        if m:
                            name = m.group(1)
                            op = m.group(2)
                            version = m.group(3)
                            if op and version:
                                is_range = (op != "==")
                            else:
                                version = "unspecified"
                                is_range = True
                            components.append(
                                SBOMComponent(
                                    name=name,
                                    version=version,
                                    ecosystem="pypi",
                                    purl=f"pkg:pypi/{name.lower()}@{version}",
                                    source_file=f.path,
                                    direct=True,
                                    is_approximate_range=is_range,
                                )
                            )
                except Exception:
                    pass

        # 6. Python: poetry.lock
        if "poetry.lock" in file_map:
            try:
                full_path = self.repo_dir / "poetry.lock"
                text = full_path.read_text(encoding="utf-8", errors="ignore")
                for block in text.split("[[package]]")[1:]:
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
                                is_approximate_range=False,
                            )
                        )
            except Exception:
                pass

        # 7. Rust: Cargo.lock
        if "Cargo.lock" in file_map:
            try:
                full_path = self.repo_dir / "Cargo.lock"
                text = full_path.read_text(encoding="utf-8", errors="ignore")
                for block in text.split("[[package]]")[1:]:
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
                                is_approximate_range=False,
                            )
                        )
            except Exception:
                pass

        # 8. Go: go.mod
        if "go.mod" in file_map:
            try:
                full_path = self.repo_dir / "go.mod"
                text = full_path.read_text(encoding="utf-8", errors="ignore")
                in_require = False
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("require ("):
                        in_require = True
                        continue
                    if in_require and line.startswith(")"):
                        in_require = False
                        continue
                    if in_require or line.startswith("require "):
                        clean_line = line.replace("require ", "").strip()
                        parts = clean_line.split()
                        if len(parts) >= 2:
                            name, ver = parts[0], parts[1]
                            components.append(
                                SBOMComponent(
                                    name=name,
                                    version=ver,
                                    ecosystem="golang",
                                    purl=f"pkg:golang/{name}@{ver}",
                                    source_file="go.mod",
                                    direct=True,
                                    is_approximate_range=False,
                                )
                            )
            except Exception:
                pass

        # 9. PHP: composer.lock
        if "composer.lock" in file_map:
            try:
                full_path = self.repo_dir / "composer.lock"
                data = json.loads(full_path.read_text(encoding="utf-8", errors="ignore"))
                packages = data.get("packages", []) + data.get("packages-dev", [])
                for pkg in packages:
                    name = pkg.get("name")
                    version = pkg.get("version", "").lstrip("v")
                    license_name = ", ".join(pkg.get("license", [])) if pkg.get("license") else None
                    if name:
                        components.append(
                            SBOMComponent(
                                name=name,
                                version=version,
                                ecosystem="composer",
                                license=license_name,
                                purl=f"pkg:composer/{name}@{version}",
                                source_file="composer.lock",
                                direct=True,
                                is_approximate_range=False,
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
