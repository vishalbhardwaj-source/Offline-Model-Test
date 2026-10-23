import json
from pathlib import Path
from offtest.core.models import FileDisposition, FileRecord
from offtest.inventory.sbom import SBOMGenerator


def test_sbom_generation_package_json(tmp_path: Path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        json.dumps({
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "4.17.21"
            },
            "devDependencies": {
                "jest": "^29.5.0"
            }
        }),
        encoding="utf-8"
    )

    files = [
        FileRecord(
            path="package.json",
            size_bytes=len(pkg_json.read_bytes()),
            sha256="abc",
            category="build",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Config",
        )
    ]

    generator = SBOMGenerator(tmp_path, files)
    report = generator.generate()

    assert report.total_dependencies == 3
    assert report.direct_dependencies == 3
    assert "npm" in report.ecosystems
    comp_names = {c.name for c in report.components}
    assert "express" in comp_names
    assert "lodash" in comp_names
    assert "jest" in comp_names


def test_sbom_generation_requirements_txt(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "flask==2.2.5\npydantic>=2.0.0\npytest~=8.0.0\n# comment\n",
        encoding="utf-8"
    )

    files = [
        FileRecord(
            path="requirements.txt",
            size_bytes=len(req_file.read_bytes()),
            sha256="def",
            category="build",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Config",
        )
    ]

    generator = SBOMGenerator(tmp_path, files)
    report = generator.generate()

    assert report.total_dependencies == 3
    assert "pypi" in report.ecosystems
    names = {c.name for c in report.components}
    assert "flask" in names
    assert "pydantic" in names
    assert "pytest" in names
