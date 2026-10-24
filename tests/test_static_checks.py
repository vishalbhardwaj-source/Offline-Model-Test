import tempfile
from pathlib import Path
from offtest.checks.static_checks import OfflineStaticChecker
from offtest.core.models import Severity
from offtest.inventory.engine import InventoryEngine


def test_offline_static_checker_flaws():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        insecure_py = tmp_path / "flawed.py"
        code = """
import os
import yaml

DEBUG = True

def run_command(user_input):
    eval(user_input)
    os.system("echo " + user_input)
    yaml.load(user_input)
"""
        insecure_py.write_text(code, encoding="utf-8")

        # Unpinned requirements
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests\nflask>=2.0\n", encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()

        titles = [f.title for f in findings]
        assert any("eval" in t for t in titles)
        assert any("os.system" in t for t in titles)
        assert any("DEBUG" in t for t in titles)
        assert any("YAML" in t for t in titles)
        assert any("Unpinned" in t for t in titles)


def test_utf8_bom_handling_not_flagged_as_high_syntax_error():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # File with 3-byte UTF-8 BOM followed by valid Python code
        bom_file = tmp_path / "script_with_bom.py"
        bom_file.write_bytes(b"\xef\xbb\xbfimport math\n\ndef calc(x):\n    return math.sqrt(x)\n")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()

        syntax_errors = [f for f in findings if "Syntax Error" in f.title]
        bom_findings = [f for f in findings if "UTF-8 BOM" in f.title]

        # Must NOT produce a High severity SyntaxError
        assert len(syntax_errors) == 0
        # Must detect BOM as Low severity observation
        assert len(bom_findings) == 1
        assert bom_findings[0].severity == Severity.LOW

