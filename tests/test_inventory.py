import tempfile
from pathlib import Path
from offtest.core.models import FileDisposition
from offtest.inventory.classifier import classify_file
from offtest.inventory.engine import InventoryEngine


def test_classify_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Python source
        py_file = tmp_path / "app.py"
        py_file.write_text("print('hello')", encoding="utf-8")
        disp, reason, lang, cat = classify_file("app.py", py_file)
        assert disp == FileDisposition.ANALYZED
        assert lang == "Python"
        assert cat == "entry_point"

        # Binary file
        bin_file = tmp_path / "image.png"
        bin_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
        disp, reason, lang, cat = classify_file("image.png", bin_file)
        assert disp == FileDisposition.BINARY

        # Generated file
        min_file = tmp_path / "bundle.min.js"
        min_file.write_text("console.log('min');", encoding="utf-8")
        disp, reason, lang, cat = classify_file("bundle.min.js", min_file)
        assert disp == FileDisposition.GENERATED

        # Excluded file (.git)
        git_file = tmp_path / ".git" / "HEAD"
        git_file.parent.mkdir(parents=True, exist_ok=True)
        git_file.write_text("ref: refs/heads/main", encoding="utf-8")
        disp, reason, lang, cat = classify_file(".git/HEAD", git_file)
        assert disp == FileDisposition.EXCLUDED


def test_inventory_engine():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.js").write_text("console.log('test');", encoding="utf-8")
        (tmp_path / "package.json").write_text('{"name": "test-app", "dependencies": {"express": "^4.18.2"}}', encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, summary = engine.scan()

        assert summary.total_files == 2
        assert summary.analyzed_count == 2
        assert "npm/Node.js" in summary.build_systems
        assert "Express" in summary.frameworks
