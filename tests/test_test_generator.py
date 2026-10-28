from pathlib import Path
from offtest.core.models import FileDisposition, FileRecord
from offtest.generator.test_generator import ConstrainedTestGenerator


def test_constrained_test_generator(tmp_path: Path):
    calc_py = tmp_path / "calc.py"
    calc_py.write_text(
        """
def process_order(price, discount):
    if price < 0:
        raise ValueError("Invalid price")
    if discount is not None:
        return price - discount
    return price
""",
        encoding="utf-8"
    )

    files = [
        FileRecord(
            path="calc.py",
            size_bytes=len(calc_py.read_bytes()),
            sha256="abc",
            language="Python",
            category="source",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Source",
        )
    ]

    generator = ConstrainedTestGenerator(tmp_path, files)
    branches = generator.discover_branches()

    assert len(branches) >= 2
    comp_branch = [b for b in branches if b.predicate_type == "comparison"]
    assert len(comp_branch) >= 1
    assert comp_branch[0].function_name == "process_order"

    suite = generator.generate_suite(output_dir=tmp_path)
    assert suite.total_generated >= 2
    # Skipped probe tests are not considered verified or covered without an oracle
    assert suite.verified_count == 0
    assert suite.target_branches_covered == 0
    assert suite.suite_file_path is not None
    assert Path(suite.suite_file_path).is_file()
