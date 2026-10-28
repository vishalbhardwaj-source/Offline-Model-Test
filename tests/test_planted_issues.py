import tempfile
from pathlib import Path
from offtest.checks.static_checks import OfflineStaticChecker
from offtest.core.models import FileDisposition, FileRecord
from offtest.core.project_index import ProjectIndex
from offtest.discovery.app_mapper import ApplicationMapper
from offtest.generator.test_generator import ConstrainedTestGenerator
from offtest.inventory.engine import InventoryEngine


def test_planted_issues_detected_comprehensively():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Planted test file containing all scenarios
        app_code = """
import os

def never_called_helper(x):
    return x * 2

def noop_function():
    pass

def identity_func(val):
    return val

def broken_math(a, b):
    return a / (b - b)

def broken_undefined():
    return undefined_variable_xyz + 5

def constant_false_branch():
    if False:
        print("dead block")

class UnusedClass:
    def method(self):
        pass

def _private_unused():
    raise NotImplementedError("Not implemented")

@app.route("/cart/checkout", methods=["POST"])
def checkout_handler():
    return sum_prices([10, 20])

@app.route("/login", methods=["POST"])
def login_handler():
    return str("token_abc")

def sum_prices(items):
    if items:
        return sum(items)
    return 0

def test_something():
    assert 1 == 1

if __name__ == "__main__":
    print("entry")
"""
        (tmp_path / "app.py").write_text(app_code, encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        project_index = ProjectIndex(tmp_path, files)

        # 1. Verify ProjectIndex entries & reachability
        assert "app.py::never_called_helper" in [f"{s.file_path}::{s.qualified_name}" for s in project_index.unreachable_symbols]
        assert "app.py::UnusedClass" in [f"{s.file_path}::{s.qualified_name}" for s in project_index.unreachable_symbols]
        assert "app.py::_private_unused" in [f"{s.file_path}::{s.qualified_name}" for s in project_index.unreachable_symbols]

        # 2. Verify static checker catches undefined names, zero division, constant false, no-op, uncalled code
        checker = OfflineStaticChecker(tmp_path, files, project_index=project_index)
        findings = checker.run_all()
        titles = [f.title for f in findings]

        # Undefined name
        assert any("Undefined Name: 'undefined_variable_xyz'" in t for t in titles)
        # Regression test: Python builtins (print, sum, str, NotImplementedError) must NEVER be flagged as undefined
        assert not any("Undefined Name: 'print'" in t for t in titles)
        assert not any("Undefined Name: 'sum'" in t for t in titles)
        assert not any("Undefined Name: 'str'" in t for t in titles)
        assert not any("Undefined Name: 'NotImplementedError'" in t for t in titles)

        # Division by zero (b - b)
        assert any("Division by Zero" in t for t in titles)
        # Constant False condition
        assert any("Constant False Condition ('if False:')" in t for t in titles)
        # No-op functions
        assert any("No-Op Function: 'noop_function()'" in t for t in titles)
        assert any("No-Op Function: 'identity_func()'" in t for t in titles)
        # Unimplemented stub
        assert any("Unimplemented Function Stub: '_private_unused()'" in t for t in titles)
        # Uncalled dead code
        assert any("Uncalled Dead Code: Function 'never_called_helper'" in t for t in titles)
        assert any("Uncalled Dead Code: Class 'UnusedClass'" in t for t in titles)

        # Consolidate findings: broken_math, broken_undefined, constant_false_branch
        # should each produce exactly 1 consolidated finding (uncalled dead code + defect)
        broken_math_findings = [f for f in findings if "broken_math" in f.title or "broken_math" in f.evidence]
        assert len(broken_math_findings) == 1
        broken_undef_findings = [f for f in findings if "broken_undefined" in f.title or "broken_undefined" in f.evidence]
        assert len(broken_undef_findings) == 1

        # 3. Verify route parsing extracts POST (not ANY) and handler line number
        mapper = ApplicationMapper(tmp_path, files, project_index=project_index)
        routes, apis, features, workflows, integrations = mapper.map_application()

        checkout_routes = [r for r in routes if r.path == "/cart/checkout"]
        assert len(checkout_routes) == 1
        assert checkout_routes[0].method == "POST"
        assert checkout_routes[0].handler == "checkout_handler"
        assert checkout_routes[0].line_number > 1

        login_routes = [r for r in routes if r.path == "/login"]
        assert len(login_routes) == 1
        assert login_routes[0].method == "POST"
        assert login_routes[0].handler == "login_handler"
        assert login_routes[0].line_number > 1

        # 4. Verify code-derived workflows: trace checkout_handler -> sum_prices
        checkout_wfs = [w for w in workflows if "checkout" in w.entry_point.lower()]
        assert len(checkout_wfs) == 1
        assert checkout_wfs[0].symbolic_edges_verified is True
        assert any("sum_prices" in s for s in checkout_wfs[0].steps)

        # 5. Verify /login route gets its own code-derived workflow (NOT canned inferred auth)
        login_wfs = [w for w in workflows if "login" in w.entry_point.lower()]
        assert len(login_wfs) == 1
        from offtest.core.models import EvidenceStatus
        assert login_wfs[0].status == EvidenceStatus.OBSERVED
        assert login_wfs[0].symbolic_edges_verified is True
        assert not any(w.name == "User Authentication & Session Management" for w in workflows)

        # 6. Verify feature line numbers point to actual handler line numbers, NOT line 1 or line 9
        feat_checkout = next((f for f in features if "checkout" in f.name.lower()), None)
        assert feat_checkout is not None
        assert feat_checkout.line_number == checkout_routes[0].line_number

        feat_login = next((f for f in features if "login" in f.name.lower()), None)
        assert feat_login is not None
        assert feat_login.line_number == login_routes[0].line_number

        # 7. Verify test generator does NOT generate tests for if __name__ == '__main__' or if False
        generator = ConstrainedTestGenerator(tmp_path, files, project_index=project_index)
        branches = generator.discover_branches()
        cond_exprs = [b.condition_expr for b in branches]
        assert not any("__name__" in c for c in cond_exprs)
        assert not any(c == "False" or c == "0" for c in cond_exprs)

        # 8. Verify generated tests do NOT contain pytest.skip
        suite = generator.generate_suite(output_dir=tmp_path)
        assert suite.suite_file_path is not None
        suite_code = Path(suite.suite_file_path).read_text(encoding="utf-8")
        assert "pytest.skip" not in suite_code
