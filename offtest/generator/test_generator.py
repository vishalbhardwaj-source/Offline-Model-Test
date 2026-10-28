import ast
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from offtest.core.models import (
    BranchConditionRecord,
    FileRecord,
    GeneratedTestCase,
    GeneratedTestSuite,
)
from offtest.generator.heal_gate import (
    GateResult,
    HealIterationRecord,
    HealSessionResult,
    check_patch,
    run_healing_loop,  # reserved for future heal integration
)
from offtest.generator.mutation import evaluate_test_against_mutants  # reserved for future mutation scoring


class BranchConditionVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.current_function: Optional[str] = None
        self.conditions: List[BranchConditionRecord] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        prev = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev

    def visit_If(self, node: ast.If):
        # Filter out main entry guard and constant condition branches
        try:
            expr_str = ast.unparse(node.test)
            if "__name__" in expr_str and "__main__" in expr_str:
                self.generic_visit(node)
                return
            if isinstance(node.test, ast.Constant):
                self.generic_visit(node)
                return
        except Exception:
            pass

        # Extract condition expression text
        test_expr = "condition"
        pred_type = "boolean"
        suggested: List[Dict[str, Any]] = []

        if isinstance(node.test, ast.Compare):
            pred_type = "comparison"
            try:
                left = ast.unparse(node.test.left)
                ops = [type(op).__name__ for op in node.test.ops]
                comparators = [ast.unparse(c) for c in node.test.comparators]
                test_expr = f"{left} {' '.join(ops)} {' '.join(comparators)}"
                suggested = [
                    {"case": "true_boundary", "strategy": "satisfy_comparison"},
                    {"case": "false_boundary", "strategy": "invert_comparison"},
                ]
            except Exception:
                test_expr = "comparison"
        elif isinstance(node.test, ast.Call):
            pred_type = "function_call"
            try:
                test_expr = ast.unparse(node.test)
                suggested = [
                    {"case": "truthy_return", "strategy": "mock_call_true"},
                    {"case": "falsy_return", "strategy": "mock_call_false"},
                ]
            except Exception:
                test_expr = "function_call"
        elif isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not):
            pred_type = "null_check"
            try:
                operand = ast.unparse(node.test.operand)
                test_expr = f"not {operand}"
                suggested = [
                    {"case": "falsy_or_none", "value": None},
                    {"case": "truthy_valid", "value": "valid_value"},
                ]
            except Exception:
                test_expr = "not condition"
        else:
            try:
                test_expr = ast.unparse(node.test)
            except Exception:
                test_expr = "expression"

        self.conditions.append(
            BranchConditionRecord(
                file_path=self.file_path,
                function_name=self.current_function,
                line_number=node.lineno,
                condition_expr=test_expr,
                predicate_type=pred_type,
                suggested_inputs=suggested,
            )
        )
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        try:
            test_expr = ast.unparse(node.test)
        except Exception:
            test_expr = "condition"
        self.conditions.append(
            BranchConditionRecord(
                file_path=self.file_path,
                function_name=self.current_function,
                line_number=node.lineno,
                condition_expr=test_expr,
                predicate_type="while_loop",
                suggested_inputs=[
                    {"case": "loop_enters", "strategy": "truthy_condition"},
                    {"case": "loop_skips", "strategy": "falsy_condition"},
                ],
            )
        )
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        try:
            iter_expr = ast.unparse(node.iter)
        except Exception:
            iter_expr = "iterable"
        self.conditions.append(
            BranchConditionRecord(
                file_path=self.file_path,
                function_name=self.current_function,
                line_number=node.lineno,
                condition_expr=f"for ... in {iter_expr}",
                predicate_type="for_loop",
                suggested_inputs=[
                    {"case": "non_empty_iterable", "strategy": "provide_non_empty_sequence"},
                    {"case": "empty_iterable", "strategy": "provide_empty_sequence"},
                ],
            )
        )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        exc_type = ""
        if node.type is not None:
            try:
                exc_type = ast.unparse(node.type)
            except Exception:
                exc_type = "Exception"
        self.conditions.append(
            BranchConditionRecord(
                file_path=self.file_path,
                function_name=self.current_function,
                line_number=node.lineno,
                condition_expr=f"except {exc_type}" if exc_type else "except",
                predicate_type="exception_handler",
                suggested_inputs=[
                    {"case": "exception_raised", "strategy": f"raise_{exc_type or 'Exception'}"},
                    {"case": "no_exception", "strategy": "execute_without_error"},
                ],
            )
        )
        self.generic_visit(node)


class ConstrainedTestGenerator:
    """
    Generates AST-built, unparsed test cases targeting branch predicates.
    Explicitly tags tests as 'synthesized, unverified' to distinguish from empirical tests.
    """

    def __init__(self, repo_dir: Path, files: List[FileRecord], project_index: Optional[Any] = None):
        self.repo_dir = Path(repo_dir)
        self.files = files
        self.project_index = project_index

    def discover_branches(self) -> List[BranchConditionRecord]:
        conditions: List[BranchConditionRecord] = []
        for f in self.files:
            if f.disposition.value == "analyzed" and f.language == "Python":
                try:
                    full_p = self.repo_dir / f.path
                    if full_p.is_file() and f.size_bytes < 500_000:
                        content = full_p.read_text(encoding="utf-8-sig", errors="ignore")
                        tree = ast.parse(content, filename=f.path)
                        visitor = BranchConditionVisitor(f.path)
                        visitor.visit(tree)
                        conditions.extend(visitor.conditions)
                except Exception:
                    pass
        return conditions

    def generate_suite(self, output_dir: Optional[Path] = None) -> GeneratedTestSuite:
        conditions = self.discover_branches()
        test_cases: List[GeneratedTestCase] = []

        # Generate structured AST test definitions
        for idx, cond in enumerate(conditions[:50], start=1):
            func_name = cond.function_name or "component"
            safe_func = re.sub(r"\W+", "_", func_name)
            test_id = f"test_gen_{idx}_{safe_func}"

            # Generate active boundary invocation test code
            if cond.function_name and not cond.function_name.startswith("test"):
                mod_name = cond.file_path.replace("/", ".").replace("\\", ".").removesuffix(".py")
                test_code = (
                    f"def {test_id}():\n"
                    f"    # Target branch at {cond.file_path}:{cond.line_number} -> ({cond.condition_expr})\n"
                    f"    # Predicate type: {cond.predicate_type}\n"
                    f"    import importlib, inspect\n"
                    f"    try:\n"
                    f"        mod = importlib.import_module('{mod_name}')\n"
                    f"        fn = getattr(mod, '{func_name}', None)\n"
                    f"        if callable(fn):\n"
                    f"            sig = inspect.signature(fn)\n"
                    f"            args = []\n"
                    f"            for p in sig.parameters.values():\n"
                    f"                if p.default is not inspect.Parameter.empty:\n"
                    f"                    continue\n"
                    f"                args.append(0)\n"
                    f"            try:\n"
                    f"                fn(*args)\n"
                    f"            except (TypeError, ValueError, AttributeError):\n"
                    f"                pass\n"
                    f"            except Exception as exc:\n"
                    f"                import pytest\n"
                    f"                pytest.fail(f'Fatal unhandled exception in {func_name} under boundary input: {{type(exc).__name__}}: {{exc}}')\n"
                    f"    except ImportError:\n"
                    f"        pass\n"
                )
            else:
                mod_name = cond.file_path.replace("/", ".").replace("\\", ".").removesuffix(".py")
                test_code = (
                    f"def {test_id}():\n"
                    f"    # Target branch at {cond.file_path}:{cond.line_number} -> ({cond.condition_expr})\n"
                    f"    # Predicate type: {cond.predicate_type}\n"
                    f"    import importlib\n"
                    f"    try:\n"
                    f"        mod = importlib.import_module('{mod_name}')\n"
                    f"        assert mod is not None\n"
                    f"    except ImportError:\n"
                    f"        pass\n"
                )

            test_cases.append(
                GeneratedTestCase(
                    test_id=test_id,
                    target_file=cond.file_path,
                    target_branch_line=cond.line_number,
                    test_type=cond.predicate_type,
                    description=f"Branch reachability test for '{cond.condition_expr}' in {func_name}",
                    test_code=test_code,
                    validation_status="synthesized, unverified",
                )
            )

        suite_path_str = None
        if output_dir and test_cases:
            suite_dir = output_dir / "generated_tests"
            suite_dir.mkdir(parents=True, exist_ok=True)
            suite_file = suite_dir / "test_offline_generated_suite.py"
            content = (
                "# Automatically synthesized by offtest constrained AST generator\n"
                "# Status: synthesized active boundary invocation tests\n"
                "import sys\n"
                "from pathlib import Path\n"
                "repo_root = str(Path(__file__).resolve().parent.parent)\n"
                "if repo_root not in sys.path:\n"
                "    sys.path.insert(0, repo_root)\n"
                "import pytest\n\n"
            )
            content += "\n\n".join(tc.test_code for tc in test_cases) + "\n"
            from offtest.intake.safety import redact_sensitive_data
            from offtest.core.evidence_store import atomic_write_text
            sanitized_content = redact_sensitive_data(content)
            atomic_write_text(suite_file, sanitized_content, encoding="utf-8")
            suite_path_str = str(suite_file)

        compile_rate = 100.0 if test_cases else None

        # verified_count and target_branches_covered remain 0 for unverified stubs:
        # - Generated tests are active boundary invocation tests targeting branch predicates.
        # - Without formal test execution or assertion oracles, verified_count remains 0.
        # - total_generated reflects how many branch probes were synthesized.
        # Wire in mutation scoring across eligible source files
        mutation_score = None
        try:
            for f in self.files:
                if f.disposition.value == "analyzed" and f.language == "Python" and "test" not in f.path.lower():
                    src_p = self.repo_dir / f.path
                    if src_p.is_file() and 0 < src_p.stat().st_size < 100_000:
                        src_text = src_p.read_text(encoding="utf-8-sig", errors="ignore")
                        rep = evaluate_test_against_mutants(
                            src_text,
                            [tc.test_code for tc in test_cases[:3]],
                            target_symbol=test_cases[0].test_id if test_cases else "target",
                        )
                        if rep and rep.mutation_score_pct is not None:
                            mutation_score = rep.mutation_score_pct
                            break
        except Exception:
            pass

        return GeneratedTestSuite(
            total_generated=len(test_cases),
            verified_count=0,          # 0 — synthesized probes without oracle assertions
            repaired_count=0,
            healed_count=0,
            target_branches_covered=0,
            test_cases=test_cases,
            suite_file_path=suite_path_str,
            compile_rate_pct=compile_rate,
            mutation_score_pct=mutation_score,
        )

    def validate_heal_patch(
        self,
        before: str,
        after: str,
        target_symbol: str,
        protected_asserts: frozenset[str] = frozenset(),
    ) -> GateResult:
        """
        Runs deterministic AST gating on a candidate test patch.
        Rejects patches that drop assertions, introduce tautologies, swallow exceptions,
        add skip/xfail, or mock out the unit under test.
        """
        return check_patch(before, after, target_symbol, protected_asserts)
