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

    def __init__(self, repo_dir: Path, files: List[FileRecord]):
        self.repo_dir = repo_dir
        self.files = files

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

            # Build valid Python AST directly rather than string concatenation
            doc_node = ast.Expr(
                value=ast.Constant(
                    value=f"Target branch at {cond.file_path}:{cond.line_number} -> ({cond.condition_expr})\nPredicate type: {cond.predicate_type}"
                )
            )
            # Emit pytest.skip so synthesized probe never produces a false-green pass without an oracle
            skip_node = ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=ast.Name(id="pytest", ctx=ast.Load()), attr="skip", ctx=ast.Load()),
                    args=[ast.Constant(value=f"Synthesized probe for {func_name}: no test oracle available")],
                    keywords=[],
                )
            )
            func_ast = ast.FunctionDef(
                name=test_id,
                args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                body=[doc_node, skip_node],
                decorator_list=[],
                lineno=1,
                col_offset=0,
            )
            ast.fix_missing_locations(func_ast)

            # Generate formatted code cleanly with ast.unparse
            test_code = ast.unparse(func_ast)

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
            content = "# Automatically synthesized by offtest constrained AST generator\n# Status: synthesized, unverified (demonstrates branch reachability only)\nimport pytest\n\n"
            content += "\n\n".join(tc.test_code for tc in test_cases) + "\n"
            from offtest.intake.safety import redact_sensitive_data
            from offtest.core.evidence_store import atomic_write_text
            sanitized_content = redact_sensitive_data(content)
            atomic_write_text(suite_file, sanitized_content, encoding="utf-8")
            suite_path_str = str(suite_file)

        compile_rate = 100.0 if test_cases else None

        # verified_count and target_branches_covered remain 0:
        # - All generated tests emit pytest.skip(), so none are executed or verified.
        # - Skipped probes identify branch predicates but do NOT constitute coverage.
        # - total_generated reflects how many branch probes were synthesized.
        return GeneratedTestSuite(
            total_generated=len(test_cases),
            verified_count=0,          # 0 — all probes are skipped, none oracle-verified
            repaired_count=0,
            healed_count=0,
            target_branches_covered=0,  # 0 — skipped != covered
            test_cases=test_cases,
            suite_file_path=suite_path_str,
            compile_rate_pct=compile_rate,  # 100% is correct — AST compiles cleanly
            mutation_score_pct=None,
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
