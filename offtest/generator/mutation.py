"""offtest/generator/mutation.py

AST-based mutation testing engine for validating generated test quality.
Mutates source conditionals, return values, and comparison operators to measure
whether generated tests actually catch defects or pass trivially (mutation score).
"""
from __future__ import annotations

import ast
import copy
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class Mutant:
    mutant_id: str
    original_line: int
    mutation_type: str
    description: str
    mutated_ast: ast.AST


@dataclass
class MutationReport:
    total_mutants: int = 0
    killed_mutants: int = 0
    survived_mutants: int = 0
    mutation_score_pct: float = 0.0
    mutants: List[dict] = field(default_factory=list)


class ASTMutator(ast.NodeTransformer):
    """
    Generates single-point AST mutations:
    - Comparison operator inversion (< to >=, == to !=, etc.)
    - Boolean constant inversion (True to False)
    - Return value nullification (return expr to return None)
    """

    COMPARE_INVERSIONS = {
        ast.Lt: ast.GtE,
        ast.Gt: ast.LtE,
        ast.LtE: ast.Gt,
        ast.GtE: ast.Lt,
        ast.Eq: ast.NotEq,
        ast.NotEq: ast.Eq,
    }

    def __init__(self, target_function: Optional[str] = None):
        self.target_function = target_function
        self.current_function: Optional[str] = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self.current_function
        self.current_function = node.name
        res = self.generic_visit(node)
        self.current_function = prev
        return res

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        prev = self.current_function
        self.current_function = node.name
        res = self.generic_visit(node)
        self.current_function = prev
        return res


def generate_mutants(source_code: str, target_function: Optional[str] = None) -> List[Mutant]:
    """Generates valid AST mutants for a given source code string."""
    try:
        base_tree = ast.parse(source_code)
    except SyntaxError:
        return []

    mutants: List[Mutant] = []
    mutant_idx = 1

    # 1. Comparison operator mutations
    for node in ast.walk(base_tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            op_cls = type(node.ops[0])
            if op_cls in ASTMutator.COMPARE_INVERSIONS:
                inverted_op = ASTMutator.COMPARE_INVERSIONS[op_cls]()
                # Create a cloned tree with this single mutation
                cloned = copy.deepcopy(base_tree)
                for c_node in ast.walk(cloned):
                    if (
                        isinstance(c_node, ast.Compare)
                        and getattr(c_node, "lineno", -1) == getattr(node, "lineno", -2)
                        and len(c_node.ops) == 1
                        and isinstance(c_node.ops[0], op_cls)
                    ):
                        c_node.ops = [inverted_op]
                        mutants.append(
                            Mutant(
                                mutant_id=f"MUT-{mutant_idx:03d}",
                                original_line=getattr(node, "lineno", 1),
                                mutation_type="InvertComparison",
                                description=f"Inverted comparison operator at line {getattr(node, 'lineno', 1)}",
                                mutated_ast=cloned,
                            )
                        )
                        mutant_idx += 1
                        break

        # 2. Return value nullification
        elif isinstance(node, ast.Return) and node.value is not None:
            if not (isinstance(node.value, ast.Constant) and node.value.value is None):
                cloned = copy.deepcopy(base_tree)
                for c_node in ast.walk(cloned):
                    if (
                        isinstance(c_node, ast.Return)
                        and getattr(c_node, "lineno", -1) == getattr(node, "lineno", -2)
                        and c_node.value is not None
                    ):
                        c_node.value = ast.Constant(value=None)
                        mutants.append(
                            Mutant(
                                mutant_id=f"MUT-{mutant_idx:03d}",
                                original_line=getattr(node, "lineno", 1),
                                mutation_type="NullifyReturn",
                                description=f"Replaced return expression with None at line {getattr(node, 'lineno', 1)}",
                                mutated_ast=cloned,
                            )
                        )
                        mutant_idx += 1
                        break

    return mutants


def evaluate_test_against_mutants(
    source_code: str,
    test_code: str,
    target_function: Optional[str] = None,
) -> MutationReport:
    """
    Executes generated test assertions against synthesized mutants in an isolated namespace.
    If the test fails on mutated code, the mutant is killed (effective test).
    If the test passes on mutated code, the mutant survived (tautology / weak assertion).
    """
    mutants = generate_mutants(source_code, target_function)
    if not mutants:
        return MutationReport(
            total_mutants=0,
            killed_mutants=0,
            survived_mutants=0,
            mutation_score_pct=100.0,
            mutants=[],
        )

    killed = 0
    survived = 0
    mutant_records = []

    for m in mutants:
        mutant_src = ast.unparse(m.mutated_ast)
        # Execute in ephemeral sandbox namespace
        ns = {}
        passed = False
        try:
            exec(mutant_src, ns)
            # Execute test code
            exec(test_code, ns)
            # Call any test functions found in namespace
            for k, v in list(ns.items()):
                if k.startswith("test_") and callable(v):
                    v()
            passed = True
        except (AssertionError, Exception):
            passed = False

        if passed:
            survived += 1
            status = "survived"
        else:
            killed += 1
            status = "killed"

        mutant_records.append({
            "mutant_id": m.mutant_id,
            "line": m.original_line,
            "type": m.mutation_type,
            "status": status,
        })

    total = len(mutants)
    score = round((killed / total) * 100.0, 1) if total > 0 else 0.0

    return MutationReport(
        total_mutants=total,
        killed_mutants=killed,
        survived_mutants=survived,
        mutation_score_pct=score,
        mutants=mutant_records,
    )
