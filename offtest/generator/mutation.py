"""offtest/generator/mutation.py

AST-based mutation testing engine for validating generated test quality.
Mutates source conditionals, boundary operators, and return values to measure
whether generated tests actually catch defects or pass trivially (mutation score).
"""
from __future__ import annotations

import ast
import copy
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
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
    interpretation: str = "Empirical floor metric (equivalent mutants prevent theoretical 100% score)"


class ASTMutator(ast.NodeTransformer):
    """
    Generates fine-grained boundary AST mutations:
    - Off-by-one comparison mutations (< to <=, > to >=, <= to <, >= to >)
    - Equality inversions (== to !=, != to ==)
    - Boolean operator swapping (and to or, or to and)
    - Constant value boundary offsets (+1, -1)
    - Return value nullification (return expr to return None)
    """

    OFF_BY_ONE_COMPARISONS = {
        ast.Lt: ast.LtE,
        ast.Gt: ast.GtE,
        ast.LtE: ast.Lt,
        ast.GtE: ast.Gt,
        ast.Eq: ast.NotEq,
        ast.NotEq: ast.Eq,
    }


def generate_mutants(source_code: str, target_function: Optional[str] = None) -> List[Mutant]:
    """Generates fine-grained boundary mutants for a given source code string."""
    try:
        base_tree = ast.parse(source_code)
    except SyntaxError:
        return []

    mutants: List[Mutant] = []
    mutant_idx = 1

    # 1. Boundary & off-by-one comparison mutations
    for node in ast.walk(base_tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            op_cls = type(node.ops[0])
            if op_cls in ASTMutator.OFF_BY_ONE_COMPARISONS:
                mutated_op = ASTMutator.OFF_BY_ONE_COMPARISONS[op_cls]()
                cloned = copy.deepcopy(base_tree)
                for c_node in ast.walk(cloned):
                    if (
                        isinstance(c_node, ast.Compare)
                        and getattr(c_node, "lineno", -1) == getattr(node, "lineno", -2)
                        and len(c_node.ops) == 1
                        and isinstance(c_node.ops[0], op_cls)
                    ):
                        c_node.ops = [mutated_op]
                        mutants.append(
                            Mutant(
                                mutant_id=f"MUT-{mutant_idx:03d}",
                                original_line=getattr(node, "lineno", 1),
                                mutation_type=f"Boundary_{op_cls.__name__}_to_{type(mutated_op).__name__}",
                                description=f"Mutated operator {op_cls.__name__} to {type(mutated_op).__name__} at line {getattr(node, 'lineno', 1)}",
                                mutated_ast=cloned,
                            )
                        )
                        mutant_idx += 1
                        break

        # 2. Boolean operator swap (and <-> or)
        elif isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                new_op = ast.Or()
            elif isinstance(node.op, ast.Or):
                new_op = ast.And()
            else:
                new_op = None

            if new_op:
                cloned = copy.deepcopy(base_tree)
                for c_node in ast.walk(cloned):
                    if (
                        isinstance(c_node, ast.BoolOp)
                        and getattr(c_node, "lineno", -1) == getattr(node, "lineno", -2)
                    ):
                        c_node.op = new_op
                        mutants.append(
                            Mutant(
                                mutant_id=f"MUT-{mutant_idx:03d}",
                                original_line=getattr(node, "lineno", 1),
                                mutation_type=f"BoolOp_{type(node.op).__name__}_to_{type(new_op).__name__}",
                                description=f"Swapped boolean operator at line {getattr(node, 'lineno', 1)}",
                                mutated_ast=cloned,
                            )
                        )
                        mutant_idx += 1
                        break

        # 3. Constant numeric boundary offset (+1)
        elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            cloned = copy.deepcopy(base_tree)
            for c_node in ast.walk(cloned):
                if (
                    isinstance(c_node, ast.Constant)
                    and getattr(c_node, "lineno", -1) == getattr(node, "lineno", -2)
                    and c_node.value == node.value
                ):
                    c_node.value = node.value + 1
                    mutants.append(
                        Mutant(
                            mutant_id=f"MUT-{mutant_idx:03d}",
                            original_line=getattr(node, "lineno", 1),
                            mutation_type="ConstantOffset_Plus1",
                            description=f"Offset constant {node.value} to {node.value + 1} at line {getattr(node, 'lineno', 1)}",
                            mutated_ast=cloned,
                        )
                    )
                    mutant_idx += 1
                    break

        # 4. Return value nullification
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
    timeout_sec: float = 3.0,
    module_name: str = "target_module",
) -> MutationReport:
    """
    Executes generated test assertions against synthesized mutants in an isolated temporary subprocess.
    Uses subprocess execution with a strict timeout to ensure mutant infinite loops do not hang the runner,
    and isolates sys.modules so the test imports the mutated code rather than a cached module.
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

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_p = Path(tmp_dir)

        for m in mutants:
            mutant_src = ast.unparse(m.mutated_ast)
            module_file = tmp_p / f"{module_name}.py"
            module_file.write_text(mutant_src, encoding="utf-8")

            # Harness script running the test against the mutated module
            runner_script = tmp_p / "run_mutation_test.py"
            runner_content = f"""
import sys
from pathlib import Path
sys.path.insert(0, r"{str(tmp_p)}")
import {module_name}
from {module_name} import *

# Injected test code
{test_code}

# Run all test functions defined
current_ns = dict(locals())
for k, v in current_ns.items():
    if k.startswith("test_") and callable(v):
        v()
"""
            runner_script.write_text(runner_content, encoding="utf-8")

            try:
                # Subprocess with timeout protects against mutant infinite loops
                proc = subprocess.run(
                    [sys.executable, "-B", str(runner_script)],
                    cwd=tmp_dir,
                    capture_output=True,
                    timeout=timeout_sec,
                )
                if proc.returncode == 0:
                    # Test passed against mutant -> mutant SURVIVED (weak/tautological test)
                    survived += 1
                    status = "survived"
                else:
                    # Test failed or raised AssertionError -> mutant KILLED (effective test)
                    killed += 1
                    status = "killed"
            except subprocess.TimeoutExpired:
                # Mutant introduced an infinite loop/hang caught by timeout -> KILLED
                killed += 1
                status = "killed (timeout)"
            except Exception:
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
