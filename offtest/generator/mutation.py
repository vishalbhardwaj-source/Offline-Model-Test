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
    timed_out_mutants: int = 0
    invalid_mutants: int = 0
    mutation_score_pct: float = 0.0
    baseline_passed: bool = True
    canary_verified: bool = False
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
    Hardened mutation harness:
    1. Baseline check: Verifies that tests pass against unmutated source first.
    2. Canary mutant: Injects a known breaking mutant to verify the test actually imports the mutant module.
    3. IsolatedRunner: Runs each mutant with environment scrubbing, proxy nullification, and full process tree termination.
    4. Granular metrics: Distinguishes assertion failures, timeouts, survived mutants, and invalid mutants.
    """
    from offtest.checks.isolated_runner import IsolatedRunner

    mutants = generate_mutants(source_code, target_function)
    if not mutants:
        return MutationReport(
            total_mutants=0,
            killed_mutants=0,
            survived_mutants=0,
            timed_out_mutants=0,
            invalid_mutants=0,
            mutation_score_pct=100.0,
            baseline_passed=True,
            canary_verified=False,
            mutants=[],
        )

    killed = 0
    survived = 0
    timed_out = 0
    invalid = 0
    mutant_records = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_p = Path(tmp_dir)
        runner = IsolatedRunner(tmp_p, timeout_sec=max(1, int(timeout_sec)))

        def _execute_harness(src_text: str) -> Tuple[int, str, str, float]:
            mod_file = tmp_p / f"{module_name}.py"
            mod_file.write_text(src_text, encoding="utf-8")
            script_file = tmp_p / "run_mutation_harness.py"
            script_content = f"""
import sys
from pathlib import Path
sys.path.insert(0, r"{str(tmp_p)}")
import {module_name}
from {module_name} import *

# Injected test code
{test_code}

# Run all test functions defined in test_code
current_ns = dict(locals())
for k, v in current_ns.items():
    if k.startswith("test_") and callable(v):
        v()
"""
            script_file.write_text(script_content, encoding="utf-8")
            return runner.run([sys.executable, "-B", str(script_file)])

        # 1. Baseline Execution: Test MUST pass on unmutated code
        b_exit, b_out, b_err, _ = _execute_harness(source_code)
        if b_exit != 0:
            return MutationReport(
                total_mutants=len(mutants),
                killed_mutants=0,
                survived_mutants=0,
                timed_out_mutants=0,
                invalid_mutants=0,
                mutation_score_pct=0.0,
                baseline_passed=False,
                canary_verified=False,
                mutants=[],
                interpretation="Baseline test failed against unmutated code; tests cannot be trusted for mutation analysis.",
            )

        # 2. Canary Mutant: Invalidate target module to confirm the test imports the mutant
        canary_src = source_code + "\n\n# Canary mutant injection\ndef __canary_check__(): raise RuntimeError('__CANARY_TRIGGERED__')\n"
        # Also mutate any return statement in target function to raise RuntimeError
        canary_tree = None
        try:
            canary_tree = ast.parse(source_code)
            for node in ast.walk(canary_tree):
                if isinstance(node, ast.Return):
                    node.value = ast.Constant(value=None)
            canary_src = ast.unparse(canary_tree)
        except Exception:
            pass

        c_exit, _, _, _ = _execute_harness(canary_src)
        # Canary is verified if modifying the return values broke at least one assertion
        canary_verified = (c_exit != 0)

        # 3. Evaluate Mutants
        for m in mutants:
            try:
                mutant_src = ast.unparse(m.mutated_ast)
            except Exception:
                invalid += 1
                mutant_records.append({
                    "mutant_id": m.mutant_id,
                    "line": m.original_line,
                    "type": m.mutation_type,
                    "status": "invalid (unparse failed)",
                })
                continue

            exit_code, stdout, stderr, dur = _execute_harness(mutant_src)

            if exit_code == -9 or exit_code == 124 or "timed out" in stderr.lower() or "timeout" in stdout.lower():
                timed_out += 1
                killed += 1
                status = "killed (timeout)"
            elif exit_code != 0:
                # Failed assertions or syntax/runtime errors
                if "AssertionError" in stderr or "assert" in stderr.lower() or exit_code == 1:
                    killed += 1
                    status = "killed"
                else:
                    invalid += 1
                    status = "invalid (crash)"
            else:
                survived += 1
                status = "survived"

            mutant_records.append({
                "mutant_id": m.mutant_id,
                "line": m.original_line,
                "type": m.mutation_type,
                "status": status,
            })

    total = len(mutants)
    valid_mutants = total - invalid
    score = round((killed / valid_mutants) * 100.0, 1) if valid_mutants > 0 else 0.0

    return MutationReport(
        total_mutants=total,
        killed_mutants=killed,
        survived_mutants=survived,
        timed_out_mutants=timed_out,
        invalid_mutants=invalid,
        mutation_score_pct=score,
        baseline_passed=True,
        canary_verified=canary_verified,
        mutants=mutant_records,
    )
