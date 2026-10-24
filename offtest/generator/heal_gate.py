"""offtest/generator/heal_gate.py

Deterministic gate for the self-healing loop. A model-produced patch is
accepted only if it does not make the test weaker than the version it
replaces. Pure AST analysis, no execution, no model involvement.
"""
from __future__ import annotations

import ast
import difflib
from dataclasses import asdict, dataclass, field
from typing import Callable, List, Optional, Set

SKIP_CALLS = {"pytest.skip", "pytest.xfail", "pytest.importorskip", "self.skipTest"}
SKIP_MARKS = {"skip", "skipif", "xfail"}
PATCH_LEAVES = {"patch", "setattr", "object", "monkeypatch"}
BROAD_EXC = {"Exception", "BaseException"}


@dataclass(frozen=True)
class Violation:
    rule: str
    test: str
    detail: str = ""
    line: int | None = None


@dataclass
class GateResult:
    violations: list[Violation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def add(self, rule: str, test: str, detail: str = "", line: int | None = None):
        self.violations.append(Violation(rule, test, detail, line))

    def feedback(self) -> str:
        """Text safe to hand back to the model on rejection."""
        return "\n".join(f"- {v.rule}: {v.test} {v.detail}".rstrip() for v in self.violations)


@dataclass
class Profile:
    asserts: int = 0          # real assertions (assert stmt, self.assertX, pytest.raises)
    tautologies: int = 0      # assert True, assert x == x, assert y or True
    swallows: int = 0         # broad except with no re-raise
    skips: int = 0
    target_calls: int = 0     # calls to the unit under test
    target_mocked: int = 0    # patches that replace the unit under test
    assert_srcs: set[str] = field(default_factory=set)


@dataclass
class HealIterationRecord:
    iteration: int
    diff: str
    passed_gate: bool
    violations: list[Violation] = field(default_factory=list)
    failure_origin: str = "test_defect"
    is_product_defect: bool = False
    feedback: str = ""


@dataclass
class HealSessionResult:
    target: str
    initial_code: str
    final_code: str
    healed: bool
    iterations: list[HealIterationRecord] = field(default_factory=list)
    stopped_reason: str = "converged"
    is_product_defect: bool = False
    validation_status: str = "synthesized, unverified"


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    curr = node
    while isinstance(curr, ast.Attribute):
        parts.append(curr.attr)
        curr = curr.value
    if isinstance(curr, ast.Name):
        parts.append(curr.id)
    return ".".join(reversed(parts))


def _is_tautology(test: ast.expr) -> bool:
    if isinstance(test, ast.Constant):
        return bool(test.value)
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return any(_is_tautology(v) for v in test.values)
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        if isinstance(test.ops[0], (ast.Eq, ast.Is, ast.LtE, ast.GtE)):
            try:
                return ast.dump(test.left) == ast.dump(test.comparators[0])
            except Exception:
                return False
    return False


class _Collector(ast.NodeVisitor):
    def __init__(self, target: str):
        self.t = target
        self.p = Profile()

    def visit_Assert(self, n: ast.Assert):
        if _is_tautology(n.test):
            self.p.tautologies += 1
        else:
            self.p.asserts += 1
            try:
                self.p.assert_srcs.add(ast.unparse(n))
            except Exception:
                pass
        self.generic_visit(n)

    def visit_ExceptHandler(self, n: ast.ExceptHandler):
        broad = n.type is None or _dotted(n.type) in BROAD_EXC
        if broad and not any(isinstance(x, ast.Raise) for x in ast.walk(n)):
            self.p.swallows += 1
        self.generic_visit(n)

    def visit_Call(self, n: ast.Call):
        name = _dotted(n.func)
        leaf = name.rsplit(".", 1)[-1]
        if leaf == "raises" or (leaf.startswith("assert") and "." in name):
            self.p.asserts += 1
        if leaf == self.t or name == self.t:
            self.p.target_calls += 1
        if name in SKIP_CALLS:
            self.p.skips += 1
        if leaf in PATCH_LEAVES:
            for a in n.args[:2]:
                if (
                    isinstance(a, ast.Constant)
                    and isinstance(a.value, str)
                    and a.value.rsplit(".", 1)[-1] == self.t
                ):
                    self.p.target_mocked += 1
        self.generic_visit(n)


def profiles(tree: ast.AST, target: str) -> dict[str, Profile]:
    out: dict[str, Profile] = {}

    def walk(node: ast.AST, prefix: str):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, ast.ClassDef):
                walk(ch, f"{prefix}{ch.name}.")
            elif isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)) and ch.name.startswith("test"):
                c = _Collector(target)
                for stmt in ch.body:
                    c.visit(stmt)
                for d in ch.decorator_list:
                    base = d.func if isinstance(d, ast.Call) else d
                    if _dotted(base).rsplit(".", 1)[-1] in SKIP_MARKS:
                        c.p.skips += 1
                out[prefix + ch.name] = c.p

    walk(tree, "")
    return out


def compute_patch_diff(before: str, after: str, filename: str = "test_candidate.py") -> str:
    """Computes a unified diff between two code revisions."""
    b_lines = before.splitlines(keepends=True)
    a_lines = after.splitlines(keepends=True)
    diff = difflib.unified_diff(b_lines, a_lines, fromfile=f"a/{filename}", tofile=f"b/{filename}")
    return "".join(diff)


def check_patch(
    before: str,
    after: str,
    target: str,
    protected: frozenset[str] = frozenset(),
) -> GateResult:
    """Compare a test module before and after a model patch.

    target:    bare name of the unit under test (e.g. "apply_discount").
    protected: unparsed assert statements derived from symbolic oracles;
               they must survive verbatim in the same test.
    """
    res = GateResult()
    try:
        new_tree = ast.parse(after)
    except SyntaxError as e:
        res.add("syntax_error", "<module>", str(e), e.lineno)
        return res
    try:
        old_tree = ast.parse(before)
    except SyntaxError as e:
        res.add("syntax_error_in_baseline", "<module>", str(e), e.lineno)
        return res

    new = profiles(new_tree, target)
    old = profiles(old_tree, target)

    for name, o in old.items():
        n = new.get(name)
        if n is None:
            res.add("test_removed", name)
            continue
        if n.asserts < o.asserts:
            res.add("assertion_dropped", name, f"{o.asserts} -> {n.asserts}")
        lost = (o.assert_srcs & protected) - n.assert_srcs
        if lost:
            res.add("oracle_assertion_changed", name, "; ".join(sorted(lost)))
        if n.tautologies > o.tautologies:
            res.add("tautology_added", name)
        if o.target_calls and not n.target_calls:
            res.add("target_not_called", name, target)
        if n.swallows > o.swallows:
            res.add("exception_swallowed", name)
        if n.skips > o.skips:
            res.add("skip_or_xfail_added", name)
        if n.target_mocked > o.target_mocked:
            res.add("target_mocked", name, target)

    for name, n in new.items():
        if name not in old and n.asserts == 0:
            res.add("new_test_without_assertions", name)
    return res


def run_healing_loop(
    candidate: str,
    target: str,
    test_runner: Callable[[str], tuple[bool, str, str]],  # returns (passed, failure_origin, failure_sig)
    patch_generator: Callable[[str, str, str], str],     # (candidate, failure_sig, feedback) -> new_patch
    protected_asserts: frozenset[str] = frozenset(),
    max_heal: int = 3,
) -> HealSessionResult:
    """
    Executes a bounded self-healing loop with deterministic AST invariant gating.
    Distinguishes test defects (healed) from product defects (never healed).
    """
    session = HealSessionResult(
        target=target,
        initial_code=candidate,
        final_code=candidate,
        healed=False,
        iterations=[],
        validation_status="synthesized, unverified",
    )

    curr_candidate = candidate
    pending_feedback = ""

    for k in range(1, max_heal + 1):
        passed, failure_origin, failure_sig = test_runner(curr_candidate)
        if passed:
            session.final_code = curr_candidate
            session.healed = True
            session.stopped_reason = "passed"
            return session

        # Distinguish test defect from product defect
        if failure_origin == "symbolic_oracle":
            # Product defect, never heal!
            session.is_product_defect = True
            session.stopped_reason = "symbolic_oracle_violation_product_defect"
            return session

        # Ask generator for patch
        patch = patch_generator(curr_candidate, failure_sig, pending_feedback)
        gate = check_patch(curr_candidate, patch, target, protected_asserts)
        diff_text = compute_patch_diff(curr_candidate, patch)

        record = HealIterationRecord(
            iteration=k,
            diff=diff_text,
            passed_gate=gate.ok,
            violations=gate.violations,
            failure_origin=failure_origin,
            feedback=gate.feedback(),
        )
        session.iterations.append(record)

        if gate.ok:
            curr_candidate = patch
            session.final_code = patch
            pending_feedback = ""
        else:
            pending_feedback = gate.feedback()

    # Final check on outcome
    final_pass, _, _ = test_runner(session.final_code)
    session.healed = final_pass
    if not final_pass:
        session.stopped_reason = "max_iterations_exhausted"

    return session
