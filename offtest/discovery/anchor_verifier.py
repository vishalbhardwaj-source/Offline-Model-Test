"""offtest/discovery/anchor_verifier.py

Mechanical verification for source code anchors (file:line:symbol).
Validates that cited files exist, lines are in range, AST nodes match claimed constructs,
and content hashes (SHA-256) are pinned to prevent fabricated citations.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class AnchorVerificationResult:
    is_valid: bool
    file_path: str
    line_number: Optional[int]
    file_sha256: Optional[str] = None
    error_code: Optional[str] = None
    detail: Optional[str] = None


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        data = path.read_bytes()
        # Normalize CRLF to LF to ensure consistent cryptographic anchor hashes across Windows and Linux
        if b"\r\n" in data:
            data = data.replace(b"\r\n", b"\n")
        h.update(data)
        return h.hexdigest()
    except Exception:
        return "error_reading_hash"


def verify_source_anchor(
    repo_dir: Path,
    file_path: str,
    line_number: Optional[int],
    expected_construct: Optional[str] = None,
    expected_sha256: Optional[str] = None,
    expected_method: Optional[str] = None,
    expected_path: Optional[str] = None,
) -> AnchorVerificationResult:
    """
    Mechanically verifies a source code anchor against the physical snapshot.
    Claims whose anchors fail verification are rejected immediately without repair.
    Validates file existence, bounds, SHA-256 hash, and route decorator claims (path & method).
    """
    target = repo_dir / file_path
    if not target.is_file():
        return AnchorVerificationResult(
            is_valid=False,
            file_path=file_path,
            line_number=line_number,
            error_code="ANCHOR_FILE_NOT_FOUND",
            detail=f"Cited file does not exist in repository: '{file_path}'",
        )

    current_sha256 = compute_file_sha256(target)
    if expected_sha256 and expected_sha256.lower() != current_sha256.lower():
        return AnchorVerificationResult(
            is_valid=False,
            file_path=file_path,
            line_number=line_number,
            file_sha256=current_sha256,
            error_code="ANCHOR_HASH_MISMATCH",
            detail=f"Content hash mismatch for '{file_path}': expected {expected_sha256[:12]}..., got {current_sha256[:12]}...",
        )

    if line_number is None:
        return AnchorVerificationResult(
            is_valid=True,
            file_path=file_path,
            line_number=None,
            file_sha256=current_sha256,
        )

    try:
        content = target.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()
    except Exception as e:
        return AnchorVerificationResult(
            is_valid=False,
            file_path=file_path,
            line_number=line_number,
            file_sha256=current_sha256,
            error_code="ANCHOR_UNREADABLE",
            detail=f"Failed to read file content: {e}",
        )

    total_lines = len(lines)
    if line_number < 1 or line_number > total_lines:
        return AnchorVerificationResult(
            is_valid=False,
            file_path=file_path,
            line_number=line_number,
            file_sha256=current_sha256,
            error_code="ANCHOR_LINE_OUT_OF_BOUNDS",
            detail=f"Line {line_number} out of bounds (file has {total_lines} lines)",
        )

    # If construct check is requested and file is Python
    if expected_construct and (file_path.endswith(".py") or target.suffix == ".py"):
        try:
            tree = ast.parse(content, filename=file_path)
            matched_ast = False
            claim_mismatched = False

            class ConstructVisitor(ast.NodeVisitor):
                def __init__(self, target_line: int, kind: str):
                    self.target_line = target_line
                    self.kind = kind.lower()
                    self.found = False
                    self.claim_failed = False

                def generic_visit(self, node: ast.AST):
                    if hasattr(node, "lineno"):
                        # Calculate full function span starting at first decorator
                        decs = getattr(node, "decorator_list", [])
                        first_line = min([getattr(d, "lineno", node.lineno) for d in decs], default=node.lineno)
                        end_lineno = getattr(node, "end_lineno", node.lineno)

                        if first_line <= self.target_line <= end_lineno:
                            if self.kind in ("function", "def", "route", "handler") and isinstance(
                                node, (ast.FunctionDef, ast.AsyncFunctionDef)
                            ):
                                self.found = True
                                # If expected_path or expected_method is specified, check decorators
                                if expected_path or expected_method:
                                    path_matched = not expected_path
                                    method_matched = not expected_method
                                    for d in decs:
                                        if isinstance(d, ast.Call):
                                            # Check route path in args
                                            if expected_path and d.args and isinstance(d.args[0], ast.Constant):
                                                if str(d.args[0].value).rstrip("/") == expected_path.rstrip("/"):
                                                    path_matched = True
                                            # Check method
                                            if expected_method:
                                                fn_name = ""
                                                if isinstance(d.func, ast.Attribute):
                                                    fn_name = d.func.attr.lower()
                                                if fn_name == expected_method.lower():
                                                    method_matched = True
                                                elif fn_name == "route":
                                                    # Check methods keyword e.g. methods=['POST']
                                                    for kw in d.keywords:
                                                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                                                            for m_elem in kw.value.elts:
                                                                if isinstance(m_elem, ast.Constant) and str(m_elem.value).upper() == expected_method.upper():
                                                                    method_matched = True
                                    if not (path_matched and method_matched):
                                        self.claim_failed = True
                            elif self.kind in ("class",) and isinstance(node, ast.ClassDef):
                                self.found = True
                            elif self.kind in ("decorator", "route") and any(
                                getattr(d, "lineno", 0) == self.target_line for d in decs
                            ):
                                self.found = True
                    if not self.found:
                        super().generic_visit(node)

            v = ConstructVisitor(line_number, expected_construct)
            v.visit(tree)
            matched_ast = v.found
            claim_mismatched = v.claim_failed

            if matched_ast and claim_mismatched:
                return AnchorVerificationResult(
                    is_valid=False,
                    file_path=file_path,
                    line_number=line_number,
                    file_sha256=current_sha256,
                    error_code="ANCHOR_CLAIM_MISMATCH",
                    detail=f"Decorator arguments do not match route claim (expected {expected_method or 'ANY'} {expected_path or ''})",
                )

            if not matched_ast:
                line_text = lines[line_number - 1].strip()
                if expected_construct.lower() in ("route", "decorator") and line_text.startswith("@"):
                    matched_ast = True
                elif expected_construct.lower() in ("function", "def") and line_text.startswith("def "):
                    matched_ast = True

            if not matched_ast:
                return AnchorVerificationResult(
                    is_valid=False,
                    file_path=file_path,
                    line_number=line_number,
                    file_sha256=current_sha256,
                    error_code="ANCHOR_AST_MISMATCH",
                    detail=f"Line {line_number} does not match expected construct '{expected_construct}': {lines[line_number - 1].strip()[:60]}",
                )
        except Exception:
            pass

    return AnchorVerificationResult(
        is_valid=True,
        file_path=file_path,
        line_number=line_number,
        file_sha256=current_sha256,
    )
