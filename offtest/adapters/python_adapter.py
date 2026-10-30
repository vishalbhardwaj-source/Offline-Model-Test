"""offtest/adapters/python_adapter.py

Python language adapter.
Provides semantic AST parsing, symtable scope resolution, FastAPI/Flask route analysis,
three-state call graph reachability, and automated pytest synthesis.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, List, Optional

from offtest.adapters.base import BaseLanguageAdapter
from offtest.core.models import FeatureDepth, Finding, GeneratedTestSuite, LanguageCoverage


class PythonAdapter(BaseLanguageAdapter):
    name = "python"
    supported_languages = ("Python",)

    def get_coverage(self) -> LanguageCoverage:
        return LanguageCoverage(
            language="Python",
            symbols=FeatureDepth.SEMANTIC,
            call_graph=FeatureDepth.SEMANTIC,
            reachability=FeatureDepth.SEMANTIC,
            routes_and_auth=FeatureDepth.SEMANTIC,
            taint_and_rules=FeatureDepth.SEMANTIC,
            test_synthesis=FeatureDepth.SEMANTIC,
            notes="Semantic AST & symtable analysis; FastAPI/Flask route & auth extraction; pytest synthesis active",
        )

    def index_file(self, rel_path: str, content: str, project_index: Any) -> None:
        tree = project_index.get_ast(rel_path)
        if tree:
            project_index._index_python_file(rel_path, tree)

    def run_rules(
        self,
        rel_path: str,
        content: str,
        project_index: Any,
        checker: Any,
        branch: Optional[str] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        counter = len(findings) + 1

        syntax_finding, parsed_ast = checker._check_python_syntax(rel_path, content, counter, branch)
        if syntax_finding:
            findings.append(syntax_finding)
            return findings

        if parsed_ast:
            py_findings = checker._check_python_security_ast(rel_path, parsed_ast, counter, branch)
            findings.extend(py_findings)
            counter += len(py_findings)

            dead_findings = checker._check_python_dead_code(rel_path, parsed_ast, counter, branch)
            findings.extend(dead_findings)
            counter += len(dead_findings)

            semantic_findings = checker._check_python_semantic_bugs(rel_path, parsed_ast, counter, branch)
            findings.extend(semantic_findings)

        return findings
