"""offtest/adapters/base.py

Base interface and coverage metadata for language-specific analyzers.
Provides unified abstractions for:
- Symbols, lexical scopes, and definitions
- Call edges and reachability entry roots
- Routes and authentication markers
- Taint sources, sinks, and static rules
- Test harness integration
"""
from __future__ import annotations

import abc
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from offtest.core.models import (
    FeatureDepth,
    Finding,
    GeneratedTestSuite,
    LanguageCoverage,
    RouteRecord,
)


class BaseLanguageAdapter(abc.ABC):
    """Abstract base class for all language-specific scanner adapters."""

    name: str = "base"
    supported_languages: Tuple[str, ...] = ()

    @abc.abstractmethod
    def get_coverage(self) -> LanguageCoverage:
        """Declares coverage depth (none, heuristic, semantic) per analysis feature."""
        raise NotImplementedError

    @abc.abstractmethod
    def index_file(self, rel_path: str, content: str, project_index: Any) -> None:
        """Indexes symbols, calls, entry points, and routes into the unified ProjectIndex."""
        raise NotImplementedError

    @abc.abstractmethod
    def run_rules(
        self,
        rel_path: str,
        content: str,
        project_index: Any,
        checker: Any,
        branch: Optional[str] = None,
    ) -> List[Finding]:
        """Runs language-specific and framework-specific security, hygiene, and correctness rules."""
        raise NotImplementedError

    def synthesize_tests(
        self, repo_dir: Path, target_file: str, project_index: Any
    ) -> Optional[GeneratedTestSuite]:
        """Synthesizes isolated test cases if test harness is available for this language."""
        return None
