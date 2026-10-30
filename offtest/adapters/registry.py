"""offtest/adapters/registry.py

Central registry for language adapters.
Maps file languages to specialized adapters (Python, TypeScript/React, Java/Spring).
"""
from __future__ import annotations

from typing import Dict, List, Optional

from offtest.adapters.base import BaseLanguageAdapter
from offtest.adapters.java_adapter import JavaAdapter
from offtest.adapters.python_adapter import PythonAdapter
from offtest.adapters.typescript_adapter import TypeScriptAdapter
from offtest.core.models import LanguageCoverage

_ADAPTERS: List[BaseLanguageAdapter] = [
    PythonAdapter(),
    TypeScriptAdapter(),
    JavaAdapter(),
]

_LANGUAGE_TO_ADAPTER: Dict[str, BaseLanguageAdapter] = {}
for _ad in _ADAPTERS:
    for _lang in _ad.supported_languages:
        _LANGUAGE_TO_ADAPTER[_lang] = _ad


def get_adapter_for_language(language: Optional[str]) -> Optional[BaseLanguageAdapter]:
    """Returns the registered language adapter for a detected language."""
    if not language:
        return None
    return _LANGUAGE_TO_ADAPTER.get(language)


def get_all_adapters() -> List[BaseLanguageAdapter]:
    """Returns all registered adapters."""
    return list(_ADAPTERS)


def get_all_coverages() -> Dict[str, LanguageCoverage]:
    """Returns coverage declarations for all registered adapters."""
    return {ad.name: ad.get_coverage() for ad in _ADAPTERS}
