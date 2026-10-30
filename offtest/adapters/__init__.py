"""offtest/adapters/__init__.py

Language Adapter Layer for offtest.
Provides multi-language coverage across Python, TypeScript, React, and Java/Spring.
"""
from offtest.adapters.base import BaseLanguageAdapter
from offtest.adapters.java_adapter import JavaAdapter
from offtest.adapters.python_adapter import PythonAdapter
from offtest.adapters.registry import (
    get_adapter_for_language,
    get_all_adapters,
    get_all_coverages,
)
from offtest.adapters.typescript_adapter import TypeScriptAdapter

__all__ = [
    "BaseLanguageAdapter",
    "PythonAdapter",
    "TypeScriptAdapter",
    "JavaAdapter",
    "get_adapter_for_language",
    "get_all_adapters",
    "get_all_coverages",
]
