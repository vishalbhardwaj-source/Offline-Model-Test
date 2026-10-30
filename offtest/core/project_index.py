"""offtest/core/project_index.py

Unified ProjectIndex: parses every file once, caches ASTs, lines, and hashes,
builds symbol tables, cross-file call graphs, reachability maps from entry points,
and provides code-derived workflow traces.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from offtest.core.models import FileRecord


@dataclass
class SymbolDef:
    name: str
    qualified_name: str  # e.g., "module.func" or "Class.method"
    symbol_type: str     # "function", "async_function", "class", "method"
    file_path: str
    line_number: int
    end_line_number: int
    docstring: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    is_private: bool = False
    is_entry_point: bool = False
    is_noop: bool = False
    noop_reason: Optional[str] = None  # "pass_body", "returns_argument", "ellipsis_body"
    raises_not_implemented: bool = False
    enclosing_class: Optional[str] = None


@dataclass
class CallEdge:
    caller_file: str
    caller_symbol: Optional[str]
    callee_name: str
    line_number: int
    is_dynamic: bool = False  # getattr, __all__, locals(), globals()


@dataclass
class ExtractedRoute:
    path: str
    method: str  # "GET", "POST", "PUT", "DELETE", "PATCH", "ANY"
    handler_name: str
    file_path: str
    line_number: int
    auth_required: bool = False
    framework: str = "Flask"  # Flask, FastAPI, Express, Django


class ProjectIndex:
    """
    Parses and indexes all project source files once:
    - AST and content caching
    - Symbol definitions & lexical scopes
    - Cross-file call graph & entry-point reachability
    - Route handlers with exact HTTP methods
    - Dynamic references (__all__, getattr, decorators)
    """

    def __init__(self, repo_dir: Path, files: List[FileRecord]):
        self.repo_dir = Path(repo_dir)
        self.files = files
        self.analyzed_files = [f for f in files if f.disposition.value == "analyzed"]
        
        # Caches
        self._content_cache: Dict[str, str] = {}
        self._ast_cache: Dict[str, Optional[ast.AST]] = {}
        self._lines_cache: Dict[str, List[str]] = {}

        # Symbol & Graph tables
        self.symbols: Dict[str, SymbolDef] = {}  # key: f"{file_path}::{qualified_name}"
        self.symbols_by_name: Dict[str, List[SymbolDef]] = {}  # short name -> defs
        self.routes: List[ExtractedRoute] = []
        self.call_edges: List[CallEdge] = []
        self.entry_points: Set[str] = set()  # set of symbol keys (f"{file_path}::{name}")
        self.dynamic_names: Set[str] = set()  # names used via getattr, __all__, etc.
        self.exported_names: Set[str] = set()  # names explicitly in __all__
        self.imported_modules: Set[str] = set()  # all packages/modules imported across project
        self.all_loaded_names: Set[str] = set()  # all Name(ctx=Load) & annotation symbols across project

        # Call Graph adjacencies
        self.adjacency: Dict[str, Set[str]] = {}  # caller_key -> set(callee_keys)
        self.reachable_symbols: Set[str] = set()
        self.unreachable_symbols: List[SymbolDef] = []

        # Run the full single-pass parse and index
        self._build_index()

    def get_content(self, file_path: str) -> str:
        if file_path in self._content_cache:
            return self._content_cache[file_path]
        full_p = self.repo_dir / file_path
        content = ""
        if full_p.is_file():
            try:
                content = full_p.read_text(encoding="utf-8-sig", errors="ignore")
            except Exception:
                pass
        self._content_cache[file_path] = content
        return content

    def get_ast(self, file_path: str) -> Optional[ast.AST]:
        if file_path in self._ast_cache:
            return self._ast_cache[file_path]
        content = self.get_content(file_path)
        tree = None
        if content:
            try:
                tree = ast.parse(content, filename=file_path)
            except Exception:
                tree = None
        self._ast_cache[file_path] = tree
        return tree

    def get_lines(self, file_path: str) -> List[str]:
        if file_path in self._lines_cache:
            return self._lines_cache[file_path]
        content = self.get_content(file_path)
        lines = content.splitlines()
        self._lines_cache[file_path] = lines
        return lines

    def _build_index(self):
        from offtest.adapters.registry import get_adapter_for_language

        # 1. Parse and extract symbols, calls, routes per file via language adapters
        for f in self.analyzed_files:
            adapter = get_adapter_for_language(f.language)
            content = self.get_content(f.path)
            if adapter:
                adapter.index_file(f.path, content, self)
            elif f.language == "Python":
                tree = self.get_ast(f.path)
                if tree:
                    self._index_python_file(f.path, tree)
            elif f.language in ["JavaScript", "TypeScript", "JavaScript (JSX)", "TypeScript (TSX)"]:
                self._index_js_ts_file(f.path)

        # 2. Resolve call graph edges across the whole project
        self._resolve_call_graph()

        # 3. Compute entry-point reachability
        self._compute_reachability()

    def _index_python_file(self, rel_path: str, tree: ast.AST):
        is_test_file = (
            "test" in rel_path.lower()
            or rel_path.startswith("tests/")
            or rel_path.startswith("tests\\")
        )

        class IndexVisitor(ast.NodeVisitor):
            def __init__(self, outer: ProjectIndex):
                self.outer = outer
                self.current_class: Optional[str] = None
                self.current_function: Optional[str] = None

            def visit_Import(self, node: ast.Import):
                for alias in node.names:
                    self.outer.imported_modules.add(alias.name)
                    self.outer.imported_modules.add(alias.name.split(".")[0])
                    bound = alias.asname or alias.name.split(".")[0]
                    self.outer.all_loaded_names.add(bound)
                self.generic_visit(node)

            def visit_ImportFrom(self, node: ast.ImportFrom):
                if node.module:
                    self.outer.imported_modules.add(node.module)
                    self.outer.imported_modules.add(node.module.split(".")[0])
                for alias in node.names:
                    bound = alias.asname or alias.name
                    self.outer.all_loaded_names.add(bound)
                    self.outer.all_loaded_names.add(alias.name)

                # Resolved relative imports: e.g. from .ml_engine import ml_engine
                if node.level and node.level > 0:
                    caller_sym = self.current_function or "__top__"
                    for alias in node.names:
                        self.outer.call_edges.append(
                            CallEdge(
                                caller_file=rel_path,
                                caller_symbol=caller_sym,
                                callee_name=alias.name,
                                line_number=node.lineno,
                            )
                        )
                        self.outer.dynamic_names.add(alias.name)
                self.generic_visit(node)

            def visit_Name(self, node: ast.Name):
                if isinstance(node.ctx, ast.Load):
                    self.outer.all_loaded_names.add(node.id)
                self.generic_visit(node)

            def visit_AnnAssign(self, node: ast.AnnAssign):
                for sub in ast.walk(node.annotation):
                    if isinstance(sub, ast.Name):
                        self.outer.all_loaded_names.add(sub.id)
                self.generic_visit(node)

            def visit_Assign(self, node: ast.Assign):
                # Check for __all__ = [...]
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    self.outer.exported_names.add(elt.value)
                                    self.outer.dynamic_names.add(elt.value)
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call):
                # Check for getattr(obj, "func") or hasattr(obj, "func")
                if isinstance(node.func, ast.Name) and node.func.id in ("getattr", "hasattr"):
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                        self.outer.dynamic_names.add(node.args[1].value)

                callee_name = None
                if isinstance(node.func, ast.Name):
                    callee_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee_name = node.func.attr

                if callee_name:
                    caller_sym = self.current_function
                    if self.current_class and caller_sym:
                        caller_sym = f"{self.current_class}.{caller_sym}"
                    # Top-level module code connects as __top__ root
                    caller_sym = caller_sym or "__top__"
                    self.outer.call_edges.append(
                        CallEdge(
                            caller_file=rel_path,
                            caller_symbol=caller_sym,
                            callee_name=callee_name,
                            line_number=node.lineno,
                        )
                    )
                self.generic_visit(node)

            def visit_ClassDef(self, node: ast.ClassDef):
                prev_class = self.current_class
                self.current_class = node.name

                decorators = [ast.unparse(d) for d in node.decorator_list]
                is_private = node.name.startswith("_") and not node.name.startswith("__")
                is_entry = is_test_file and node.name.startswith("Test")

                sym_def = SymbolDef(
                    name=node.name,
                    qualified_name=node.name,
                    symbol_type="class",
                    file_path=rel_path,
                    line_number=node.lineno,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    docstring=ast.get_docstring(node),
                    decorators=decorators,
                    is_private=is_private,
                    is_entry_point=is_entry,
                )
                key = f"{rel_path}::{node.name}"
                self.outer.symbols[key] = sym_def
                self.outer.symbols_by_name.setdefault(node.name, []).append(sym_def)
                if is_entry:
                    self.outer.entry_points.add(key)

                self.generic_visit(node)
                self.current_class = prev_class

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self._handle_func(node, is_async=False)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                self._handle_func(node, is_async=True)

            def _handle_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool):
                prev_func = self.current_function
                self.current_function = node.name

                qname = f"{self.current_class}.{node.name}" if self.current_class else node.name
                params = [a.arg for a in node.args.args]
                decorators = [ast.unparse(d) for d in node.decorator_list]
                is_private = node.name.startswith("_") and not node.name.startswith("__")

                # Detect if this is an entry point
                is_entry = False
                if is_test_file and (node.name.startswith("test_") or node.name.startswith("test")):
                    is_entry = True

                # Route decorator detection (Flask / FastAPI / Django)
                route_info = self._extract_route(node)
                if route_info:
                    is_entry = True
                    self.outer.routes.append(route_info)

                # Special CLI / main entry points
                if node.name in ("main", "cli", "run", "handler") and not is_private:
                    is_entry = True
                if any("command" in d.lower() or "endpoint" in d.lower() or "receiver" in d.lower() for d in decorators):
                    is_entry = True

                # Inspect parameter defaults for FastAPI Depends(...) edges
                all_defaults = list(node.args.defaults) + [d for d in getattr(node.args, "kw_defaults", []) if d is not None]
                for d in all_defaults:
                    for sub in ast.walk(d):
                        if isinstance(sub, ast.Call):
                            fn = getattr(sub.func, "id", None) or getattr(sub.func, "attr", None)
                            if fn == "Depends" and sub.args:
                                dep = getattr(sub.args[0], "id", None) or getattr(sub.args[0], "attr", None)
                                if dep:
                                    self.outer.call_edges.append(
                                        CallEdge(
                                            caller_file=rel_path,
                                            caller_symbol=qname,
                                            callee_name=dep,
                                            line_number=node.lineno,
                                        )
                                    )
                                    self.outer.dynamic_names.add(dep)

                # Broad usage: any Load reference inside the function body connects as a dependency
                # (generalizes callbacks e.g. map, Thread(target=...), run_in_threadpool)
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                        if sub.id != node.name:
                            self.outer.call_edges.append(
                                CallEdge(
                                    caller_file=rel_path,
                                    caller_symbol=qname,
                                    callee_name=sub.id,
                                    line_number=sub.lineno,
                                )
                            )

                # Semantic inspection: No-Op and Stub detection
                is_noop, noop_reason, raises_not_impl = self._check_noop_and_stubs(node, params, decorators)

                sym_def = SymbolDef(
                    name=node.name,
                    qualified_name=qname,
                    symbol_type="async_function" if is_async else ("method" if self.current_class else "function"),
                    file_path=rel_path,
                    line_number=node.lineno,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    docstring=ast.get_docstring(node),
                    parameters=params,
                    decorators=decorators,
                    is_private=is_private,
                    is_entry_point=is_entry,
                    is_noop=is_noop,
                    noop_reason=noop_reason,
                    raises_not_implemented=raises_not_impl,
                    enclosing_class=self.current_class,
                )

                key = f"{rel_path}::{qname}"
                self.outer.symbols[key] = sym_def
                self.outer.symbols_by_name.setdefault(node.name, []).append(sym_def)
                if is_entry:
                    self.outer.entry_points.add(key)

                self.generic_visit(node)
                self.current_function = prev_func

            def _check_noop_and_stubs(
                self, node: ast.FunctionDef | ast.AsyncFunctionDef, params: List[str], decorators: List[str]
            ) -> Tuple[bool, Optional[str], bool]:
                # If abstractmethod or overload, it is intentionally a signature stub
                if any("abstractmethod" in d or "overload" in d for d in decorators):
                    return False, None, False

                body_stmts = node.body
                # Filter out leading docstring
                if body_stmts and isinstance(body_stmts[0], ast.Expr) and isinstance(body_stmts[0].value, ast.Constant) and isinstance(body_stmts[0].value.value, str):
                    body_stmts = body_stmts[1:]

                # 1. Empty body: only `pass` or `...`
                if len(body_stmts) == 1:
                    stmt = body_stmts[0]
                    if isinstance(stmt, ast.Pass):
                        return True, "Empty function body consisting solely of 'pass'", False
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
                        return True, "Empty function body consisting solely of '...'", False

                    # 2. Always raises NotImplementedError
                    if isinstance(stmt, ast.Raise):
                        exc_name = ""
                        if isinstance(stmt.exc, ast.Name):
                            exc_name = stmt.exc.id
                        elif isinstance(stmt.exc, ast.Call) and isinstance(stmt.exc.func, ast.Name):
                            exc_name = stmt.exc.func.id
                        if exc_name == "NotImplementedError":
                            return False, None, True

                    # 3. Identity function returning its input argument
                    if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Name):
                        if params and stmt.value.id == params[0]:
                            return True, f"Trivial identity function that only returns its argument '{stmt.value.id}'", False

                elif len(body_stmts) == 0:
                    return True, "Empty function body with only a docstring", False

                return False, None, False

            def _extract_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Optional[ExtractedRoute]:
                for dec in node.decorator_list:
                    # e.g., @app.route("/path", methods=["POST"])
                    # e.g., @app.get("/path")
                    # e.g., @router.post("/path")
                    if isinstance(dec, ast.Call):
                        func = dec.func
                        route_path = None
                        method = "GET"
                        is_route = False

                        if isinstance(func, ast.Attribute):
                            attr_lower = func.attr.lower()
                            if attr_lower in ("get", "post", "put", "delete", "patch"):
                                is_route = True
                                method = attr_lower.upper()
                            elif attr_lower == "route":
                                is_route = True
                                method = "GET"  # default for Flask @app.route unless methods kwarg is passed
                                for kw in dec.keywords:
                                    if kw.arg == "methods":
                                        if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)) and kw.value.elts:
                                            first_elt = kw.value.elts[0]
                                            if isinstance(first_elt, ast.Constant) and isinstance(first_elt.value, str):
                                                method = first_elt.value.upper()

                        if is_route and dec.args:
                            arg0 = dec.args[0]
                            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                                route_path = arg0.value

                        if is_route and route_path:
                            # Route-level authentication detection (Depends, decorators)
                            auth = False
                            all_defaults = list(node.args.defaults) + [d for d in getattr(node.args, "kw_defaults", []) if d is not None]
                            for d in all_defaults:
                                for sub in ast.walk(d):
                                    if isinstance(sub, ast.Call):
                                        fn = getattr(sub.func, "id", None) or getattr(sub.func, "attr", None)
                                        if fn == "Depends" and sub.args:
                                            dep_name = getattr(sub.args[0], "id", None) or getattr(sub.args[0], "attr", None) or ""
                                            if any(w in dep_name.lower() for w in ("auth", "login", "user", "token", "jwt", "session", "cred", "permission", "security")):
                                                auth = True
                            if not auth:
                                auth = any(any(w in ast.unparse(d).lower() for w in ("auth", "login_required", "jwt_required", "permission_required", "require_user", "authenticated")) for d in node.decorator_list)

                            return ExtractedRoute(
                                path=route_path,
                                method=method,
                                handler_name=node.name,
                                file_path=rel_path,
                                line_number=node.lineno,
                                auth_required=auth,
                                framework="FastAPI" if isinstance(node, ast.AsyncFunctionDef) else "Flask",
                            )
                return None

        visitor = IndexVisitor(self)
        visitor.visit(tree)

        # Every module's top-level execution is an entry root (fixes init_cache_db() and singletons)
        self.entry_points.add(f"{rel_path}::__top__")

        # Check for if __name__ == "__main__": as an entry point
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test_str = ""
                try:
                    test_str = ast.unparse(node.test)
                except Exception:
                    pass
                if "__name__" in test_str and "__main__" in test_str:
                    main_key = f"{rel_path}::__main__"
                    self.entry_points.add(main_key)
                    # Mark any function called directly inside the if __name__ == "__main__" block as an entry point
                    for subnode in ast.walk(node):
                        if isinstance(subnode, ast.Call):
                            c_name = None
                            if isinstance(subnode.func, ast.Name):
                                c_name = subnode.func.id
                            elif isinstance(subnode.func, ast.Attribute):
                                c_name = subnode.func.attr
                            if c_name:
                                for s in self.symbols_by_name.get(c_name, []):
                                    if s.file_path == rel_path:
                                        self.entry_points.add(f"{s.file_path}::{s.qualified_name}")

    def _index_js_ts_file(self, rel_path: str):
        content = self.get_content(rel_path)
        lines = content.splitlines()

        # Track imported JS/TS packages
        for m in re.finditer(r"""(?:require\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"])""", content):
            mod_name = m.group(1) or m.group(2)
            if mod_name and not mod_name.startswith((".", "/")):
                self.imported_modules.add(mod_name)
                if "/" in mod_name and not mod_name.startswith("@"):
                    self.imported_modules.add(mod_name.split("/")[0])

        # Regex extract Express routes
        js_route_pattern = re.compile(
            r"""(?:app|router)\.(get|post|put|delete|patch|use)\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        )
        for idx, line in enumerate(lines, start=1):
            m = js_route_pattern.search(line)
            if m:
                method = m.group(1).upper()
                if method == "USE":
                    method = "ANY"
                path = m.group(2)
                self.routes.append(
                    ExtractedRoute(
                        path=path,
                        method=method,
                        handler_name=f"express_handler_L{idx}",
                        file_path=rel_path,
                        line_number=idx,
                        framework="Express",
                    )
                )

    def _resolve_call_graph(self):
        """
        Connects caller symbols to target callee symbols across the project.
        """
        for edge in self.call_edges:
            caller_key = f"{edge.caller_file}::{edge.caller_symbol}" if edge.caller_symbol else f"{edge.caller_file}::__top__"
            self.adjacency.setdefault(caller_key, set())

            # Find matching callee definitions
            # 1. First priority: symbol in same file
            matched_keys = []
            candidates = self.symbols_by_name.get(edge.callee_name, [])
            for c in candidates:
                if c.file_path == edge.caller_file:
                    matched_keys.append(f"{c.file_path}::{c.qualified_name}")

            # 2. If not in same file, match imported / other project files
            if not matched_keys:
                for c in candidates:
                    matched_keys.append(f"{c.file_path}::{c.qualified_name}")

            for mk in matched_keys:
                self.adjacency[caller_key].add(mk)

    def _compute_reachability(self):
        """
        Runs BFS from all identified entry points to compute the reachable subgraph.
        Three-state reachability model:
        - reachable: proven edge from an entry point.
        - unknown: no edge found, no proof of absence (default).
        - unreachable: positive evidence of a private symbol with zero references across project.
        """
        queue = list(self.entry_points)
        visited = set(self.entry_points)

        while queue:
            curr = queue.pop(0)
            for neighbor in self.adjacency.get(curr, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        self.reachable_symbols = visited

        all_referenced = set(self.dynamic_names) | set(self.exported_names) | self.all_loaded_names

        # Identify unreachable symbols in user code (exclude tests and dunder methods)
        self.unreachable_symbols = []
        for key, sym in self.symbols.items():
            if "test" in sym.file_path.lower() or sym.file_path.startswith("tests"):
                continue
            if sym.name.startswith("__") and sym.name.endswith("__"):
                continue  # dunder methods like __init__, __str__
            if sym.is_entry_point or key in self.reachable_symbols:
                continue

            # Heuristic reachability rule (Page 1 & 3): Heuristic reachability can only produce
            # 'unknown', never 'unreachable'. For non-Python languages (TS/JS/React, Java) and Spring beans,
            # symbols with no proven path remain in 'unknown' reachability state.
            ext = Path(sym.file_path).suffix.lower()
            if ext not in (".py",):
                continue

            self.unreachable_symbols.append(sym)

    def trace_workflow(self, handler_file: str, handler_name: str) -> List[Tuple[str, int, str]]:
        """
        Traces the execution path starting from a route handler.
        Returns a list of (file_path, line_number, step_description).
        """
        start_key = f"{handler_file}::{handler_name}"
        steps: List[Tuple[str, int, str]] = []

        handler_sym = self.symbols.get(start_key)
        line = handler_sym.line_number if handler_sym else 1
        steps.append((handler_file, line, f"Entry handler '{handler_name}()'"))

        # Follow outgoing edges up to 5 steps deep
        visited = {start_key}
        queue = [start_key]

        while queue and len(steps) < 6:
            curr = queue.pop(0)
            for callee_key in sorted(self.adjacency.get(curr, set())):
                if callee_key not in visited:
                    visited.add(callee_key)
                    callee_sym = self.symbols.get(callee_key)
                    if callee_sym:
                        steps.append(
                            (
                                callee_sym.file_path,
                                callee_sym.line_number,
                                f"Calls '{callee_sym.name}()' ({callee_sym.symbol_type}) in {Path(callee_sym.file_path).name}:{callee_sym.line_number}",
                            )
                        )
                        queue.append(callee_key)

        return steps
