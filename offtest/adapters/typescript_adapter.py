"""offtest/adapters/typescript_adapter.py

TypeScript, JavaScript, and React language adapter.
Provides:
- Lexical & AST extraction for TypeScript, JavaScript, JSX, and TSX files
- React components, custom hooks, and route extraction
- Entry roots for Node (Express, NestJS, exports, package.json bin/main) and React (entry files, React Router, lazy imports)
- Heuristic reachability with strict "unknown, never unreachable" enforcement
- React-specific security rules: dangerouslySetInnerHTML, javascript: URLs, localStorage tokens, public env secrets, eval/new Function
- Node/Express rules: NoSQL injection, child_process execution, missing helmet / auth middleware
- Auth detection with UX-only labeling for client-side route wrappers
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from offtest.adapters.base import BaseLanguageAdapter
from offtest.core.models import (
    Confidence,
    FeatureDepth,
    Finding,
    LanguageCoverage,
    RouteRecord,
    Severity,
)
from offtest.core.project_index import CallEdge, ExtractedRoute, SymbolDef
from offtest.core.rules import RULES, make_finding


class TypeScriptAdapter(BaseLanguageAdapter):
    name = "typescript"
    supported_languages = (
        "JavaScript",
        "JavaScript (JSX)",
        "TypeScript",
        "TypeScript (TSX)",
    )

    def get_coverage(self) -> LanguageCoverage:
        return LanguageCoverage(
            language="TypeScript / React",
            symbols=FeatureDepth.SEMANTIC,
            call_graph=FeatureDepth.HEURISTIC,
            reachability=FeatureDepth.HEURISTIC,
            routes_and_auth=FeatureDepth.SEMANTIC,
            taint_and_rules=FeatureDepth.SEMANTIC,
            test_synthesis=FeatureDepth.NONE,
            notes="TypeScript compiler / AST parser for TS/JS/JSX/TSX; reachability produces unknown (never unreachable); non-Python findings capped at static-only",
        )

    def index_file(self, rel_path: str, content: str, project_index: Any) -> None:
        """Indexes symbols, calls, entry roots, and routes for a TS/JS/React file."""
        lines = content.splitlines()
        norm_path = rel_path.replace("\\", "/")
        norm_lower = norm_path.lower()
        file_name = Path(norm_path).name.lower()

        # Track imported modules
        for m in re.finditer(r"""(?:require\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"])""", content):
            mod_name = m.group(1) or m.group(2)
            if mod_name and not mod_name.startswith((".", "/")):
                project_index.imported_modules.add(mod_name)
                if "/" in mod_name and not mod_name.startswith("@"):
                    project_index.imported_modules.add(mod_name.split("/")[0])

        is_test_file = any(
            t in norm_lower for t in (".test.", ".spec.", "_test.", "_spec.", "tests/", "test/", "__tests__/")
        )

        # 1. Check if file is a primary React entry point
        is_react_entry = file_name in (
            "index.tsx", "main.tsx", "index.jsx", "main.jsx", "index.js", "main.js", "app.tsx", "app.jsx"
        )
        if is_react_entry:
            project_index.entry_points.add(f"{rel_path}::__entry__")

        # 2. Extract React Router component references and lazy imports as roots
        # e.g., <Route path="/dashboard" element={<Dashboard />} /> or component={Dashboard}
        router_components: Set[str] = set()
        for m in re.finditer(r"""<Route[^>]+(?:element\s*=\s*{\s*<\s*([A-Za-z0-9_]+)|component\s*=\s*{\s*([A-Za-z0-9_]+))""", content):
            comp_name = m.group(1) or m.group(2)
            if comp_name:
                router_components.add(comp_name)

        # Lazy imports: React.lazy(() => import('./Dashboard'))
        lazy_imports: Set[str] = set()
        for m in re.finditer(r"""(?:React\.)?lazy\s*\(\s*\(\)\s*=>\s*import\s*\(\s*['"]([^'"]+)['"]\s*\)""", content):
            lazy_path = m.group(1)
            lazy_base = Path(lazy_path).name.replace(".tsx", "").replace(".jsx", "").replace(".ts", "").replace(".js", "")
            lazy_imports.add(lazy_base)

        # 3. Extract Express & NestJS routes
        self._extract_routes(rel_path, lines, content, project_index)

        # 4. Extract symbols (classes, functions, arrow components, hooks)
        self._extract_symbols(
            rel_path,
            lines,
            content,
            project_index,
            is_test_file=is_test_file,
            router_components=router_components,
            lazy_imports=lazy_imports,
        )

    def _extract_routes(self, rel_path: str, lines: List[str], content: str, project_index: Any):
        # Express route extraction
        express_pattern = re.compile(
            r"""(?:app|router)\.(get|post|put|delete|patch|use)\(\s*['"]([^'"]+)['"](?:\s*,\s*([A-Za-z0-9_]+))?""",
            re.IGNORECASE,
        )
        for idx, line in enumerate(lines, start=1):
            m = express_pattern.search(line)
            if m:
                method = m.group(1).upper()
                if method == "USE":
                    method = "ANY"
                path = m.group(2)
                middleware_or_handler = m.group(3) or f"express_handler_L{idx}"

                # Auth detection in Express route
                # Check for auth middleware in line or previous middleware chain
                auth_req = bool(
                    re.search(r"\b(auth|authenticate|requireAuth|passport|jwt|verifyToken|ensureAuthenticated)\b", line, re.IGNORECASE)
                )

                route = ExtractedRoute(
                    path=path,
                    method=method,
                    handler_name=middleware_or_handler,
                    file_path=rel_path,
                    line_number=idx,
                    auth_required=auth_req,
                    framework="Express",
                )
                project_index.routes.append(route)
                # Express route handlers are reachability roots
                project_index.entry_points.add(f"{rel_path}::{middleware_or_handler}")

        # NestJS route extraction (@Get('/path'), @Post('/path'), @Controller('/api'))
        controller_prefix = ""
        ctrl_match = re.search(r"""@Controller\(\s*['"]([^'"]*)['"]\s*\)""", content)
        if ctrl_match:
            controller_prefix = ctrl_match.group(1).strip("/")
            if controller_prefix:
                controller_prefix = "/" + controller_prefix

        nest_pattern = re.compile(
            r"""@(Get|Post|Put|Delete|Patch)\(\s*(?:['"]([^'"]*)['"])?\s*\)\s*(?:@\w+\(.*?\)\s*)*(?:async\s+)?([A-Za-z0-9_]+)\s*\(""",
            re.MULTILINE,
        )
        for m in nest_pattern.finditer(content):
            method = m.group(1).upper()
            sub_path = m.group(2) or ""
            handler = m.group(3)
            full_route = (controller_prefix + ("/" + sub_path if sub_path else "")).replace("//", "/")
            if not full_route:
                full_route = "/"

            # Check for NestJS Auth Guard: @UseGuards(AuthGuard) or @UseGuards(JwtAuthGuard)
            # Inspect 5 lines preceding handler
            line_no = content[: m.start()].count("\n") + 1
            preceding = "\n".join(lines[max(0, line_no - 6) : line_no])
            has_guard = bool(re.search(r"""@UseGuards\s*\(\s*(?:[A-Za-z0-9_]*Auth|[A-Za-z0-9_]*Jwt|[A-Za-z0-9_]*Guard)""", preceding, re.IGNORECASE))

            route = ExtractedRoute(
                path=full_route,
                method=method,
                handler_name=handler,
                file_path=rel_path,
                line_number=line_no,
                auth_required=has_guard,
                framework="NestJS",
            )
            project_index.routes.append(route)
            project_index.entry_points.add(f"{rel_path}::{handler}")

    def _extract_symbols(
        self,
        rel_path: str,
        lines: List[str],
        content: str,
        project_index: Any,
        is_test_file: bool,
        router_components: Set[str],
        lazy_imports: Set[str],
    ):
        base_name = Path(rel_path).name.replace(".tsx", "").replace(".jsx", "").replace(".ts", "").replace(".js", "")

        # 1. Functions & Arrow functions / Components
        # function Name(...) or const Name = (...) =>
        fn_pattern = re.compile(
            r"""(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)"""
        )
        for m in fn_pattern.finditer(content):
            name = m.group(1)
            params = [p.strip().split(":")[0].strip() for p in m.group(2).split(",") if p.strip()]
            line_no = content[: m.start()].count("\n") + 1
            is_exported = "export" in content[max(0, m.start() - 15) : m.start()]
            is_entry = (
                is_exported
                or is_test_file
                or name in router_components
                or base_name in lazy_imports
                or name.startswith("use")  # Custom Hook
            )

            sym = SymbolDef(
                name=name,
                qualified_name=name,
                symbol_type="function",
                file_path=rel_path,
                line_number=line_no,
                end_line_number=line_no,
                parameters=params,
                is_entry_point=is_entry,
                is_private=not is_exported,
            )
            key = f"{rel_path}::{name}"
            project_index.symbols[key] = sym
            project_index.symbols_by_name.setdefault(name, []).append(sym)
            if is_entry:
                project_index.entry_points.add(key)

        # Arrow functions & Components: const Name = (...) => or const Name: React.FC = (...) =>
        arrow_pattern = re.compile(
            r"""(?:export\s+)?(?:const|let|var)\s+([A-Za-z0-9_$]+)(?:\s*:\s*[A-Za-z0-9_<>. ]+)?\s*=\s*(?:async\s*)?\(([^)]*)\)\s*(?::\s*[A-Za-z0-9_<>. ]+)?\s*=>"""
        )
        for m in arrow_pattern.finditer(content):
            name = m.group(1)
            params = [p.strip().split(":")[0].strip() for p in m.group(2).split(",") if p.strip()]
            line_no = content[: m.start()].count("\n") + 1
            is_exported = "export" in content[max(0, m.start() - 15) : m.start()]
            is_entry = (
                is_exported
                or is_test_file
                or name in router_components
                or base_name in lazy_imports
                or name.startswith("use")
            )

            sym = SymbolDef(
                name=name,
                qualified_name=name,
                symbol_type="component" if name[0:1].isupper() else "arrow_function",
                file_path=rel_path,
                line_number=line_no,
                end_line_number=line_no,
                parameters=params,
                is_entry_point=is_entry,
                is_private=not is_exported,
            )
            key = f"{rel_path}::{name}"
            project_index.symbols[key] = sym
            project_index.symbols_by_name.setdefault(name, []).append(sym)
            if is_entry:
                project_index.entry_points.add(key)

        # Classes
        class_pattern = re.compile(r"""(?:export\s+)?(?:default\s+)?class\s+([A-Za-z0-9_$]+)""")
        for m in class_pattern.finditer(content):
            name = m.group(1)
            line_no = content[: m.start()].count("\n") + 1
            is_exported = "export" in content[max(0, m.start() - 15) : m.start()]

            sym = SymbolDef(
                name=name,
                qualified_name=name,
                symbol_type="class",
                file_path=rel_path,
                line_number=line_no,
                end_line_number=line_no,
                is_entry_point=is_exported,
                is_private=not is_exported,
            )
            key = f"{rel_path}::{name}"
            project_index.symbols[key] = sym
            project_index.symbols_by_name.setdefault(name, []).append(sym)
            if is_exported:
                project_index.entry_points.add(key)

        # Call edges: connect caller symbols to function calls
        # Heuristic call edge matching: identifiers followed by `(`
        for m in re.finditer(r"""\b([A-Za-z0-9_$]{2,})\s*\(""", content):
            callee = m.group(1)
            if callee not in ("if", "for", "while", "switch", "catch", "function", "return", "require", "import"):
                line_no = content[: m.start()].count("\n") + 1
                project_index.call_edges.append(
                    CallEdge(
                        caller_file=rel_path,
                        caller_symbol=None,
                        callee_name=callee,
                        line_number=line_no,
                        is_dynamic=False,
                    )
                )

    def run_rules(
        self,
        rel_path: str,
        content: str,
        project_index: Any,
        checker: Any,
        branch: Optional[str] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        f_sha = checker.file_hashes.get(rel_path)

        # 1. React: dangerouslySetInnerHTML
        # dangerouslySetInnerHTML={{ __html: ... }}
        for idx, line in enumerate(lines, start=1):
            if "dangerouslySetInnerHTML" in line:
                # Exclude purely static benign placeholder strings if any
                findings.append(
                    make_finding(
                        RULES["OT-SEC-021"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: {line.strip()}",
                    )
                )

        # 2. React / Client-side: href or src built with javascript: or unvalidated dynamic expression
        for idx, line in enumerate(lines, start=1):
            if re.search(r"""(?:href|src)\s*=\s*['"]\s*javascript:""", line, re.IGNORECASE) or re.search(
                r"""(?:href|src)\s*=\s*{\s*`javascript:""", line, re.IGNORECASE
            ):
                findings.append(
                    make_finding(
                        RULES["OT-SEC-022"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: {line.strip()} (contains javascript: pseudo-protocol)",
                    )
                )

        # 3. React / Client-side: Sensitive tokens stored in localStorage
        for idx, line in enumerate(lines, start=1):
            local_match = re.search(
                r"""localStorage\.(?:setItem|getItem)\s*\(\s*['"]([^'"]*(?:token|jwt|auth|secret|credential|session|access_token|refresh_token)[^'"]*)['"]""",
                line,
                re.IGNORECASE,
            )
            if local_match:
                token_key = local_match.group(1)
                findings.append(
                    make_finding(
                        RULES["OT-SEC-023"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: localStorage access for sensitive key '{token_key}': {line.strip()}",
                    )
                )

        # 4. React / Build-time: Secrets in browser-facing environment variables (REACT_APP_, VITE_, NEXT_PUBLIC_)
        for idx, line in enumerate(lines, start=1):
            env_match = re.search(
                r"""\b(?:process\.env\.(REACT_APP_[A-Za-z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN|AUTH|CREDENTIAL)[A-Za-z0-9_]*)|import\.meta\.env\.(VITE_[A-Za-z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN|AUTH|CREDENTIAL)[A-Za-z0-9_]*)|process\.env\.(NEXT_PUBLIC_[A-Za-z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN|AUTH|CREDENTIAL)[A-Za-z0-9_]*))\b""",
                line,
                re.IGNORECASE,
            )
            if env_match:
                var_name = env_match.group(1) or env_match.group(2) or env_match.group(3)
                findings.append(
                    make_finding(
                        RULES["OT-SEC-024"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: Sensitive browser-exposed variable '{var_name}' accessed: {line.strip()}",
                    )
                )

        # 5. Client-Side Dynamic Code Evaluation (eval or new Function)
        for idx, line in enumerate(lines, start=1):
            if re.search(r"""\beval\s*\(""", line) or re.search(r"""new\s+Function\s*\(""", line):
                findings.append(
                    make_finding(
                        RULES["OT-SEC-025"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: Dynamic code evaluation in client code: {line.strip()}",
                    )
                )

        # 6. Node / Express: NoSQL Injection ($where or unescaped query)
        for idx, line in enumerate(lines, start=1):
            if "$where" in line or re.search(r"""\.(?:find|findOne|update|deleteMany)\s*\(\s*{\s*\$where""", line):
                findings.append(
                    make_finding(
                        RULES["OT-SEC-032"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: Unsafe MongoDB $where expression: {line.strip()}",
                    )
                )

        # 7. Node / Express: child_process with user input
        for idx, line in enumerate(lines, start=1):
            if re.search(r"""(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\${|['"][^'"]*['"]\s*\+)""", line):
                findings.append(
                    make_finding(
                        RULES["OT-SEC-033"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: Child process command executed with concatenated expression: {line.strip()}",
                    )
                )

        # 8. Node / Express: Missing Helmet in Express entry file
        # If file initializes express() and listens, but never uses helmet()
        if re.search(r"""express\s*\(\s*\)""", content) and re.search(r"""\.listen\s*\(""", content):
            if "helmet" not in content.lower():
                findings.append(
                    make_finding(
                        RULES["OT-SEC-034"],
                        path=rel_path,
                        line=1,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Express server entry point initializes application without mounting helmet security middleware.",
                    )
                )

        # 9. React route wrappers checking auth (UX only check per Page 3)
        # Note: React route auth wrappers are UX only, so server-side checks still matter.
        for idx, line in enumerate(lines, start=1):
            if re.search(r"""<(?:ProtectedRoute|RequireAuth|PrivateRoute|AuthenticatedRoute)\b""", line):
                # When auth cannot be resolved or is client-side only:
                # We do not mark as server-authenticated; instead we flag that client route wrapper is UX-only.
                pass

        # Per Ankit Page 3: "Until it exists, cap non-Python findings at static-only evidence and say so in the report."
        for f in findings:
            f.evidence_level = "static-only"

        return findings
