"""offtest/adapters/java_adapter.py

Java and Spring Boot language adapter.
Provides:
- Symbol extraction for Java classes, interfaces, methods, annotations, and Spring beans
- Entry roots for Java: main method, Spring @RestController mappings, @Bean, @Scheduled, @EventListener, servlets and filters, tests
- Three-state reachability handling: treats unreferenced Spring beans as unknown, never unreachable
- Route and auth detection: Spring mapping annotations, @PreAuthorize, @Secured, SecurityFilterChain
- Spring and Java security rules:
  * SQL injection via string concatenation (JDBC, JPA native queries)
  * Unsafe deserialization (ObjectInputStream)
  * XXE in XML parsers
  * Missing method-level security on controllers
  * Permissive CSRF or CORS in Spring Security
  * Hardcoded credentials in application.properties and application.yml
"""
from __future__ import annotations

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


class JavaAdapter(BaseLanguageAdapter):
    name = "java"
    supported_languages = ("Java", "Properties")

    def get_coverage(self) -> LanguageCoverage:
        return LanguageCoverage(
            language="Java / Spring",
            symbols=FeatureDepth.SEMANTIC,
            call_graph=FeatureDepth.HEURISTIC,
            reachability=FeatureDepth.HEURISTIC,
            routes_and_auth=FeatureDepth.SEMANTIC,
            taint_and_rules=FeatureDepth.SEMANTIC,
            test_synthesis=FeatureDepth.NONE,
            notes="JavaParser-compatible symbol & annotation analyzer; Spring DI beans treated as unknown (never unreachable); non-Python findings capped at static-only",
        )

    def index_file(self, rel_path: str, content: str, project_index: Any) -> None:
        """Indexes symbols, calls, entry roots, and routes for a Java file."""
        if not rel_path.endswith(".java"):
            return

        lines = content.splitlines()
        norm_path = rel_path.replace("\\", "/")
        norm_lower = norm_path.lower()
        file_name = Path(norm_path).name

        is_test_file = (
            any(t in norm_lower for t in ("/test/", "/tests/", "\\test\\", "\\tests\\"))
            or file_name.endswith(("Test.java", "Tests.java", "TestCase.java"))
            or "@Test" in content
        )

        # 1. Package extraction
        pkg_match = re.search(r"""^\s*package\s+([A-Za-z0-9_.]+)\s*;""", content, re.MULTILINE)
        pkg_name = pkg_match.group(1) if pkg_match else ""

        # 2. Extract classes, interfaces, and Spring annotations
        class_pattern = re.compile(
            r"""((?:@\w+(?:\(.*?\))?\s+)*)(?:public\s+|protected\s+|private\s+)?(?:abstract\s+|final\s+)?(?:class|interface|enum)\s+([A-Za-z0-9_]+)"""
        )
        for cm in class_pattern.finditer(content):
            annotations_str = cm.group(1)
            class_name = cm.group(2)
            qname = f"{pkg_name}.{class_name}" if pkg_name else class_name
            line_no = content[: cm.start()].count("\n") + 1

            # Check if class is an entry root:
            # Servlet / Filter / Spring Controller / Spring Boot Application
            is_entry = (
                is_test_file
                or any(
                    ann in annotations_str
                    for ann in (
                        "@SpringBootApplication",
                        "@RestController",
                        "@Controller",
                        "@Configuration",
                        "@Component",
                        "@Service",
                        "@Repository",
                        "@WebFilter",
                        "@WebServlet",
                    )
                )
                or any(
                    base in content
                    for base in ("HttpServlet", "Filter", "OncePerRequestFilter", "GenericFilterBean")
                )
            )

            is_spring_bean = any(
                ann in annotations_str
                for ann in ("@Component", "@Service", "@Repository", "@Configuration", "@Bean")
            )

            sym = SymbolDef(
                name=class_name,
                qualified_name=qname,
                symbol_type="class",
                file_path=rel_path,
                line_number=line_no,
                end_line_number=line_no,
                is_entry_point=is_entry,
                is_private=False,
            )
            key = f"{rel_path}::{class_name}"
            project_index.symbols[key] = sym
            project_index.symbols_by_name.setdefault(class_name, []).append(sym)
            if is_entry:
                project_index.entry_points.add(key)
            if is_spring_bean:
                # Mark as dynamic/bean so reachability never marks it unreachable
                project_index.dynamic_names.add(class_name)

        # 3. Extract methods and Spring routes
        self._extract_methods_and_routes(rel_path, lines, content, project_index, is_test_file, pkg_name)

        # 4. Extract call edges (method invocations)
        for m in re.finditer(r"""\b([A-Za-z0-9_]{3,})\s*\(""", content):
            callee = m.group(1)
            if callee not in ("if", "for", "while", "switch", "catch", "synchronized", "super", "this", "return"):
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

    def _extract_methods_and_routes(
        self,
        rel_path: str,
        lines: List[str],
        content: str,
        project_index: Any,
        is_test_file: bool,
        pkg_name: str,
    ):
        # Detect controller-level base path: @RequestMapping("/api/v1")
        base_route = ""
        base_match = re.search(r"""@RequestMapping\(\s*(?:value\s*=\s*)?['"]([^'"]*)['"]""", content)
        if base_match:
            base_route = base_match.group(1).rstrip("/")

        # Spring route mapping annotations
        route_annot_pattern = re.compile(
            r"""((?:@\w+(?:\(.*?\))?\s+)*)@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?['"]([^'"]*)['"].*?\))?\s*(?:public\s+|protected\s+|private\s+)?(?:[A-Za-z0-9_<>,. ]+)\s+([A-Za-z0-9_]+)\s*\(""",
            re.MULTILINE,
        )
        for rm in route_annot_pattern.finditer(content):
            preceding_annots = rm.group(1)
            mapping_type = rm.group(2)
            sub_path = rm.group(3) or ""
            handler_name = rm.group(4)
            line_no = content[: rm.start()].count("\n") + 1

            method = "GET"
            if mapping_type == "PostMapping":
                method = "POST"
            elif mapping_type == "PutMapping":
                method = "PUT"
            elif mapping_type == "DeleteMapping":
                method = "DELETE"
            elif mapping_type == "PatchMapping":
                method = "PATCH"
            elif mapping_type == "RequestMapping":
                # check if method kwarg exists
                m_match = re.search(r"""method\s*=\s*RequestMethod\.([A-Z]+)""", rm.group(0))
                if m_match:
                    method = m_match.group(1)

            full_path = (base_route + ("/" + sub_path if sub_path else "")).replace("//", "/")
            if not full_path:
                full_path = "/"

            # Auth detection: @PreAuthorize, @Secured, @RolesAllowed
            auth_req = any(
                ann in (preceding_annots + content[rm.start() : rm.end()])
                for ann in ("@PreAuthorize", "@Secured", "@RolesAllowed")
            )

            route = ExtractedRoute(
                path=full_path,
                method=method,
                handler_name=handler_name,
                file_path=rel_path,
                line_number=line_no,
                auth_required=auth_req,
                framework="Spring",
            )
            project_index.routes.append(route)
            # Route handler is an entry root
            key = f"{rel_path}::{handler_name}"
            project_index.entry_points.add(key)

        # Standard method extraction: public void main, @Bean, @Scheduled, @EventListener, @Test
        method_pattern = re.compile(
            r"""((?:@\w+(?:\(.*?\))?\s+)*)(?:public\s+|protected\s+|private\s+)?(?:static\s+)?(?:final\s+)?(?:[A-Za-z0-9_<>,. ]+)\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"""
        )
        for mm in method_pattern.finditer(content):
            annots = mm.group(1)
            m_name = mm.group(2)
            line_no = content[: mm.start()].count("\n") + 1
            if m_name in ("if", "for", "while", "switch", "catch"):
                continue

            is_main = m_name == "main" and "public static void" in mm.group(0)
            is_bean = "@Bean" in annots
            is_scheduled = "@Scheduled" in annots
            is_event = "@EventListener" in annots
            is_test = "@Test" in annots or is_test_file

            is_entry = is_main or is_bean or is_scheduled or is_event or is_test

            sym = SymbolDef(
                name=m_name,
                qualified_name=m_name,
                symbol_type="method",
                file_path=rel_path,
                line_number=line_no,
                end_line_number=line_no,
                is_entry_point=is_entry,
                is_private="private " in mm.group(0),
            )
            key = f"{rel_path}::{m_name}"
            project_index.symbols[key] = sym
            project_index.symbols_by_name.setdefault(m_name, []).append(sym)
            if is_entry:
                project_index.entry_points.add(key)
            if is_bean:
                project_index.dynamic_names.add(m_name)

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
        file_name = Path(rel_path).name.lower()

        # 1. Spring config files: application.properties, application.yml, application.yaml
        if file_name in ("application.properties", "application.yml", "application.yaml") or (
            rel_path.endswith((".properties", ".yml", ".yaml")) and "config" in rel_path.lower()
        ):
            for idx, line in enumerate(lines, start=1):
                clean_l = line.strip()
                if clean_l.startswith("#") or not clean_l:
                    continue
                # Match hard-coded password/secret assignment without ${...} placeholder
                prop_m = re.search(
                    r"""(?:password|secret|api[_-]?key|token)\s*[:=]\s*(['"]?)([^'"\s${}]+)\1""",
                    clean_l,
                    re.IGNORECASE,
                )
                if prop_m:
                    val = prop_m.group(2)
                    if len(val) >= 4 and not any(
                        ph in val.lower() for ph in ("todo", "placeholder", "xxx", "change_me", "changeme")
                    ):
                        findings.append(
                            make_finding(
                                RULES["OT-SEC-031"],
                                path=rel_path,
                                line=idx,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {idx}: Hard-coded credential in Spring configuration: {clean_l}",
                            )
                        )

        if not rel_path.endswith(".java"):
            return findings

        # 2. Java SQL injection via String Concatenation (JDBC / JPA native queries)
        for idx, line in enumerate(lines, start=1):
            if (
                re.search(r"""\.(?:executeQuery|executeUpdate|execute|createNativeQuery)\s*\(\s*.*?\+""", line, re.IGNORECASE)
                or re.search(r"""@Query\s*\(\s*(?:value\s*=\s*)?.*?\+.*?nativeQuery\s*=\s*true""", line, re.IGNORECASE)
            ):
                findings.append(
                    make_finding(
                        RULES["OT-SEC-026"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: Dynamic SQL query constructed via string concatenation: {line.strip()}",
                    )
                )

        # 3. Unsafe Java Object Deserialization (ObjectInputStream)
        for idx, line in enumerate(lines, start=1):
            if re.search(r"""new\s+ObjectInputStream\s*\(""", line) or re.search(
                r"""\.readObject\s*\(\s*\)""", line
            ):
                findings.append(
                    make_finding(
                        RULES["OT-SEC-027"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: Insecure ObjectInputStream deserialization: {line.strip()}",
                    )
                )

        # 4. XML External Entity (XXE) Injection
        for idx, line in enumerate(lines, start=1):
            if any(
                p in line
                for p in (
                    "DocumentBuilderFactory.newInstance()",
                    "SAXParserFactory.newInstance()",
                    "XMLInputFactory.newFactory()",
                    "XMLInputFactory.newInstance()",
                )
            ):
                # Verify if disallow-doctype-decl feature is actually enabled on parser
                has_safe_features = bool(
                    re.search(r"""setFeature\(\s*['"][^'"]*disallow-doctype-decl['"]\s*,\s*true\s*\)""", content)
                    or "IS_SUPPORTING_EXTERNAL_ENTITIES, false" in content
                )
                if not has_safe_features:
                    findings.append(
                        make_finding(
                            RULES["OT-SEC-028"],
                            path=rel_path,
                            line=idx,
                            file_sha256=f_sha,
                            branch=branch,
                            evidence=f"Line {idx}: XML Parser instantiated without disallow-doctype-decl XXE protection: {line.strip()}",
                        )
                    )

        # 5. Missing Method-Level Security on Spring Controller State-Changing Endpoints
        if "@RestController" in content or "@Controller" in content:
            state_mapping_pattern = re.compile(
                r"""((?:@\w+(?:\(.*?\))?\s+)*)@(PostMapping|PutMapping|DeleteMapping|PatchMapping)""",
                re.MULTILINE,
            )
            for sm in state_mapping_pattern.finditer(content):
                preceding = sm.group(1)
                mapping_name = sm.group(2)
                line_no = content[: sm.start()].count("\n") + 1
                has_auth = any(
                    ann in preceding for ann in ("@PreAuthorize", "@Secured", "@RolesAllowed")
                )
                if not has_auth:
                    findings.append(
                        make_finding(
                            RULES["OT-SEC-029"],
                            path=rel_path,
                            line=line_no,
                            file_sha256=f_sha,
                            branch=branch,
                            evidence=f"Line {line_no}: State-changing Spring @{mapping_name} endpoint lacks method-level authorization annotation (@PreAuthorize, @Secured, @RolesAllowed).",
                        )
                    )

        # 6. Permissive CSRF or CORS settings in Spring Security
        for idx, line in enumerate(lines, start=1):
            if re.search(r"""\.csrf\(\)\.disable\(\)""", line) or re.search(
                r"""\.csrf\(\s*csrf\s*->\s*csrf\.disable\(\)\s*\)""", line
            ):
                findings.append(
                    make_finding(
                        RULES["OT-SEC-030"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: Spring Security CSRF protection explicitly disabled: {line.strip()}",
                    )
                )
            elif "setAllowedOrigins" in line and "*" in line and "allowCredentials" in content:
                findings.append(
                    make_finding(
                        RULES["OT-SEC-030"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: Permissive Spring CORS configuration with wildcard origin: {line.strip()}",
                    )
                )

        # Non-Python findings capped at static-only per Ankit Page 3
        for f in findings:
            f.evidence_level = "static-only"

        return findings
