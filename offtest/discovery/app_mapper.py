import ast
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from offtest.core.models import (
    APIRecord,
    EvidenceStatus,
    FeatureRecord,
    FileRecord,
    IntegrationRecord,
    RouteRecord,
    WorkflowRecord,
)


class ApplicationMapper:
    def __init__(self, repo_dir: Path, files: List[FileRecord]):
        self.repo_dir = repo_dir
        self.files = files
        self.test_files = [f for f in files if f.category == "test"]

    def map_application(self) -> Tuple[List[RouteRecord], List[APIRecord], List[FeatureRecord], List[WorkflowRecord], List[IntegrationRecord]]:
        routes: List[RouteRecord] = []
        apis: List[APIRecord] = []
        features: List[FeatureRecord] = []
        workflows: List[WorkflowRecord] = []
        integrations: List[IntegrationRecord] = []

        # Gather test contents to link tests
        test_file_contents: Dict[str, str] = {}
        for tf in self.test_files:
            try:
                full_path = self.repo_dir / tf.path
                if full_path.is_file() and tf.size_bytes < 500000:
                    test_file_contents[tf.path] = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        # Regex patterns for Python routes (Flask / FastAPI)
        py_route_pattern = re.compile(
            r"""@(?:app|router|api)\.(get|post|put|delete|patch|route)\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        )
        # Regex patterns for JS/TS routes (Express)
        js_route_pattern = re.compile(
            r"""(?:app|router)\.(get|post|put|delete|patch|use)\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        )
        # Django urls
        django_route_pattern = re.compile(
            r"""(?:path|re_path)\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        )
        # Feature flag patterns
        feature_flag_pattern = re.compile(
            r"""(?:is_feature_enabled|isEnabled|useFeature|feature_flags\.get|FEATURE_)\s*\(\s*['"]([^'"]+)['"]|\b(FEATURE_[A-Z0-9_]+)\b"""
        )

        detected_integrations: Dict[str, Tuple[str, Set[str]]] = {}

        # 1. Inspect source files
        for f in self.files:
            if f.disposition.value != "analyzed":
                continue

            full_path = self.repo_dir / f.path
            if not full_path.is_file() or f.size_bytes > 1_000_000:
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()

            # Python AST and Regex parsing
            if f.language == "Python":
                for line_idx, line in enumerate(lines, start=1):
                    # Check routes
                    m = py_route_pattern.search(line)
                    if m:
                        method = m.group(1).upper()
                        path = m.group(2)
                        if method == "ROUTE":
                            method = "ANY"
                        
                        is_api = path.startswith("/api") or "/v1/" in path or "/v2/" in path
                        if is_api:
                            apis.append(
                                APIRecord(
                                    endpoint=path,
                                    method=method,
                                    file_path=f.path,
                                    line_number=line_idx,
                                    status=EvidenceStatus.OBSERVED,
                                    notes="FastAPI/Flask API route detected",
                                )
                            )
                        else:
                            routes.append(
                                RouteRecord(
                                    path=path,
                                    method=method,
                                    file_path=f.path,
                                    line_number=line_idx,
                                    status=EvidenceStatus.OBSERVED,
                                    notes="FastAPI/Flask web route detected",
                                )
                            )

                    # Django routes
                    dm = django_route_pattern.search(line)
                    if dm and "url" in f.path.lower():
                        path = "/" + dm.group(1).lstrip("^").rstrip("$")
                        routes.append(
                            RouteRecord(
                                path=path,
                                method="ANY",
                                file_path=f.path,
                                line_number=line_idx,
                                status=EvidenceStatus.OBSERVED,
                                notes="Django URL route detected",
                            )
                        )

            # JavaScript / TypeScript route parsing
            elif f.language in ["JavaScript", "TypeScript", "JavaScript (JSX)", "TypeScript (TSX)"]:
                for line_idx, line in enumerate(lines, start=1):
                    m = js_route_pattern.search(line)
                    if m:
                        method = m.group(1).upper()
                        path = m.group(2)
                        is_api = path.startswith("/api") or "/v1/" in path
                        if is_api:
                            apis.append(
                                APIRecord(
                                    endpoint=path,
                                    method=method,
                                    file_path=f.path,
                                    line_number=line_idx,
                                    status=EvidenceStatus.OBSERVED,
                                    notes="Express / Node API endpoint detected",
                                )
                            )
                        else:
                            routes.append(
                                RouteRecord(
                                    path=path,
                                    method=method,
                                    file_path=f.path,
                                    line_number=line_idx,
                                    status=EvidenceStatus.OBSERVED,
                                    notes="Express / Node web route detected",
                                )
                            )

            # HTML files as routes / screens
            elif f.language == "HTML":
                page_route = "/" + f.path.replace("\\", "/")
                if page_route.endswith("/index.html"):
                    page_route = page_route[:-10] or "/"
                routes.append(
                    RouteRecord(
                        path=page_route,
                        method="GET",
                        file_path=f.path,
                        line_number=1,
                        status=EvidenceStatus.OBSERVED,
                        notes="Static HTML page / screen",
                    )
                )

            # Feature flags scan
            for line_idx, line in enumerate(lines, start=1):
                fm = feature_flag_pattern.search(line)
                if fm:
                    flag_name = fm.group(1) or fm.group(2)
                    if flag_name:
                        # Find linked tests
                        linked = []
                        for tf_path, t_content in test_file_contents.items():
                            if flag_name in t_content:
                                linked.append(tf_path)
                        features.append(
                            FeatureRecord(
                                name=f"Feature Toggle: {flag_name}",
                                flag_key=flag_name,
                                file_path=f.path,
                                line_number=line_idx,
                                status=EvidenceStatus.OBSERVED,
                                linked_tests=linked,
                            )
                        )

            # Integrations heuristics
            lower_content = content.lower()
            if "sqlite3" in lower_content or "sqlite://" in lower_content:
                detected_integrations.setdefault("SQLite Database", ("Database", set()))[1].add(f.path)
            if "postgresql" in lower_content or "psycopg2" in lower_content or "postgres://" in lower_content:
                detected_integrations.setdefault("PostgreSQL", ("Database", set()))[1].add(f.path)
            if "redis" in lower_content:
                detected_integrations.setdefault("Redis Cache/Broker", ("Cache/Broker", set()))[1].add(f.path)
            if "stripe" in lower_content:
                detected_integrations.setdefault("Stripe Payment Gateway", ("Payment", set()))[1].add(f.path)
            if "sendgrid" in lower_content or "nodemailer" in lower_content:
                detected_integrations.setdefault("Email Service", ("Email", set()))[1].add(f.path)
            if "boto3" in lower_content or "aws-sdk" in lower_content:
                detected_integrations.setdefault("AWS Cloud Services", ("Cloud Provider", set()))[1].add(f.path)
            if "jwt" in lower_content or "jsonwebtoken" in lower_content or "oauth" in lower_content:
                detected_integrations.setdefault("Token / OAuth Authentication", ("Authentication", set()))[1].add(f.path)

        # Build IntegrationRecords
        for name, (cat, files_set) in detected_integrations.items():
            integrations.append(
                IntegrationRecord(
                    name=name,
                    category=cat,
                    detected_in=sorted(list(files_set)),
                    status=EvidenceStatus.OBSERVED,
                )
            )

        # 2. Workflow Discovery
        # Scan for CI/CD workflows
        for f in self.files:
            if ".github/workflows" in f.path or ".gitlab-ci" in f.path:
                workflows.append(
                    WorkflowRecord(
                        name=f"CI/CD Pipeline: {Path(f.path).name}",
                        description="Automated continuous integration workflow",
                        entry_point=f.path,
                        related_files=[f.path],
                        linked_tests=[],
                        status=EvidenceStatus.OBSERVED,
                        steps=["Build / Lint / Test pipeline defined in CI configuration"],
                    )
                )

        # Heuristic application workflows based on discovered routes & files
        route_paths = [r.path.lower() for r in routes] + [a.endpoint.lower() for a in apis]
        auth_routes = [r for r in route_paths if any(term in r for term in ["login", "register", "auth", "signup", "signin"])]
        if auth_routes:
            # Check if any test tests authentication
            linked_auth_tests = []
            for tf_path, t_content in test_file_contents.items():
                if any(term in t_content.lower() for term in ["login", "auth", "token"]):
                    linked_auth_tests.append(tf_path)

            workflows.append(
                WorkflowRecord(
                    name="User Authentication & Session Management",
                    description="User login, registration, and credential validation workflow",
                    entry_point=auth_routes[0],
                    related_files=[r.file_path for r in routes if r.path.lower() in auth_routes] + [a.file_path for a in apis if a.endpoint.lower() in auth_routes],
                    linked_tests=linked_auth_tests,
                    status=EvidenceStatus.INFERRED,
                    steps=["Submit credentials", "Validate password/token", "Establish session"],
                )
            )

        checkout_routes = [r for r in route_paths if any(term in r for term in ["checkout", "payment", "order", "cart"])]
        if checkout_routes:
            linked_cart_tests = []
            for tf_path, t_content in test_file_contents.items():
                if any(term in t_content.lower() for term in ["order", "cart", "checkout"]):
                    linked_cart_tests.append(tf_path)

            workflows.append(
                WorkflowRecord(
                    name="Checkout & Order Processing",
                    description="User cart management, order submission, and payment flow",
                    entry_point=checkout_routes[0],
                    related_files=[r.file_path for r in routes if r.path.lower() in checkout_routes],
                    linked_tests=linked_cart_tests,
                    status=EvidenceStatus.INFERRED,
                    steps=["View cart", "Initiate checkout", "Process payment", "Confirm order"],
                )
            )

        # Deduplicate features by flag_key/name
        unique_features = []
        seen_flags = set()
        for ft in features:
            key = ft.flag_key or ft.name
            if key not in seen_flags:
                seen_flags.add(key)
                unique_features.append(ft)

        return routes, apis, unique_features, workflows, integrations
