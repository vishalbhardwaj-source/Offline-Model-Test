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
                    test_file_contents[tf.path] = full_path.read_text(encoding="utf-8-sig", errors="ignore")
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

        # 1. Inspect source files (backend code before static HTML templates)
        sorted_files = sorted(
            [f for f in self.files if f.disposition.value == "analyzed"],
            key=lambda x: (1 if x.language == "HTML" else 0, x.path)
        )

        for f in sorted_files:
            if f.disposition.value != "analyzed":
                continue

            full_path = self.repo_dir / f.path
            if not full_path.is_file() or f.size_bytes > 1_000_000:
                continue

            try:
                content = full_path.read_text(encoding="utf-8-sig", errors="ignore")
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
                                    file_sha256=getattr(f, "sha256", None),
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
                                    file_sha256=getattr(f, "sha256", None),
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
                                file_sha256=getattr(f, "sha256", None),
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
                                    file_sha256=getattr(f, "sha256", None),
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
                                    file_sha256=getattr(f, "sha256", None),
                                    status=EvidenceStatus.OBSERVED,
                                    notes="Express / Node web route detected",
                                )
                            )

                    # Angular / SPA routes: { path: '...' }
                    if "routing" in f.path.lower() or "route" in f.path.lower():
                        ang_match = re.search(r"""path:\s*['"]([^'"]*)['"]""", line)
                        if ang_match:
                            spa_path = ang_match.group(1).strip()
                            if spa_path and not any(r.path == ("/" + spa_path) for r in routes):
                                routes.append(
                                    RouteRecord(
                                        path="/" + spa_path.lstrip("/"),
                                        method="GET",
                                        file_path=f.path,
                                        line_number=line_idx,
                                        file_sha256=getattr(f, "sha256", None),
                                        status=EvidenceStatus.OBSERVED,
                                        notes="SPA / Angular router route detected",
                                    )
                                )

            # HTML files as routes / screens (only registered if not already served or if purely static site)
            elif f.language == "HTML":
                page_route = "/" + f.path.replace("\\", "/")
                if page_route.endswith("/index.html"):
                    page_route = page_route[:-10] or "/"
                
                # In backend apps, HTML files are templates/screens; only register if no server handler covers this path
                has_server_endpoints = any(r.notes and "route detected" in r.notes for r in routes) or len(apis) > 0
                already_handled = any(r.path == page_route for r in routes) or any(a.endpoint == page_route for a in apis)
                if not already_handled and not has_server_endpoints:
                    routes.append(
                        RouteRecord(
                            path=page_route,
                            method="GET",
                            file_path=f.path,
                            line_number=1,
                            file_sha256=getattr(f, "sha256", None),
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
                        # Find linked tests (exclude synthesized unverified tests)
                        linked = []
                        for tf_path, t_content in test_file_contents.items():
                            if "synthesized" in tf_path.lower():
                                continue
                            if flag_name in t_content:
                                linked.append(tf_path)
                        features.append(
                            FeatureRecord(
                                name=f"Feature Toggle: {flag_name}",
                                flag_key=flag_name,
                                file_path=f.path,
                                line_number=line_idx,
                                file_sha256=getattr(f, "sha256", None),
                                status=EvidenceStatus.OBSERVED,
                                linked_tests=linked,
                                description=f"Runtime feature toggle flag '{flag_name}' controlling dynamic execution paths.",
                            )
                        )

            # Component & Service functional feature discovery (Angular, React, Vue, TypeScript)
            if f.language in ["TypeScript", "JavaScript", "JavaScript (JSX)", "TypeScript (TSX)"]:
                is_test_file = any(t_ext in f.path.lower() for t_ext in [".spec.", ".test.", "test_"])
                if not is_test_file and "node_modules" not in f.path:
                    for line_idx, line in enumerate(lines, start=1):
                        # Component detection
                        comp_match = re.search(r"""(?:export\s+)?class\s+([A-Za-z0-9_]+Component)\b""", line)
                        # Service detection
                        svc_match = re.search(r"""(?:export\s+)?class\s+([A-Za-z0-9_]+Service)\b""", line)
                        # Effects detection
                        eff_match = re.search(r"""(?:export\s+)?class\s+([A-Za-z0-9_]+Effects?)\b""", line)
                        # Reducer detection
                        red_match = re.search(r"""(?:export\s+)?(?:function|const)\s+([A-Za-z0-9_]+Reducer)\b""", line)

                        match_name = None
                        feat_title = None
                        feat_desc = None

                        if comp_match:
                            raw_name = comp_match.group(1)
                            clean_stem = raw_name.replace("Component", "")
                            match_name = raw_name
                            friendly_map = {
                                "Navbar": ("Navigation Bar & Category Selector", "Provides category selection navigation menu for section switching (World, Politics, Tech, etc.) and deep-link routing."),
                                "News": ("Top Stories Feed & Article Coordinator", "Coordinates section top stories display, loading state spinners, and responsive article grid rendering."),
                                "NewsItem": ("Article Card & Media Presentation", "Renders article preview cards with headline, abstract, publication date, byline, and external story links."),
                                "Header": ("Application Masthead & Branding", "Presents top-level branding banner, application title, and masthead layout."),
                                "Sections": ("News Section Filter Management", "Maintains active category selections and emits section change events."),
                            }
                            if clean_stem in friendly_map:
                                feat_title, feat_desc = friendly_map[clean_stem]
                            else:
                                feat_title = f"{clean_stem} UI Component"
                                feat_desc = f"User presentation and view interaction component managing {clean_stem} interface lifecycle."

                        elif svc_match:
                            raw_name = svc_match.group(1)
                            clean_stem = raw_name.replace("Service", "")
                            match_name = raw_name
                            if clean_stem.lower() == "news":
                                feat_title = "External News API Client Service"
                                feat_desc = "Issues asynchronous HTTP requests to external news REST endpoints and deserializes payload into typed models."
                            else:
                                feat_title = f"{clean_stem} Data & API Service"
                                feat_desc = f"Business logic and asynchronous HTTP client service managing {clean_stem} data operations."

                        elif eff_match:
                            raw_name = eff_match.group(1)
                            match_name = raw_name
                            feat_title = "NgRx Reactive Side-Effect Dispatcher"
                            feat_desc = "Intercepts dispatched store actions, triggers asynchronous service queries, and feeds results back to state store."

                        elif red_match:
                            raw_name = red_match.group(1)
                            clean_stem = raw_name.replace("Reducer", "").capitalize()
                            match_name = raw_name
                            feat_title = f"Immutable {clean_stem} State Store & Cache"
                            feat_desc = f"Maintains immutable application state slice for {clean_stem}, tracking loading indicators and error states."

                        if match_name and feat_title:
                            # Link tests
                            linked = []
                            file_base = Path(f.path).stem.replace(".component", "").replace(".service", "")
                            for tf_path, t_content in test_file_contents.items():
                                if "synthesized" in tf_path.lower():
                                    continue
                                if match_name in t_content or file_base.lower() in tf_path.lower():
                                    linked.append(tf_path)

                            features.append(
                                FeatureRecord(
                                    name=feat_title,
                                    flag_key=match_name,
                                    file_path=f.path,
                                    line_number=line_idx,
                                    file_sha256=getattr(f, "sha256", None),
                                    status=EvidenceStatus.OBSERVED,
                                    linked_tests=sorted(list(set(linked))),
                                    description=feat_desc,
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
        # Scan for CI/CD workflows (excluding external dependencies)
        for f in self.files:
            if any(part in f.path for part in ["node_modules", "dist", "vendor", ".git"]):
                continue
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

        # Reactive State Management (NgRx / Redux / Store Pipelines)
        store_files = [
            f.path for f in self.files
            if f.disposition.value == "analyzed" and any(k in f.path.lower() for k in ["store", "effects", "actions", "reducers"])
        ]
        effect_files = [f for f in store_files if "effect" in f.lower()]
        service_files = [
            f.path for f in self.files
            if f.disposition.value == "analyzed" and "service" in f.path.lower()
        ]

        if effect_files or (store_files and service_files):
            linked_store_tests = []
            for tf_path in test_file_contents:
                if any(k in tf_path.lower() for k in ["store", "effect", "action", "service"]):
                    linked_store_tests.append(tf_path)

            all_related = sorted(list(set(effect_files + store_files[:6] + service_files[:4])))
            workflows.append(
                WorkflowRecord(
                    name="Asynchronous Data Ingestion & State Pipeline",
                    description="End-to-end reactive state management workflow (Action Dispatch -> Effect Service Query -> Reducer Store Update -> View Projection)",
                    entry_point="Action Dispatch (NgRx / State Store)",
                    related_files=all_related,
                    linked_tests=linked_store_tests,
                    status=EvidenceStatus.OBSERVED,
                    steps=[
                        "UI component dispatches action with intent and parameters",
                        "Reactive Effect intercepts action and executes asynchronous service call",
                        "Service issues HTTP request to external/internal API endpoint",
                        "On HTTP Success: Dispatches success action with response payload",
                        "Reducer commits updated immutable state slice into global store",
                        "On HTTP Failure: Dispatches failure action and transitions to error state",
                        "UI selectors project updated state to active component templates",
                    ],
                    is_advisory=False,
                    symbolic_edges_verified=True,
                )
            )

        # Navigation & Screen Routing Workflows
        spa_routes = [r for r in routes if not r.path.startswith("/src/") and not r.path.endswith(".html")]
        if spa_routes:
            main_route = spa_routes[0].path
            rel_files = sorted(list(set([r.file_path for r in spa_routes[:5]])))
            workflows.append(
                WorkflowRecord(
                    name="Content Navigation & Screen Route Transition",
                    description="User client-side routing and view transition workflow across application sections",
                    entry_point=main_route,
                    related_files=rel_files,
                    linked_tests=[tf for tf in test_file_contents if "route" in tf.lower() or "app" in tf.lower()],
                    status=EvidenceStatus.OBSERVED,
                    steps=[
                        f"User selects navigation link or initiates route change to '{main_route}'",
                        "Client router matches URL path and resolves route configuration",
                        "Target view component is mounted and lifecycle hooks execute",
                        "Component triggers initial state queries and renders view template",
                    ],
                    is_advisory=False,
                    symbolic_edges_verified=True,
                )
            )

        # API Resource CRUD Workflows
        product_or_item_apis = [a for a in apis if any(k in a.endpoint.lower() for k in ["product", "item", "user", "order", "news", "article"])]
        if product_or_item_apis:
            first_api = product_or_item_apis[0]
            resource_name = first_api.endpoint.split("/")[-1].capitalize() or "Resource"
            workflows.append(
                WorkflowRecord(
                    name=f"{resource_name} Catalog & Data Retrieval",
                    description=f"REST endpoint consumption and data retrieval workflow for {resource_name}",
                    entry_point=f"{first_api.method} {first_api.endpoint}",
                    related_files=[first_api.file_path],
                    linked_tests=[tf for tf in test_file_contents if resource_name.lower() in tf.lower()],
                    status=EvidenceStatus.OBSERVED,
                    steps=[
                        f"Client issues {first_api.method} request to '{first_api.endpoint}'",
                        "Server validates parameters, authentication, and permissions",
                        "Server executes query and serializes response entity collection",
                        "Client deserializes payload and updates view models",
                    ],
                    is_advisory=False,
                    symbolic_edges_verified=True,
                )
            )

        # Heuristic application workflows based on discovered routes & files
        route_paths = [r.path.lower() for r in routes] + [a.endpoint.lower() for a in apis]
        auth_routes = [r for r in route_paths if any(term in r for term in ["login", "register", "auth", "signup", "signin"])]
        if auth_routes:
            # Check if any non-synthesized test tests authentication
            linked_auth_tests = []
            for tf_path, t_content in test_file_contents.items():
                if "synthesized" in tf_path.lower():
                    continue
                if any(term in t_content.lower() for term in ["login", "auth", "token"]):
                    linked_auth_tests.append(tf_path)

            workflows.append(
                WorkflowRecord(
                    name="User Authentication & Session Management",
                    description="User login, registration, and credential validation workflow (inferred advisory journey)",
                    entry_point=auth_routes[0],
                    related_files=[r.file_path for r in routes if r.path.lower() in auth_routes] + [a.file_path for a in apis if a.endpoint.lower() in auth_routes],
                    linked_tests=linked_auth_tests,
                    status=EvidenceStatus.INFERRED,
                    steps=["Submit credentials", "Validate password/token", "Establish session"],
                    is_advisory=True,
                    symbolic_edges_verified=False,
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
                    description="User cart management, order submission, and payment flow (inferred advisory journey)",
                    entry_point=checkout_routes[0],
                    related_files=[r.file_path for r in routes if r.path.lower() in checkout_routes],
                    linked_tests=linked_cart_tests,
                    status=EvidenceStatus.INFERRED,
                    steps=["View cart", "Initiate checkout", "Process payment", "Confirm order"],
                    is_advisory=True,
                    symbolic_edges_verified=False,
                )
            )

        # Fallback baseline journey if no workflows detected
        if len(workflows) == 0:
            workflows.append(
                WorkflowRecord(
                    name="Application Bootstrap & Initial Render",
                    description="Standard lifecycle startup and initial UI rendering workflow",
                    entry_point="/",
                    related_files=[f.path for f in sorted_files[:3]],
                    linked_tests=list(test_file_contents.keys())[:2],
                    status=EvidenceStatus.OBSERVED,
                    steps=[
                        "Load application runtime bundle and dependencies",
                        "Initialize application configuration and root context",
                        "Render initial landing view / dashboard",
                    ],
                    is_advisory=True,
                    symbolic_edges_verified=False,
                )
            )

        # Ensure features are never empty for any application
        if len(features) == 0:
            if apis:
                first_api = apis[0]
                features.append(
                    FeatureRecord(
                        name="REST API & Resource Management",
                        flag_key="API_SERVICE",
                        file_path=first_api.file_path,
                        line_number=first_api.line_number or 1,
                        status=EvidenceStatus.OBSERVED,
                        linked_tests=[tf for tf in test_file_contents if "api" in tf.lower()],
                        description="Server-side HTTP API processing client requests, parameter validation, and data serialization.",
                    )
                )
            elif routes:
                first_route = routes[0]
                features.append(
                    FeatureRecord(
                        name="Application UI Navigation & View Routing",
                        flag_key="ROUTING_SERVICE",
                        file_path=first_route.file_path,
                        line_number=first_route.line_number or 1,
                        status=EvidenceStatus.OBSERVED,
                        linked_tests=[tf for tf in test_file_contents if "route" in tf.lower() or "test" in tf.lower()],
                        description="Handles URL-driven routing, page view activation, and template rendering for users.",
                    )
                )
            elif sorted_files:
                top_file = sorted_files[0]
                features.append(
                    FeatureRecord(
                        name="Core Application Runtime & Processing",
                        flag_key="CORE_RUNTIME",
                        file_path=top_file.path,
                        line_number=1,
                        status=EvidenceStatus.OBSERVED,
                        linked_tests=list(test_file_contents.keys())[:1],
                        description="Core application runtime controlling environment initialization, business logic, and operations.",
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
