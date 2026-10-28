import ast
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
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
    def __init__(self, repo_dir: Path, files: List[FileRecord], project_index: Optional[Any] = None):
        self.repo_dir = Path(repo_dir)
        self.files = files
        self.test_files = [f for f in files if f.category == "test"]
        if project_index is None:
            from offtest.core.project_index import ProjectIndex
            self.project_index = ProjectIndex(repo_dir, files)
        else:
            self.project_index = project_index

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

        # 0. Load AST-extracted routes from ProjectIndex with exact HTTP methods & handlers
        for er in self.project_index.routes:
            f_sha = next((getattr(f, "sha256", None) for f in self.files if f.path == er.file_path), None)
            is_api = er.path.startswith("/api") or "/v1/" in er.path or "/v2/" in er.path
            if is_api:
                apis.append(
                    APIRecord(
                        endpoint=er.path,
                        method=er.method,
                        handler=er.handler_name,
                        file_path=er.file_path,
                        line_number=er.line_number,
                        file_sha256=f_sha,
                        status=EvidenceStatus.OBSERVED,
                        auth_required=er.auth_required,
                        notes=f"{er.framework} API route detected",
                    )
                )
            else:
                routes.append(
                    RouteRecord(
                        path=er.path,
                        method=er.method,
                        handler=er.handler_name,
                        file_path=er.file_path,
                        line_number=er.line_number,
                        file_sha256=f_sha,
                        status=EvidenceStatus.OBSERVED,
                        notes=f"{er.framework} web route detected",
                    )
                )

        # Regex patterns for Python routes (Flask / FastAPI fallback)
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
                        # Skip if already discovered from AST
                        if any(r.path == path and (r.method == method or r.method == "ANY" or method == "ANY") for r in routes) or any(a.endpoint == path for a in apis):
                            continue
                        
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
                            feat_title = f"{clean_stem} UI Component"
                            feat_desc = f"User presentation and view interaction component managing {clean_stem} interface lifecycle."

                        elif svc_match:
                            raw_name = svc_match.group(1)
                            clean_stem = raw_name.replace("Service", "")
                            match_name = raw_name
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
        # 2a. Code-Derived Workflows: follow the call graph from each route handler
        seen_wf_names = set()
        traced_route_paths = set()
        for r_entry in (routes + apis):
            handler = getattr(r_entry, "handler", None)
            path_str = getattr(r_entry, "path", None) or getattr(r_entry, "endpoint", "")
            method_str = getattr(r_entry, "method", "ANY")
            if handler:
                call_trace = self.project_index.trace_workflow(r_entry.file_path, handler)
                if len(call_trace) >= 1:
                    traced_route_paths.add(path_str.lower())
                    wf_name = f"{method_str} {path_str} Execution Workflow"
                    if wf_name not in seen_wf_names:
                        seen_wf_names.add(wf_name)
                        desc = f"Call-graph workflow traced from handler '{handler}()' in {r_entry.file_path}:{r_entry.line_number}"
                        steps = [desc for _, _, desc in call_trace]
                        rel_files = sorted(list(set(fp for fp, _, _ in call_trace)))
                        linked = []
                        for tf_path, t_content in test_file_contents.items():
                            if "synthesized" in tf_path.lower():
                                continue
                            if any(k in t_content.lower() for k in [handler.lower(), Path(r_entry.file_path).stem.lower()]):
                                linked.append(tf_path)

                        workflows.append(
                            WorkflowRecord(
                                name=wf_name,
                                description=desc,
                                entry_point=f"{method_str} {path_str} -> {handler}()",
                                related_files=rel_files,
                                linked_tests=sorted(list(set(linked))),
                                status=EvidenceStatus.OBSERVED,
                                steps=steps,
                                is_advisory=False,
                                symbolic_edges_verified=True,
                                initiated_by=f"Client sends {method_str} request to '{path_str}'",
                                processing_pipeline=steps,
                                where_it_leads=f"Executes {call_trace[-1][2]} and terminates handler",
                                subgraph="API & Route Execution",
                            )
                        )
        # Scan for CI/CD workflows (excluding external dependencies but NOT .github/)
        for f in self.files:
            path_norm = f.path.replace("\\", "/")
            path_parts = path_norm.split("/")
            # Skip genuine node_modules, dist output, vendor directories, and .git internals
            # but NOT .github/workflows which starts with ".github" not ".git"
            if any(seg in path_parts for seg in ["node_modules", "dist", "vendor"]):
                continue
            if "/.git/" in "/" + path_norm + "/" and not path_norm.startswith(".github"):
                continue
            if ".github/workflows" in path_norm or ".gitlab-ci" in path_norm:
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
                    status=EvidenceStatus.INFERRED,
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
                    symbolic_edges_verified=False,
                )
            )

        # Navigation & Screen Routing Workflows
        # Only add client-side SPA navigation workflow if genuine SPA routing files exist
        spa_router_files = [f for f in self.files if any(k in f.path.lower() for k in ["routing.module", "router.js", "app-routing", "routes.ts"])]
        spa_routes = [r for r in routes if "SPA" in (r.notes or "")]
        if spa_routes and spa_router_files:
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
                    symbolic_edges_verified=False,
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
                    symbolic_edges_verified=False,
                )
            )

        # Domain-agnostic workflow inference for routes not already covered by call-graph traces
        covered_eps = {w.entry_point.lower() for w in workflows if w.entry_point}
        route_paths = [r.path.lower() for r in routes] + [a.endpoint.lower() for a in apis]

        # Auth workflow — only if auth routes were actually discovered and not already traced
        auth_routes = [
            r for r in route_paths
            if any(term in r for term in ["login", "register", "auth", "signup", "signin"])
            and r not in traced_route_paths
            and not any(r in ep for ep in covered_eps)
        ]
        if auth_routes:
            linked_auth_tests = []
            for tf_path, t_content in test_file_contents.items():
                if "synthesized" in tf_path.lower():
                    continue
                if any(term in t_content.lower() for term in ["login", "auth", "token"]):
                    linked_auth_tests.append(tf_path)

            workflows.append(
                WorkflowRecord(
                    name="User Authentication & Session Management",
                    description="User login, registration, and credential validation workflow (inferred from route names; not call-graph verified)",
                    entry_point=auth_routes[0],
                    related_files=[r.file_path for r in routes if r.path.lower() in auth_routes] + [a.file_path for a in apis if a.endpoint.lower() in auth_routes],
                    linked_tests=linked_auth_tests,
                    status=EvidenceStatus.INFERRED,
                    steps=["Submit credentials", "Validate password/token", "Establish session"],
                    is_advisory=True,
                    symbolic_edges_verified=False,
                    initiated_by="User authentication prompt or login page",
                    processing_pipeline=["1. Ingest credentials", "2. Validate hash/token", "3. Establish session state"],
                    where_it_leads="Grants authenticated session token and unlocks protected API routes",
                    subgraph="Authentication",
                )
            )

        checkout_routes = [
            r for r in route_paths
            if any(term in r for term in ["checkout", "payment", "order", "cart"])
            and r not in traced_route_paths
            and not any(r in ep for ep in covered_eps)
        ]
        if checkout_routes:
            linked_cart_tests = []
            for tf_path, t_content in test_file_contents.items():
                if any(term in t_content.lower() for term in ["order", "cart", "checkout"]):
                    linked_cart_tests.append(tf_path)

            workflows.append(
                WorkflowRecord(
                    name="Checkout & Order Processing",
                    description="User cart management, order submission, and payment flow (inferred from route names; not call-graph verified)",
                    entry_point=checkout_routes[0],
                    related_files=[r.file_path for r in routes if r.path.lower() in checkout_routes],
                    linked_tests=linked_cart_tests,
                    status=EvidenceStatus.INFERRED,
                    steps=["View cart", "Initiate checkout", "Process payment", "Confirm order"],
                    is_advisory=True,
                    symbolic_edges_verified=False,
                    initiated_by="User clicks checkout button from cart view",
                    processing_pipeline=["1. Validate cart contents", "2. Process payment transaction", "3. Dispatch order confirmation"],
                    where_it_leads="Commits order transaction to database and triggers fulfillment",
                    subgraph="E-Commerce",
                )
            )

        # Fallback baseline journey if no workflows detected
        if len(workflows) == 0:
            workflows.append(
                WorkflowRecord(
                    name="Application Bootstrap & Initial Render",
                    description="Standard lifecycle startup and initial UI rendering workflow (fallback — no routes or API endpoints detected)",
                    entry_point="/",
                    related_files=[f.path for f in sorted_files[:3]],
                    linked_tests=list(test_file_contents.keys())[:2],
                    status=EvidenceStatus.INFERRED,
                    steps=[
                        "Load application runtime bundle and dependencies",
                        "Initialize application configuration and root context",
                        "Render initial landing view / dashboard",
                    ],
                    is_advisory=True,
                    symbolic_edges_verified=False,
                    initiated_by="Initial browser navigation to root URL",
                    processing_pipeline=["1. Load application bundles", "2. Mount root component", "3. Render landing screen"],
                    where_it_leads="Presents active application interface to user",
                    subgraph="Bootstrap",
                )
            )

        # Populate features from discovered workflows only if no explicit feature flags were found.
        # Status is INFERRED (not OBSERVED) because these are synthesized from workflow data,
        # not from real feature flag API calls in the source code.
        if len(features) == 0:
            for wf in workflows:
                feat_name = wf.name
                target_file = wf.related_files[0] if wf.related_files else (sorted_files[0].path if sorted_files else "app.py")
                # Look up actual line number of target symbol in project_index
                actual_line = 1
                handler_match = re.search(r"->\s*(\w+)\(\)", wf.entry_point or "")
                if handler_match:
                    h_name = handler_match.group(1)
                    sym_key = f"{target_file}::{h_name}"
                    if sym_key in self.project_index.symbols:
                        actual_line = self.project_index.symbols[sym_key].line_number
                    elif h_name in self.project_index.symbols_by_name:
                        file_matches = [s for s in self.project_index.symbols_by_name[h_name] if s.file_path == target_file]
                        if file_matches:
                            actual_line = file_matches[0].line_number
                        else:
                            actual_line = self.project_index.symbols_by_name[h_name][0].line_number

                if actual_line == 1:
                    for r in (routes + apis):
                        r_p = getattr(r, "path", None) or getattr(r, "endpoint", "")
                        if r_p and r_p in (wf.entry_point or "") and getattr(r, "file_path", None) == target_file:
                            actual_line = r.line_number
                            break

                if actual_line == 1:
                    for sym in self.project_index.symbols.values():
                        if sym.file_path == target_file and (sym.name.lower() in feat_name.lower() or feat_name.lower() in sym.name.lower()):
                            actual_line = sym.line_number
                            break

                if actual_line == 1:
                    for sym in self.project_index.symbols.values():
                        if sym.file_path == target_file:
                            actual_line = sym.line_number
                            break
                flag = re.sub(r'[^A-Z0-9_]', '_', feat_name.upper())[:30]
                features.append(
                    FeatureRecord(
                        name=feat_name,
                        flag_key=flag,
                        file_path=target_file,
                        line_number=actual_line,
                        # NOTE: synthesized fallback — status is INFERRED, not OBSERVED
                        status=EvidenceStatus.INFERRED,
                        linked_tests=wf.linked_tests,
                        description=wf.description,
                    )
                )

        # Second fallback: if still empty (no workflows either), synthesize from first discovered API/route/file.
        # Status is explicitly INFERRED to avoid claiming OBSERVED evidence we do not have.
        if len(features) == 0:
            if apis:
                first_api = apis[0]
                features.append(
                    FeatureRecord(
                        name="REST API & Resource Management",
                        flag_key="API_SERVICE",
                        file_path=first_api.file_path,
                        line_number=first_api.line_number or 1,
                        # NOTE: synthesized fallback — not an observed feature flag
                        status=EvidenceStatus.INFERRED,
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
                        # NOTE: synthesized fallback — not an observed feature flag
                        status=EvidenceStatus.INFERRED,
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
                        # NOTE: synthesized fallback — not an observed feature flag
                        status=EvidenceStatus.INFERRED,
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
