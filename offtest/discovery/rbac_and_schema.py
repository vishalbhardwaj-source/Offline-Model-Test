import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from offtest.core.models import (
    APIRecord,
    EvidenceStatus,
    FileRecord,
    OpenAPISpecRecord,
    RBACMatrix,
    RBACPermissionRecord,
    RouteRecord,
)


class RBACAndSchemaExtractor:
    """Extracts a Role-Based Access Control (RBAC) permission matrix and synthesizes an offline OpenAPI 3.1 specification."""

    def __init__(self, repo_dir: Path, files: List[FileRecord], routes: List[RouteRecord], apis: List[APIRecord]):
        self.repo_dir = repo_dir
        self.files = files
        self.routes = routes
        self.apis = apis

    def extract_rbac(self) -> RBACMatrix:
        permissions: List[RBACPermissionRecord] = []
        role_to_endpoints: Dict[str, List[str]] = {
            "Anonymous": [],
            "Authenticated": [],
            "Admin": [],
        }

        # Regex patterns for auth decorators / middleware
        login_req_pattern = re.compile(r"""@(?:login_required|auth_required|jwt_required|authenticate|require_auth)\b""", re.IGNORECASE)
        role_req_pattern = re.compile(
            r"""@(?:roles_required|has_role|require_role|roles_allowed|allow_roles)\s*\(\s*['"]?([a-zA-Z0-9_\-]+)['"]?""",
            re.IGNORECASE,
        )
        admin_pattern = re.compile(r"""\b(?:is_admin|admin_required|require_admin|@admin)\b""", re.IGNORECASE)
        js_auth_middleware_pattern = re.compile(r"""(?:authMiddleware|passport\.authenticate|verifyToken|checkRole\(['"](\w+)['"]\))""")

        # Cache file lines and hashes for context lookups
        file_lines: Dict[str, List[str]] = {}
        file_hashes: Dict[str, str] = {f.path: f.sha256 for f in self.files if getattr(f, "sha256", None)}
        for f in self.files:
            if f.disposition.value == "analyzed" and f.language in ["Python", "JavaScript", "TypeScript"]:
                try:
                    full_p = self.repo_dir / f.path
                    if full_p.is_file():
                        file_lines[f.path] = full_p.read_text(encoding="utf-8", errors="ignore").splitlines()
                except Exception:
                    pass

        # Combine routes and APIs for RBAC evaluation
        all_targets: List[Tuple[str, str, str, int]] = []
        for r in self.routes:
            all_targets.append((r.path, r.method, r.file_path, r.line_number or 1))
        for a in self.apis:
            all_targets.append((a.endpoint, a.method, a.file_path, a.line_number or 1))

        # Deduplicate
        seen_targets = set()
        for endpoint, method, file_path, line_num in all_targets:
            key = (endpoint, method, file_path)
            if key in seen_targets:
                continue
            seen_targets.add(key)

            lines = file_lines.get(file_path, [])
            auth_required = False
            roles: List[str] = []
            guard_syntaxes: List[str] = []

            # Identify contiguous decorator and definition block for this handler without bleeding into adjacent routes
            idx = max(0, min(line_num - 1, len(lines) - 1)) if lines else 0
            start_idx = idx
            route_dec_re = re.compile(r"@\w+\.(?:route|get|post|put|delete|patch)\b")
            while start_idx > 0:
                prev_line = lines[start_idx - 1].strip()
                if prev_line.startswith("@") and not route_dec_re.search(prev_line):
                    start_idx -= 1
                elif route_dec_re.search(prev_line) and lines[idx].strip().startswith("def"):
                    # line_num was pointing to def, include preceding route decorator
                    start_idx -= 1
                    break
                else:
                    break

            end_idx = idx
            while end_idx < len(lines) - 1:
                next_line = lines[end_idx + 1].strip()
                if next_line.startswith("@"):
                    if route_dec_re.search(next_line):
                        break
                    end_idx += 1
                elif next_line.startswith("def ") or next_line.startswith("async def "):
                    end_idx += 1
                    break
                else:
                    break

            context_block = "\n".join(lines[start_idx : end_idx + 1])
            block_lines = lines[start_idx : end_idx + 1]

            # In Flask-style web frameworks, auth guards must appear BETWEEN the route decorator and the def statement.
            # A guard placed ABOVE @app.route is evaluated at module load time and does NOT wrap HTTP requests!
            route_line_offset = None
            for b_idx, b_line in enumerate(block_lines):
                if route_dec_re.search(b_line):
                    route_line_offset = b_idx
                    break

            if route_line_offset is not None:
                active_guard_block = "\n".join(block_lines[route_line_offset:])
                misplaced_guard_block = "\n".join(block_lines[:route_line_offset])
            else:
                active_guard_block = context_block
                misplaced_guard_block = ""

            login_m = login_req_pattern.search(active_guard_block)
            if login_m:
                auth_required = True
                roles.append("Authenticated")
                guard_syntaxes.append(login_m.group(0).strip())

            role_m = role_req_pattern.search(active_guard_block)
            if role_m:
                auth_required = True
                explicit_role = role_m.group(1).capitalize()
                roles.append(explicit_role)
                guard_syntaxes.append(role_m.group(0).strip())
                if explicit_role not in role_to_endpoints:
                    role_to_endpoints[explicit_role] = []

            admin_m = admin_pattern.search(active_guard_block)
            if admin_m:
                auth_required = True
                if "Admin" not in roles:
                    roles.append("Admin")
                guard_syntaxes.append(admin_m.group(0).strip())

            js_auth_m = js_auth_middleware_pattern.search(active_guard_block)
            if js_auth_m:
                auth_required = True
                roles.append("Authenticated")
                guard_syntaxes.append(js_auth_m.group(0).strip())
                if js_auth_m.group(1):
                    custom_role = js_auth_m.group(1).capitalize()
                    roles.append(custom_role)
                    if custom_role not in role_to_endpoints:
                        role_to_endpoints[custom_role] = []

            # Check if guard was misplaced above route decorator (Flask vulnerability)
            has_misplaced_guard = bool(
                misplaced_guard_block
                and (
                    login_req_pattern.search(misplaced_guard_block)
                    or role_req_pattern.search(misplaced_guard_block)
                    or admin_pattern.search(misplaced_guard_block)
                )
                and not auth_required
            )

            # Public vs Unverified guard evaluation
            status = EvidenceStatus.OBSERVED
            derived_guard_str = "; ".join(guard_syntaxes) if guard_syntaxes else None
            if auth_required:
                for r in roles:
                    if f"{method} {endpoint}" not in role_to_endpoints.get(r, []):
                        role_to_endpoints.setdefault(r, []).append(f"{method} {endpoint}")
            else:
                # Check for explicit public declarations or conventional public auth/health endpoints
                # Conventional endpoints (/login, /register, /health, /) without decorators are inferred as Anonymous
                is_explicit_public = (
                    re.search(r"""@(?:public|allow_anonymous|permit_all)\b""", context_block, re.IGNORECASE)
                    or endpoint in ["/", "/health", "/login", "/register", "/api/v1/auth/login"]
                )
                if has_misplaced_guard:
                    roles = ["Unverified (Misplaced guard above route decorator)"]
                    status = EvidenceStatus.UNVERIFIED
                    derived_guard_str = "insecure_decorator_order: guard placed above @app.route (bypassed in Flask)"
                    role_to_endpoints.setdefault(roles[0], []).append(f"{method} {endpoint}")
                elif is_explicit_public:
                    roles = ["Anonymous"]
                    status = EvidenceStatus.INFERRED
                    derived_guard_str = "inferred_public_endpoint"
                    role_to_endpoints.setdefault("Anonymous", []).append(f"{method} {endpoint}")
                else:
                    # Do not assume unguarded routes are public: global middleware or CBVs may apply
                    roles = ["Unverified (No local guard)"]
                    status = EvidenceStatus.UNVERIFIED
                    role_to_endpoints.setdefault("Unverified (No local guard)", []).append(f"{method} {endpoint}")

            permissions.append(
                RBACPermissionRecord(
                    endpoint=endpoint,
                    method=method,
                    auth_required=auth_required,
                    required_roles=roles,
                    file_path=file_path,
                    line_number=line_num,
                    file_sha256=file_hashes.get(file_path),
                    derived_guard_syntax=derived_guard_str,
                    status=status,
                )
            )

        # Only list roles that actually have one or more associated endpoints
        all_roles = sorted([r for r, eps in role_to_endpoints.items() if len(eps) > 0 and not r.startswith("Unverified")])
        return RBACMatrix(
            roles=all_roles,
            endpoints_count=len(permissions),
            permissions=permissions,
            role_to_endpoints_map=role_to_endpoints,
        )

    def synthesize_openapi(self, title: str = "Inferred Application API", version: str = "1.0.0") -> OpenAPISpecRecord:
        paths: Dict[str, Any] = {}
        rbac = self.extract_rbac()
        auth_map = {(p.endpoint, p.method.upper()): p.auth_required for p in rbac.permissions}

        # Standardize paths and methods from routes and apis
        all_endpoints: Dict[str, Dict[str, Any]] = {}

        for a in self.apis:
            norm_path = self._normalize_openapi_path(a.endpoint)
            method = a.method.lower()
            if method == "any":
                method = "get"
            
            responses: Dict[str, Any] = {
                "200": {"description": "Successful operation", "x-inferred": True},
                "400": {"description": "Bad Request", "x-inferred": True},
                "500": {"description": "Internal Server Error", "x-inferred": True},
            }
            if auth_map.get((a.endpoint, a.method.upper()), False):
                responses["401"] = {"description": "Unauthorized - Authentication required", "x-inferred": True}

            all_endpoints.setdefault(norm_path, {})[method] = {
                "summary": f"Handler for {a.endpoint}",
                "operationId": f"{method}_{norm_path.strip('/').replace('/', '_').replace('{', '').replace('}', '') or 'root'}",
                "parameters": self._extract_path_params(norm_path),
                "responses": responses,
            }

        for r in self.routes:
            if not r.path.startswith("/api"):
                norm_path = self._normalize_openapi_path(r.path)
                method = r.method.lower()
                if method == "any":
                    method = "get"
                if norm_path not in all_endpoints or method not in all_endpoints[norm_path]:
                    all_endpoints.setdefault(norm_path, {})[method] = {
                        "summary": f"UI / Page Route {r.path}",
                        "operationId": f"{method}_{norm_path.strip('/').replace('/', '_').replace('{', '').replace('}', '') or 'root'}",
                        "parameters": self._extract_path_params(norm_path),
                        "responses": {
                            "200": {"description": "HTML or JSON Page Content", "x-inferred": True},
                            "404": {"description": "Not Found", "x-inferred": True},
                        },
                    }

        return OpenAPISpecRecord(
            openapi_version="3.1.0",
            title=title,
            version=version,
            paths_count=len(all_endpoints),
            paths=all_endpoints,
            is_valid=True,
        )

    def _normalize_openapi_path(self, path: str) -> str:
        # Express-style :id -> {id}
        norm = re.sub(r":([a-zA-Z0-9_]+)", r"{\1}", path)
        if not norm.startswith("/"):
            norm = "/" + norm
        return norm

    def _extract_path_params(self, path: str) -> List[Dict[str, Any]]:
        params = []
        matches = re.findall(r"\{([a-zA-Z0-9_]+)\}", path)
        for m in matches:
            params.append(
                {
                    "name": m,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
            )
        return params
