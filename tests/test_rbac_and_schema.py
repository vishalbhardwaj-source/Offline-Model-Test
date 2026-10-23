from pathlib import Path
from offtest.core.models import APIRecord, EvidenceStatus, FileDisposition, FileRecord, RouteRecord
from offtest.discovery.rbac_and_schema import RBACAndSchemaExtractor


def test_rbac_extraction(tmp_path: Path):
    app_py = tmp_path / "app.py"
    app_py.write_text(
        """
@app.route('/login')
def login():
    return 'login'

@app.route('/dashboard')
@login_required
def dashboard():
    return 'dashboard'

@app.route('/admin/users')
@roles_required('admin')
def admin_users():
    return 'admin'
""",
        encoding="utf-8"
    )

    files = [
        FileRecord(
            path="app.py",
            size_bytes=len(app_py.read_bytes()),
            sha256="123",
            language="Python",
            category="source",
            disposition=FileDisposition.ANALYZED,
            disposition_reason="Source",
        )
    ]

    routes = [
        RouteRecord(path="/login", method="GET", file_path="app.py", line_number=2),
        RouteRecord(path="/dashboard", method="GET", file_path="app.py", line_number=6),
        RouteRecord(path="/admin/users", method="GET", file_path="app.py", line_number=11),
    ]

    extractor = RBACAndSchemaExtractor(tmp_path, files, routes, [])
    matrix = extractor.extract_rbac()

    assert matrix.endpoints_count == 3
    assert "Anonymous" in matrix.roles
    assert "Authenticated" in matrix.roles
    assert "Admin" in matrix.roles

    perm_map = {p.endpoint: p for p in matrix.permissions}
    assert perm_map["/login"].auth_required is False
    assert "Anonymous" in perm_map["/login"].required_roles

    assert perm_map["/dashboard"].auth_required is True
    assert "Authenticated" in perm_map["/dashboard"].required_roles

    assert perm_map["/admin/users"].auth_required is True
    assert "Admin" in perm_map["/admin/users"].required_roles


def test_openapi_synthesis(tmp_path: Path):
    apis = [
        APIRecord(endpoint="/api/v1/users", method="GET", file_path="api.py", line_number=5),
        APIRecord(endpoint="/api/v1/users/:id", method="POST", file_path="api.py", line_number=10),
    ]

    extractor = RBACAndSchemaExtractor(tmp_path, [], [], apis)
    spec = extractor.synthesize_openapi(title="Test Service API", version="2.0.0")

    assert spec.openapi_version == "3.1.0"
    assert spec.title == "Test Service API"
    assert spec.paths_count == 2
    assert "/api/v1/users" in spec.paths
    assert "/api/v1/users/{id}" in spec.paths
    assert "post" in spec.paths["/api/v1/users/{id}"]
    params = spec.paths["/api/v1/users/{id}"]["post"]["parameters"]
    assert any(p["name"] == "id" for p in params)
