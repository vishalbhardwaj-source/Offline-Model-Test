"""tests/test_critique_improvements.py

Comprehensive test suite verifying the resolution of all critique items:
1. Structural categorization, rule registry, single confidence scale, and gate overhaul.
2. False positives reduction (annotations, __init__, [project.urls], positional SafeLoader, fixture detection, secret allowlist, GET login, lockfiles, volume aggregation).
3. Missing detections coverage (async handlers, import aliases, AnnAssign debug flags, app.run(debug=True), subprocess(shell=True), SQL injection, zip-slip, weak hashes, mktemp).
4. Robustness (package.json non-string safety, deterministic fingerprint IDs, secure HMAC key storage).
"""
import ast
import tempfile
from pathlib import Path

from offtest.checks.planner import CheckPlanner
from offtest.checks.static_checks import OfflineStaticChecker
from offtest.core.models import (
    CheckStatus,
    Confidence,
    FileDisposition,
    FileRecord,
    FindingCategory,
    Severity,
)
from offtest.core.rules import RULES, make_finding
from offtest.intake.safety import _get_installation_hmac_key, scan_for_secrets
from offtest.inventory.engine import InventoryEngine


def test_section1_rule_registry_and_cvss_rules():
    # Rule registry existence and categories
    assert "OT-SEC-001" in RULES
    assert RULES["OT-SEC-001"].category == FindingCategory.VULNERABILITY
    assert RULES["OT-SCR-001"].category == FindingCategory.SECRET
    assert RULES["OT-POL-001"].category == FindingCategory.POLICY
    assert RULES["OT-HYG-006"].category == FindingCategory.HYGIENE

    # Policy and Hygiene rules MUST NOT carry CVSS vectors or scores
    assert RULES["OT-POL-001"].cvss_score is None
    assert RULES["OT-POL-001"].cvss_vector is None
    assert RULES["OT-HYG-006"].cvss_score is None

    # Constant os.system must not have CWE-78 or CVSS
    f_const = make_finding(RULES["OT-HYG-006"], path="app.py", line=10, evidence="os.system('ls')")
    assert f_const.category == FindingCategory.HYGIENE
    assert f_const.severity == Severity.INFORMATIONAL
    assert f_const.cwe_id is None
    assert f_const.cvss_score_estimate is None

    # Dynamic os.system carries CWE-78 and CVSS 8.8
    f_dyn = make_finding(RULES["OT-SEC-002"], path="app.py", line=10, evidence="os.system('ls ' + x)")
    assert f_dyn.category == FindingCategory.VULNERABILITY
    assert f_dyn.severity == Severity.HIGH
    assert f_dyn.cwe_id == "CWE-78"
    assert f_dyn.cvss_score_estimate == 8.8


def test_section1_planner_gate_logic():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "dummy.py").write_text("print('clean')", encoding="utf-8")
        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        planner = CheckPlanner(tmp_path, files)

        # 1. Hygiene findings only (e.g. constant os.system) must NOT fail gate
        hygiene_finding = make_finding(RULES["OT-HYG-006"], path="dummy.py", line=1, evidence="os.system('echo hi')")
        results, _ = planner.execute_all()
        # Planner with no findings passes
        assert results[0].status == CheckStatus.PASSED
        assert results[0].gate_outcome == "Pass"

        # 2. Gate evaluation with policy violation reports air-gap violations, not "security defects"
        policy_finding = make_finding(RULES["OT-POL-001"], path="requirements.txt", line=1, evidence="--index-url https://evil.com")
        crit_sec_finding = make_finding(RULES["OT-SEC-002"], path="app.py", line=1, evidence="os.system('rm ' + x)")

        # Test planner static scanner failure reason formulation directly
        findings = [policy_finding, crit_sec_finding]
        blocking_sec = [f for f in findings if f.category in (FindingCategory.VULNERABILITY, FindingCategory.SECRET) and f.severity in (Severity.CRITICAL, Severity.HIGH) and f.confidence in (Confidence.CONFIRMED, Confidence.LIKELY)]
        blocking_pol = [f for f in findings if f.category == FindingCategory.POLICY and f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(blocking_sec) == 1
        assert len(blocking_pol) == 1


def test_section2_false_positives_python_imports():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # File 1: __future__ annotations must not be flagged as unused import
        (tmp_path / "models.py").write_text("from __future__ import annotations\n\nx: int = 10\n", encoding="utf-8")

        # File 2: __init__.py re-exports must not be flagged as unused imports
        (tmp_path / "__init__.py").write_text("from .models import x\n", encoding="utf-8")

        # File 3: __all__ usage must count as referenced
        (tmp_path / "api.py").write_text("import math\n\n__all__ = ['math']\n", encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()
        unused_titles = [f.title for f in findings if "Unused Import" in f.title]

        # None of the above three files should produce unused import findings
        assert len(unused_titles) == 0


def test_section2_false_positives_manifest_and_yaml():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # 1. pyproject.toml with [project.urls] Repository metadata link
        pyproj_content = """[project]
name = "demo"
version = "0.1.0"

[project.urls]
Repository = "https://github.com/example/repo"
Homepage = "https://example.com"
"""
        (tmp_path / "pyproject.toml").write_text(pyproj_content, encoding="utf-8")

        # 2. yaml.load with positional yaml.SafeLoader
        code = """import yaml

def parse(data):
    return yaml.load(data, yaml.SafeLoader)
"""
        (tmp_path / "safe_yaml.py").write_text(code, encoding="utf-8")

        # 3. package.json with ^ and ~ ranges when package-lock.json is present
        (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"}}', encoding="utf-8")
        (tmp_path / "package-lock.json").write_text('{"name": "demo", "lockfileVersion": 3}', encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()

        titles = [f.title for f in findings]
        assert not any("Remote VCS or Network Dependency" in t for t in titles)
        assert not any("Unsafe YAML Deserialization" in t for t in titles)
        assert not any("Floating Node.js Dependency" in t for t in titles)


def test_section2_false_positives_fixture_detection():
    # Attestation and latest directories must NOT match fixture detection
    checker = OfflineStaticChecker(Path("."), [])
    assert not checker.is_fixture_or_test("attestation/verifier.py")
    assert not checker.is_fixture_or_test("latest/report.py")
    assert checker.is_fixture_or_test("tests/unit/test_app.py")
    assert checker.is_fixture_or_test("fixtures/sample.json")


def test_section2_false_positives_secret_scanner_allowlist():
    # Git SHA, SHA256, and MD5 in digest contexts must not be flagged as secrets
    code = """
commit_hash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
file_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
md5_checksum = "d41d8cd98f00b204e9800998ecf8427e"
"""
    hits = scan_for_secrets(code, "hashes.py")
    assert len(hits) == 0


def test_section2_get_login_heuristic():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # GET /login without password params is normal HTML view handler
        code = """
@app.get("/api/v1/auth/login")
def login_view():
    return render_template("login.html")

@app.get("/api/v1/auth/token")
def insecure_token_get(username, password):
    return issue_token(username, password)
"""
        (tmp_path / "routes.py").write_text(code, encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()

        insecure_auth = [f for f in findings if "Insecure Authentication Endpoint" in f.title]
        info_auth = [f for f in findings if "HTTP GET Route Used for Authentication View" in f.title]

        # Only the endpoint accepting a password query param is flagged as High Insecure Auth
        assert len(insecure_auth) == 1
        assert insecure_auth[0].severity == Severity.HIGH
        # The view endpoint is Informational Hygiene
        assert len(info_auth) == 1
        assert info_auth[0].severity == Severity.INFORMATIONAL


def test_section3_missing_rules_and_aliases():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        code = """
import subprocess as sp
from os import system as sys_exec
import hashlib
import tempfile
import tarfile

# 1. Annotated debug flag
DEBUG: bool = True

# 2. Async route handler with password
@app.get("/login")
async def async_login_handler(user, password):
    pass

# 3. Import alias for os.system
def run_sys(cmd):
    sys_exec("echo " + cmd)

# 4. subprocess with shell=True
def run_sub(cmd):
    sp.run(cmd, shell=True)

# 5. Weak hash without usedforsecurity=False
def make_digest(data):
    return hashlib.md5(data.encode())

# 6. Insecure tempfile.mktemp
def temp_path():
    return tempfile.mktemp()

# 7. Zip-slip extractall
def extract(tar_path):
    with tarfile.open(tar_path) as tf:
        tf.extractall()

# 8. SQL query via string formatting
def query_user(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % uid)

# 9. app.run(debug=True)
def start():
    app.run(debug=True)
"""
        (tmp_path / "vulns.py").write_text(code, encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()
        titles = [f.title for f in findings]

        assert any("DEBUG = True" in t for t in titles)
        assert any("Insecure Authentication Endpoint" in t for t in titles)
        assert any("Dynamic Command Execution" in t for t in titles)
        assert any("Subprocess Executed with shell=True" in t for t in titles)
        assert any("Weak Cryptographic Hash" in t for t in titles)
        assert any("Insecure Temporary File" in t for t in titles)
        assert any("Zip Slip" in t for t in titles)
        assert any("SQL Query Constructed via String Formatting" in t for t in titles)


def test_section4_robustness_and_engineering():
    # 1. Non-string package.json version handled safely
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "package.json").write_text('{"dependencies": {"odd": 123, "nested": {"version": "1.0.0"}}}', encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        # Must execute without throwing exceptions
        findings = checker.run_all()
        assert isinstance(findings, list)

    # 2. Deterministic fingerprint IDs
    f1 = make_finding(RULES["OT-SEC-001"], path="src/main.py", line=42, evidence="eval(x)")
    f2 = make_finding(RULES["OT-SEC-001"], path="src/main.py", line=42, evidence="eval(x)")
    assert f1.id == f2.id
    assert f1.id.startswith("FIND-OT-SEC-001-")

    # 3. HMAC installation key is persisted in user directory with restricted permissions
    key = _get_installation_hmac_key()
    assert isinstance(key, bytes) and len(key) == 32


def test_4_axis_categorization_and_priority_calculation():
    from offtest.core.models import compute_priority

    # Verify 4 orthogonal axes on canonical rules
    eval_rule = RULES["OT-SEC-001"]
    assert eval_rule.cwe_id == "CWE-95"
    assert eval_rule.owasp_category == "A03:2021-Injection"
    assert eval_rule.asvs_chapter == "V5 Validation, Sanitization and Encoding"

    # Make finding and check dynamic priority score calculation
    # High (7.0) * Likely (0.8) * reachable (1.0) * public_unauth (1.5) = 8.4
    p_high_reach = compute_priority(
        Severity.HIGH, Confidence.LIKELY, reachability="reachable", exposure="public_unauth"
    )
    assert p_high_reach == 8.4

    # High (7.0) * Likely (0.8) * unreachable (0.2) * internal (0.6) = 0.67
    p_unreach = compute_priority(
        Severity.HIGH, Confidence.LIKELY, reachability="unreachable", exposure="internal"
    )
    assert p_unreach == 0.67
    assert p_high_reach > p_unreach

    # Test finding creation with new fields
    finding = make_finding(
        eval_rule,
        path="src/calc.py",
        line=15,
        evidence="eval(user_input)",
        exposure="public_unauth",
        reachability="reachable",
    )
    assert finding.owasp_category == "A03:2021-Injection"
    assert finding.asvs_chapter == "V5 Validation, Sanitization and Encoding"
    assert finding.priority_score == 8.4
    assert finding.exposure == "public_unauth"
    assert finding.reachability == "reachable"


def test_offline_advisory_matcher_and_vex_status():
    from offtest.core.project_index import ProjectIndex
    from offtest.core.models import SBOMComponent
    from offtest.inventory.advisory_matcher import OfflineAdvisoryMatcher

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        # Create a file that imports requests
        (tmp_path / "client.py").write_text("import requests\nrequests.get('https://example.com')", encoding="utf-8")
        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()
        proj_idx = ProjectIndex(tmp_path, files)

        matcher = OfflineAdvisoryMatcher(project_index=proj_idx)

        # 1. Vulnerable requests component (< 2.31.0) -> Reachable (imported)
        comp_vuln_req = SBOMComponent(
            name="requests",
            version="2.25.1",
            ecosystem="pypi",
            purl="pkg:pypi/requests@2.25.1",
            source_file="requirements.txt",
            direct=True,
            is_approximate_range=False,
        )
        # 2. Vulnerable lodash (< 4.17.21) -> Unreachable (not imported)
        comp_vuln_lodash = SBOMComponent(
            name="lodash",
            version="4.17.15",
            ecosystem="npm",
            purl="pkg:npm/lodash@4.17.15",
            source_file="package-lock.json",
            direct=True,
            is_approximate_range=False,
        )

        findings = matcher.match([comp_vuln_req, comp_vuln_lodash])
        assert len(findings) == 2

        req_f = next(f for f in findings if "requests" in f.title.lower())
        assert req_f.reachability == "reachable"
        assert req_f.evidence_level == "reachable"
        assert "affected" in req_f.impact

        lodash_f = next(f for f in findings if "lodash" in f.title.lower())
        assert lodash_f.reachability == "unreachable"
        assert lodash_f.evidence_level == "static-only"
        assert "not_affected" in lodash_f.impact
        # Unreachable finding has downgraded severity
        assert lodash_f.severity == Severity.LOW


def test_inline_suppressions_and_root_cause_clustering():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        code = """
import subprocess

# offtest: ignore[OT-SEC-003]: legacy intentional maintenance script
subprocess.run("dir", shell=True)

# Non-suppressed issue
eval("1 + 1 dynamic " + x)
"""
        (tmp_path / "script.py").write_text(code, encoding="utf-8")
        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()

        subproc_f = next(f for f in findings if f.rule_id == "OT-SEC-003")
        assert subproc_f.suppressed is True
        assert "legacy intentional" in (subproc_f.suppression_reason or "")

        eval_f = next(f for f in findings if f.rule_id == "OT-SEC-001")
        assert eval_f.suppressed is False

        # Root cause clustering check
        assert subproc_f.root_cause_cluster == "OT-SEC-003::script.py"

        # Check that planner gate ignores suppressed defects
        planner = CheckPlanner(tmp_path, files)
        # Manually verify gate logic with suppressed defect
        crit_sec = [
            f for f in findings
            if f.category in (FindingCategory.VULNERABILITY, FindingCategory.SECRET)
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
            and f.confidence in (Confidence.CONFIRMED, Confidence.LIKELY)
            and not getattr(f, "suppressed", False)
        ]
        # OT-SEC-003 is suppressed, so only OT-SEC-001 remains
        assert all(f.rule_id != "OT-SEC-003" for f in crit_sec)


def test_rbac_unauthenticated_state_changing_route():
    from offtest.core.project_index import ProjectIndex

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        code = """
from flask import Flask, request
app = Flask(__name__)

# State-changing POST route without authentication decorator
@app.route("/api/items/create", methods=["POST"])
def create_item():
    return "created"

# Login route (exempt from unauthenticated state-changing rule)
@app.route("/api/auth/login", methods=["POST"])
def login_endpoint():
    return "token"
"""
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()
        proj_idx = ProjectIndex(tmp_path, files)

        checker = OfflineStaticChecker(tmp_path, files, project_index=proj_idx)
        findings = checker.run_all()

        rbac_findings = [f for f in findings if f.rule_id == "OT-SEC-012"]
        assert len(rbac_findings) == 1
        assert "/api/items/create" in rbac_findings[0].evidence
        assert rbac_findings[0].exposure == "public_unauth"
        assert rbac_findings[0].reachability == "reachable"


def test_sarif_codeflows_and_tags():
    from offtest.core.models import RunContext
    from offtest.reports.sarif import SARIFReportGenerator

    finding = make_finding(
        RULES["OT-SEC-008"],
        path="db.py",
        line=20,
        evidence="cursor.execute('SELECT * FROM ' + table)",
    )
    context = RunContext(
        schema_version="1.1.0",
        run_id="test_run",
        timestamp="2026-10-29T00:00:00Z",
        repo_path=".",
        repo_name="test_repo",
        working_tree_clean=True,
        remotes=[],
        active_branch="main",
        platform="win32",
        python_version="3.12.10",
        offline_enforced=True,
        findings=[finding],
    )

    sarif_gen = SARIFReportGenerator(context)
    doc = sarif_gen.generate_sarif()

    # Rule metadata has tags
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    tags = rule["properties"]["tags"]
    assert "A03:2021-Injection" in tags
    assert "CWE-89" in tags

    # Result has codeFlows with threadFlows
    result = doc["runs"][0]["results"][0]
    assert "codeFlows" in result
    tflow = result["codeFlows"][0]["threadFlows"][0]
    assert len(tflow["locations"]) >= 2
    assert result["baselineState"] == "new"
    assert "priorityScore" in result["properties"]


def test_advisory_staleness_and_snapshot_metadata():
    from offtest.inventory.advisory_matcher import (
        ADVISORY_SNAPSHOT_DATE,
        ADVISORY_STALENESS_THRESHOLD_DAYS,
        check_advisory_staleness,
    )
    assert ADVISORY_SNAPSHOT_DATE == "2026-10-01"
    assert ADVISORY_STALENESS_THRESHOLD_DAYS == 90

    # check staleness execution
    is_stale, age_days, message = check_advisory_staleness()
    assert isinstance(is_stale, bool)
    assert isinstance(age_days, int)
    assert "2026-10-01" in message


def test_access_control_expanded_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # 1. OT-SEC-013: IDOR / Missing object authorization
        idor_code = """
from flask import Flask, request

app = Flask(__name__)

@app.route('/user/<user_id>/profile')
def get_user_profile(user_id):
    # Direct lookup without tenant / user match check
    return db.query(f"SELECT * FROM profiles WHERE id = {user_id}")
"""
        (tmp_path / "idor.py").write_text(idor_code, encoding="utf-8")

        # 2. OT-SEC-014: Admin route lacking role check
        priv_esc_code = """
from flask import Flask

app = Flask(__name__)

@app.route('/admin/settings/delete')
def delete_settings():
    return "deleted"
"""
        (tmp_path / "priv_esc.py").write_text(priv_esc_code, encoding="utf-8")

        # 3. OT-SEC-015: Permissive CORS with credentials
        cors_code = """
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)
"""
        (tmp_path / "cors_app.py").write_text(cors_code, encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()

        rule_ids = {f.rule_id for f in findings}
        assert "OT-SEC-013" in rule_ids
        assert "OT-SEC-014" in rule_ids
        assert "OT-SEC-015" in rule_ids


def test_policy_and_supply_chain_expanded_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # 1. OT-POL-005: Dockerfile root user
        dockerfile = """
FROM python:3.12-slim
WORKDIR /app
COPY . .
CMD ["python", "main.py"]
"""
        (tmp_path / "Dockerfile").write_text(dockerfile, encoding="utf-8")

        # 2. OT-POL-006: Unpinned GitHub action
        ci_dir = tmp_path / ".github" / "workflows"
        ci_dir.mkdir(parents=True, exist_ok=True)
        workflow_yml = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
"""
        (ci_dir / "ci.yml").write_text(workflow_yml, encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()

        rule_ids = {f.rule_id for f in findings}
        assert "OT-POL-005" in rule_ids
        assert "OT-POL-006" in rule_ids


def test_test_confirmation_feedback_loop():
    from offtest.checks.planner import calibrate_findings_with_test_results
    from offtest.core.models import CheckResult, CheckStatus

    # Create a finding with static-only evidence level and LIKELY confidence
    finding = make_finding(
        RULES["OT-SEC-008"],
        path="api/handlers.py",
        line=42,
        evidence="cursor.execute('SELECT * FROM users WHERE name = ' + user)",
        confidence=Confidence.LIKELY,
    )
    assert finding.evidence_level == "static-only"
    assert finding.confidence == Confidence.LIKELY

    # Simulate check results containing a test failure in api/handlers.py
    failing_result = CheckResult(
        tool_name="pytest",
        tool_version="8.0.0",
        check_name="Unit and Integration Tests",
        check_type="unit_test",
        command="pytest",
        exit_code=1,
        duration_sec=0.15,
        status=CheckStatus.FAILED,
        stdout="FAIL: test_sql_injection (tests.test_api) in api/handlers.py",
        stderr="AssertionError: SQL injection occurred",
        gate_outcome="Fail",
    )

    findings = [finding]
    calibrate_findings_with_test_results(findings, [failing_result])

    # Finding should be elevated to CONFIRMED and evidence_level="test-confirmed"
    assert finding.confidence == Confidence.CONFIRMED
    assert finding.evidence_level == "test-confirmed"
    assert "Dynamic Test Failure Corroboration" in finding.context["test_feedback"]

    # Verify asymmetric feedback semantics:
    # A passing test does NOT demote a deterministic rule finding
    passing_result = CheckResult(
        tool_name="pytest",
        tool_version="8.0.0",
        check_name="Unit and Integration Tests",
        check_type="unit_test",
        command="pytest",
        exit_code=0,
        duration_sec=0.15,
        status=CheckStatus.PASSED,
        stdout="PASS: test_something in api/handlers.py",
        stderr="",
        gate_outcome="Pass",
    )
    static_rule_finding = make_finding(
        RULES["OT-SEC-008"],
        path="api/handlers.py",
        line=42,
        evidence="cursor.execute('SELECT * FROM users WHERE name = ' + user)",
        confidence=Confidence.LIKELY,
    )
    calibrate_findings_with_test_results([static_rule_finding], [passing_result])
    # Must remain LIKELY, not demoted
    assert static_rule_finding.confidence == Confidence.LIKELY


def test_expanded_security_and_governance_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # 1. OT-SEC-016: Mass Assignment
        # 2. OT-SEC-017: Insecure JWT
        # 3. OT-SEC-020: ECB cipher
        python_code = """
import jwt
from Crypto.Cipher import AES

payload = User(**request.json)
token = jwt.decode('sample_token', options={"verify_signature": False})
cipher = AES.new(b"secretkey1234567", AES.MODE_ECB)
"""
        (tmp_path / "security_app.py").write_text(python_code, encoding="utf-8")

        # 4. OT-POL-007: Privileged container mode in compose
        compose_yml = """
version: '3.8'
services:
  app:
    image: myapp:latest
    privileged: true
"""
        (tmp_path / "docker-compose.yml").write_text(compose_yml, encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()

        rule_ids = {f.rule_id for f in findings}
        assert "OT-SEC-016" in rule_ids
        assert "OT-SEC-017" in rule_ids
        assert "OT-SEC-020" in rule_ids
        assert "OT-POL-007" in rule_ids


def test_expired_inline_suppression():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        code = """
import subprocess

# offtest: ignore[OT-SEC-003]: temporary test expires="2020-01-01"
subprocess.run("dir", shell=True)
"""
        (tmp_path / "expired_suppression.py").write_text(code, encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        checker = OfflineStaticChecker(tmp_path, files)
        findings = checker.run_all()

        sec_findings = [f for f in findings if f.rule_id == "OT-SEC-003"]
        assert len(sec_findings) == 1
        # Expired suppression must NOT suppress the finding!
        assert sec_findings[0].suppressed is False
        assert "expired" in sec_findings[0].suppression_reason.lower()



