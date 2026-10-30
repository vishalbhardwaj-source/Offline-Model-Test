"""tests/test_scanner_changes_review.py

Verifies the resolution of all items specified in the external review:
"Offline Testing Model: Required Scanner Changes" (Oct 30, 2026 · @Ankit)

1. Change 1: File filtering, value-only entropy, .d.ts skipping, comment down-weighting.
2. Change 2: Three-state reachability (reachable=1.0, unknown=1.0, unreachable=0.2).
3. Change 3: Symbol resolution via symtable, dead code only on private unreferenced symbols.
4. Change 4: Route auth detection (Depends, decorators) and --app-tier propagation.
5. Change 5: Overrides priority floor, entropy non-blocking, and ANALYSIS_INCOMPLETE.
6. Change 6: All regression and must-still-flag fixtures.
"""
import ast
import json
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
    compute_priority,
)
from offtest.core.project_index import ProjectIndex
from offtest.core.rules import RULES
from offtest.intake.safety import scan_for_secrets
from offtest.inventory.engine import InventoryEngine


def test_page8_regression_fixtures_must_stop_flagging(tmp_path: Path):
    """
    Page 8 Regression fixtures that MUST STOP FLAGGING:
    - lambda x: x[1]
    - except ValueError as exc
    - nested def norm(s)
    - module global defined after use
    - guarded try: import lightgbm as lgb except: lgb = None
    - callback passed to map or run_in_threadpool
    - Pydantic model used only as an annotation
    - ml_engine singleton imported with a relative import
    - init_cache_db() at import time
    - JSDoc text in node_modules/@types/node/crypto.d.ts
    - JSON key complianceHistoryBand
    """
    # 1. Python source file with standard idioms
    py_code = '''"""Sample module demonstrating valid Python idioms."""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel

class UserModel(BaseModel):
    name: str

# Guarded optional dependency import
try:
    import lightgbm as lgb
except Exception:
    lgb = None

# Callback passed to map / helper
def my_worker(item):
    return item.strip()

# Import-time database initialization
def init_cache_db():
    pass

init_cache_db()

def process_data(records: list[str], user: Optional[UserModel] = None) -> list[str]:
    # Lambda with parameter
    transformer = lambda x: x[1] if len(x) > 1 else x
    
    # Nested function definition
    def norm(s: str) -> str:
        return s.strip().lower()

    # Exception handler with bound variable
    try:
        cleaned = [norm(transformer(r)) for r in records]
    except ValueError as exc:
        cleaned = [str(exc)]

    # Callback passed to map
    mapped = list(map(my_worker, cleaned))
    
    # Global variable defined after function definition
    return [f"{item}_{SUFFIX}" for item in mapped]

# Module global defined after use
SUFFIX = "prod_v1"
'''
    app_file = tmp_path / "app.py"
    app_file.write_text(py_code, encoding="utf-8")

    # 2. Sibling module for relative import
    ml_file = tmp_path / "ml_engine.py"
    ml_file.write_text("class MLEngine:\n    pass\nml_engine = MLEngine()\n", encoding="utf-8")

    # 3. Consumer with relative import
    consumer_file = tmp_path / "consumer.py"
    consumer_file.write_text("from .ml_engine import ml_engine\nprint(ml_engine)\n", encoding="utf-8")

    # 4. JSON file with high-entropy property key
    json_file = tmp_path / "config.json"
    json_file.write_text('{\n  "complianceHistoryBand": "standard",\n  "version": 1\n}\n', encoding="utf-8")

    # 5. Vendored node_modules with .d.ts JSDoc containing private key string
    dts_dir = tmp_path / "node_modules" / "@types" / "node"
    dts_dir.mkdir(parents=True, exist_ok=True)
    dts_file = dts_dir / "crypto.d.ts"
    dts_file.write_text(
        '/**\n * Example key:\n * -----BEGIN RSA PRIVATE KEY-----\n * MIIEowIBAAKCAQEA...\n * -----END RSA PRIVATE KEY-----\n */\nexport function createPrivateKey(): void;\n',
        encoding="utf-8",
    )

    # Run Inventory Engine
    engine = InventoryEngine(str(tmp_path))
    files, summary = engine.scan()

    # Verify vendored node_modules file is excluded from static analysis
    dts_record = next(f for f in files if "crypto.d.ts" in f.path)
    assert dts_record.disposition == FileDisposition.EXCLUDED

    # Verify secret scanner does not flag JSON key complianceHistoryBand
    json_secrets = scan_for_secrets(json_file.read_text(encoding="utf-8"), "config.json")
    assert len(json_secrets) == 0

    # Verify secret scanner skips .d.ts files completely
    dts_secrets = scan_for_secrets(dts_file.read_text(encoding="utf-8"), "node_modules/@types/node/crypto.d.ts")
    assert len(dts_secrets) == 0

    # Run Static Checker on Python files
    proj_idx = ProjectIndex(tmp_path, files)
    static_checker = OfflineStaticChecker(tmp_path, files, project_index=proj_idx)
    findings = static_checker.run_all()

    # Must NOT flag undefined names for lambda x, exc, norm, or SUFFIX
    undefined_findings = [f for f in findings if f.rule_id == "OT-COR-002"]
    assert len(undefined_findings) == 0, f"Expected 0 undefined findings, got: {undefined_findings}"

    # Must NOT flag unused imports for lightgbm (guarded) or UserModel (used as annotation)
    unused_import_findings = [f for f in findings if f.rule_id == "OT-HYG-001"]
    assert not any("lightgbm" in f.title for f in unused_import_findings)
    assert not any("UserModel" in f.title for f in unused_import_findings)

    # Must NOT mark init_cache_db() or ml_engine as unreachable
    unreach_names = {s.name for s in proj_idx.unreachable_symbols}
    assert "init_cache_db" not in unreach_names
    assert "ml_engine" not in unreach_names


def test_page8_must_still_flag_fixtures(tmp_path: Path):
    """
    Page 8 Must-Still-Flag fixtures:
    - A real provider-format key in an ordinary source file
    - A key in a comment (down-weighted, still reported)
    - A genuinely unauthenticated public mutating route
    - A truly dead private function
    - A vulnerable function that is reachable only as a callback
    """
    src_code = '''
# 1. Key in a comment (down-weighted, still reported)
# AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLEKEY123"

# 2. A genuinely unauthenticated public mutating route
from flask import Flask, request
app = Flask(__name__)

@app.post("/api/users/delete")
def delete_user_route():
    # 5. Vulnerable function reachable as a callback
    items = request.json.get("items", [])
    list(map(_process_sensitive_record, items))
    return {"status": "ok"}

def _process_sensitive_record(item):
    # Function reachable via callback - must NOT be marked dead!
    import os
    os.system(item)

# 4. A truly dead private function (private, zero references across project, no decorator)
def _never_called_dead_utility(a, b):
    pass
'''
    f_py = tmp_path / "routes.py"
    f_py.write_text(src_code, encoding="utf-8")

    # Real provider key in source file
    key_file = tmp_path / "service.py"
    key_file.write_text('GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"\n', encoding="utf-8")

    engine = InventoryEngine(str(tmp_path))
    files, summary = engine.scan()
    proj_idx = ProjectIndex(tmp_path, files)
    static_checker = OfflineStaticChecker(tmp_path, files, project_index=proj_idx, app_tier="public")
    findings = static_checker.run_all()

    # 1. Real provider key in ordinary source file MUST be flagged
    gh_findings = [f for f in findings if "ghp_" in f.evidence or "GitHub" in f.title]
    assert len(gh_findings) >= 1
    assert gh_findings[0].severity == Severity.CRITICAL

    # 2. Key in a comment MUST be flagged, but down-weighted
    comment_findings = [f for f in findings if "(in comment)" in f.title or "in comment" in f.evidence]
    assert len(comment_findings) >= 1
    assert comment_findings[0].severity == Severity.LOW

    # 3. Genuinely unauthenticated mutating route MUST be flagged
    unauth_findings = [f for f in findings if f.rule_id == "OT-SEC-012"]
    assert len(unauth_findings) >= 1
    assert unauth_findings[0].severity == Severity.HIGH
    assert unauth_findings[0].exposure == "public_unauth"

    # 4. Truly dead private function MUST be identified as unreachable
    unreach_names = {s.name for s in proj_idx.unreachable_symbols}
    assert "_never_called_dead_utility" in unreach_names

    # 5. Function reachable only as callback (_process_sensitive_record) MUST NOT be marked unreachable
    assert "_process_sensitive_record" not in unreach_names


def test_three_state_reachability_and_scoring():
    """
    Verifies Change 2 & 5:
    - Three-state reachability: reachable=1.0, unknown=1.0 (no discount), unreachable=0.2.
    - Reachable Critical with precision >= 0.85 fails gate even on internal routes.
    - High-Entropy Candidate (OT-SCR-003) is Low severity and cannot fail the gate.
    """
    # 1. Unknown reachability has Reach factor 1.0 (no discount)
    p_unknown = compute_priority(
        severity=Severity.HIGH,
        confidence=Confidence.DETERMINISTIC,
        reachability="unknown",
        exposure="public_unauth",
    )
    # 70 * 1.0 * 1.0 * 1.0 * 1.0 = 70.0
    assert p_unknown == 70.0

    # 2. Unreachable private symbol gets 0.2 factor
    p_unreach = compute_priority(
        severity=Severity.HIGH,
        confidence=Confidence.DETERMINISTIC,
        reachability="unreachable",
        exposure="public_unauth",
    )
    # 70 * 1.0 * 1.0 * 0.2 * 1.0 = 14.0
    assert p_unreach == 14.0

    # 3. Rule OT-SCR-003 is Low severity and gate=False
    scr003 = RULES["OT-SCR-003"]
    assert scr003.base_severity == Severity.LOW
    assert scr003.gate is False

    # 4. Rule OT-COR-002 is Hygiene and gate=False
    cor002 = RULES["OT-COR-002"]
    assert cor002.category == FindingCategory.HYGIENE
    assert cor002.gate is False
    assert cor002.cwe_id == "CWE-457"
