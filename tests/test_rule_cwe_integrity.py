"""tests/test_rule_cwe_integrity.py

Verification tests ensuring:
1. Every security rule has a valid primary CWE ID matching '^CWE-\\d+$'.
2. Specific authorization & authentication rules match required CWE hierarchy:
   - OT-SEC-012: CWE-306 (Missing Authentication for Critical Function)
   - OT-SEC-013: CWE-639 (Authorization Bypass Through User-Controlled Key / IDOR)
   - OT-SEC-014: CWE-862 (Missing Authorization)
3. Secondary CWE tags are present for granular taxonomic classification.
4. Line-independent logicalLocationKey partial fingerprints are generated.
5. Deduplication and clustering consolidates occurrences and attaches relatedLocations.
6. Normalized 0-100 priority scoring behaves deterministically across combinations.
"""
import re
from offtest.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    compute_priority,
    deduplicate_and_cluster_findings,
)
from offtest.core.rules import RULES, make_finding


def test_rule_cwe_format_and_coverage():
    """Verify all vulnerability security rules have well-formed CWE identifiers."""
    cwe_pattern = re.compile(r"^CWE-\d+$")
    for rule_id, rule in RULES.items():
        if rule.category in (FindingCategory.VULNERABILITY, FindingCategory.SECRET):
            assert rule.cwe_id is not None, f"Rule {rule_id} missing primary CWE ID"
            assert cwe_pattern.match(rule.cwe_id), f"Rule {rule_id} CWE '{rule.cwe_id}' does not match pattern"
            for sec_cwe in rule.cwe_secondary_ids:
                assert cwe_pattern.match(sec_cwe), f"Rule {rule_id} secondary CWE '{sec_cwe}' invalid"


def test_access_control_cwe_specificity():
    """Ensure access control and authorization rules use precise leaf CWE tags."""
    sec_12 = RULES["OT-SEC-012"]
    assert sec_12.cwe_id == "CWE-306"
    assert "CWE-862" in sec_12.cwe_secondary_ids

    sec_13 = RULES["OT-SEC-013"]
    assert sec_13.cwe_id == "CWE-639"
    assert "CWE-862" in sec_13.cwe_secondary_ids

    sec_14 = RULES["OT-SEC-014"]
    assert sec_14.cwe_id == "CWE-862"
    assert "CWE-863" in sec_14.cwe_secondary_ids


def test_normalized_priority_scale():
    """Verify normalized 0-100 priority score calculations and bounds."""
    # High severity, Confirmed, Static-only, Reachable, Public: 70 * 1.0 * 1.0 * 1.0 * 1.0 = 70.0
    p1 = compute_priority(Severity.HIGH, Confidence.CONFIRMED, evidence_level="static-only", reachability="reachable", exposure="public_unauth")
    assert p1 == 70.0

    # High severity, Likely, Static-only, Reachable, Public: 70 * 0.85 * 1.0 * 1.0 * 1.0 = 59.5
    p2 = compute_priority(Severity.HIGH, Confidence.LIKELY, evidence_level="static-only", reachability="reachable", exposure="public_unauth")
    assert p2 == 59.5

    # Medium severity, Confirmed, Static-only, Reachable, Public: 40 * 1.0 * 1.0 * 1.0 * 1.0 = 40.0
    p3 = compute_priority(Severity.MEDIUM, Confidence.CONFIRMED, evidence_level="static-only", reachability="reachable", exposure="public_unauth")
    assert p3 == 40.0

    # Unreachable Critical internal: 100 * 1.0 * 1.0 * 0.2 * 0.5 = 10.0
    p4 = compute_priority(Severity.CRITICAL, Confidence.CONFIRMED, evidence_level="static-only", reachability="unreachable", exposure="internal")
    assert p4 == 10.0

    # Model hypothesis is strictly capped at 25.0
    p5 = compute_priority(Severity.CRITICAL, Confidence.CONFIRMED, evidence_level="model-hypothesis", reachability="reachable", exposure="public_unauth")
    assert p5 <= 25.0

    # CISA KEV floor override sets priority to at least 80.0
    p_kev = compute_priority(Severity.MEDIUM, Confidence.LOW, evidence_level="static-only", reachability="unreachable", exposure="internal", cisa_kev=True)
    assert p_kev >= 80.0

    # Flaky test does not demote below static-only (1.00)
    p_flaky = compute_priority(Severity.HIGH, Confidence.CONFIRMED, evidence_level="flaky-test", reachability="reachable", exposure="public_unauth")
    assert p_flaky == 70.0


def test_line_independent_fingerprint():
    """Verify logicalLocationKey excludes line numbers for stable baseline diffing."""
    f1 = make_finding(RULES["OT-SEC-001"], file_path="app/views.py", line_number=42, evidence="eval(user_input)")
    f2 = make_finding(RULES["OT-SEC-001"], file_path="app/views.py", line_number=999, evidence="eval(user_input)")

    # Different physical line numbers, but same logicalLocationKey partial fingerprint
    assert f1.partial_fingerprints["logicalLocationKey"] == f2.partial_fingerprints["logicalLocationKey"]


def test_gate_hard_overrides():
    """Verify that Gate Hard Overrides catch Critical/High/KEV/Secrets regardless of score."""
    from offtest.checks.planner import CheckPlanner
    from offtest.core.models import FileDisposition, FileRecord
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        # Create unreferenced internal script with a dynamic eval issue
        p = tmp_path / "helper.py"
        p.write_text("x = input()\neval(x)", encoding="utf-8")
        files = [
            FileRecord(
                path="helper.py",
                size_bytes=len(p.read_bytes()),
                sha256="h1",
                language="Python",
                category="source",
                disposition=FileDisposition.ANALYZED,
                disposition_reason="Source",
            )
        ]
        planner = CheckPlanner(tmp_path, files)
        results, findings = planner.execute_all()

        # Helper dynamic eval finding has Severity=HIGH, Confidence=LIKELY -> must block gate
        eval_f = next(f for f in findings if f.rule_id == "OT-SEC-001")
        assert eval_f.severity == Severity.HIGH
        stat_result = next(r for r in results if r.tool_name == "offtest-static-scanner")
        assert stat_result.gate_outcome == "Fail"


def test_deduplicate_and_cluster():
    """Verify dedup consolidates multiple occurrences and attaches secondary relatedLocations."""
    f_high = make_finding(RULES["OT-SEC-001"], file_path="api/helpers.py", line_number=10, evidence="eval(a)", severity=Severity.HIGH)
    f_low = make_finding(RULES["OT-SEC-001"], file_path="api/helpers.py", line_number=30, evidence="eval(b)", severity=Severity.MEDIUM)

    # Set same cluster notation {file}:{rule}:{parent}
    f_high.root_cause_cluster = "api/helpers.py:OT-SEC-001:helper_func"
    f_low.root_cause_cluster = "api/helpers.py:OT-SEC-001:helper_func"

    deduped = deduplicate_and_cluster_findings([f_low, f_high])
    assert len(deduped) == 1
    assert deduped[0].id == f_high.id
    assert deduped[0].related_locations is not None
    assert len(deduped[0].related_locations) == 1
