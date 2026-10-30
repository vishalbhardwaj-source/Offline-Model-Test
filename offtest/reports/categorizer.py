from typing import List, Tuple
from offtest.core.models import Finding, Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}

EXPOSURE_ORDER = {
    "public_unauth": 0,
    "public_auth": 1,
    "internal": 2,
    "test_fixture": 3,
}


def is_hardcoded_finding(f: Finding) -> bool:
    """
    Identifies whether a finding relates to hardcoded secrets, passwords,
    API tokens, or high-entropy credentials.
    """
    category = getattr(f, "category", "") or ""
    rule_id = getattr(f, "rule_id", "") or ""
    title = (getattr(f, "title", "") or "").lower()

    if category == "secret_exposure" or rule_id.startswith("OT-SCR"):
        return True
    if any(k in title for k in ("hardcoded", "secret", "entropy token", "password assignment", "plaintext credential")):
        return True
    return False


def sort_findings_by_severity(findings: List[Finding]) -> List[Finding]:
    """
    Sorts findings primarily by priority score descending (with floor overrides >= 90 at top).
    For findings tied or capped at 100:
    Tie-breaker is Severity (Critical first), then Exposure (public_unauth first).
    """
    return sorted(
        findings,
        key=lambda x: (
            -float(getattr(x, "priority_score", 0.0) or 0.0),
            SEVERITY_ORDER.get(x.severity, 99),
            EXPOSURE_ORDER.get(getattr(x, "exposure", "internal"), 99),
        )
    )


def split_findings(findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
    """
    Splits findings into:
    1) hardcoded_findings: Only hardcoded secrets, credentials, tokens
    2) code_defects: Code vulnerabilities, correctness bugs, dead code, unused imports, unpinned actions/deps
    Both lists are returned sorted Critical -> Low.
    """
    hardcoded: List[Finding] = []
    code_defects: List[Finding] = []

    for f in findings:
        if is_hardcoded_finding(f):
            hardcoded.append(f)
        else:
            code_defects.append(f)

    return sort_findings_by_severity(hardcoded), sort_findings_by_severity(code_defects)
