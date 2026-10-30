"""offtest/inventory/advisory_matcher.py

Offline vulnerability advisory matching (OSV / CVE snapshot) for SBOM components.
Performs deterministic version checking against an offline vulnerability database
and uses call-graph / import reachability to provide VEX-style statuses
(e.g., 'affected' vs 'not_affected' due to code reachability).
"""
from __future__ import annotations

import datetime
import re
from typing import Any, Dict, List, Optional, Tuple

from offtest.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    SBOMComponent,
    Severity,
)
from offtest.core.project_index import ProjectIndex
from offtest.core.rules import RULES, make_finding

# Offline curated advisory database snapshot metadata
ADVISORY_SNAPSHOT_DATE = "2026-10-01"
ADVISORY_STALENESS_THRESHOLD_DAYS = 90


def check_advisory_staleness() -> Tuple[bool, int, str]:
    """
    Evaluates whether the local offline advisory database snapshot is stale.
    Returns: (is_stale, age_days, message)
    """
    try:
        snap_dt = datetime.date.fromisoformat(ADVISORY_SNAPSHOT_DATE)
        today = datetime.date.today()
        age = (today - snap_dt).days
        is_stale = age > ADVISORY_STALENESS_THRESHOLD_DAYS
        msg = f"Offline advisory snapshot is {age} days old (snapshot date: {ADVISORY_SNAPSHOT_DATE})."
        if is_stale:
            msg += f" WARNING: Exceeds threshold of {ADVISORY_STALENESS_THRESHOLD_DAYS} days. Consider refreshing the offline advisory mirror."
        return is_stale, age, msg
    except Exception:
        return False, 0, "Advisory snapshot date verification unavailable."


def _parse_version(ver_str: str) -> Tuple[int, ...]:
    """Extract numeric parts of a semantic version string."""
    nums = re.findall(r"\d+", ver_str)
    if not nums:
        return (0, 0, 0)
    return tuple(int(x) for x in nums[:3])


def _version_less_than(v1_str: str, v2_str: str) -> bool:
    """Returns True if v1 < v2 under simple 3-tuple semver."""
    try:
        p1 = _parse_version(v1_str)
        p2 = _parse_version(v2_str)
        # Pad to length 3
        while len(p1) < 3:
            p1 = p1 + (0,)
        while len(p2) < 3:
            p2 = p2 + (0,)
        return p1 < p2
    except Exception:
        return False


# Offline curated advisory database snapshot (Air-gapped OSV/CVE entries with CISA KEV & EPSS)
OFFLINE_ADVISORIES: List[Dict[str, Any]] = [
    # --- PyPI Advisories ---
    {
        "ecosystem": "pypi",
        "name": "requests",
        "cve": "CVE-2023-32681",
        "fixed_version": "2.31.0",
        "title": "Unintended Leak of Proxy-Authorization Header",
        "summary": "Requests releases Proxy-Authorization header to destination servers when navigating across HTTPS proxies.",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "base_severity": Severity.HIGH,
        "cisa_kev": False,
        "epss_score": 0.00145,
    },
    {
        "ecosystem": "pypi",
        "name": "urllib3",
        "cve": "CVE-2023-45803",
        "fixed_version": "2.0.7",
        "title": "HTTP Request Body Not Stripped on Cross-Host Redirect",
        "summary": "urllib3 does not remove request body data on 303 redirects.",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "base_severity": Severity.MEDIUM,
        "cisa_kev": False,
        "epss_score": 0.00085,
    },
    {
        "ecosystem": "pypi",
        "name": "flask",
        "cve": "CVE-2023-30861",
        "fixed_version": "2.2.5",
        "title": "Cookie Session Disclosure via Caching Proxy",
        "summary": "When returning response without session modification, Set-Cookie header may leak via upstream caching.",
        "cwe_id": "CWE-524",
        "cwe_name": "Information Exposure Through Caching",
        "base_severity": Severity.HIGH,
        "cisa_kev": False,
        "epss_score": 0.00092,
    },
    {
        "ecosystem": "pypi",
        "name": "jinja2",
        "cve": "CVE-2024-22195",
        "fixed_version": "3.1.3",
        "title": "Cross-Site Scripting via XML/HTML Attribute Injection",
        "summary": "xmlattr filter allows injection of arbitrary HTML/XML attributes.",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "base_severity": Severity.HIGH,
        "cisa_kev": False,
        "epss_score": 0.00112,
    },
    {
        "ecosystem": "pypi",
        "name": "cryptography",
        "cve": "CVE-2023-49083",
        "fixed_version": "41.0.6",
        "title": "NULL Pointer Dereference in PKCS7 Parsing",
        "summary": "Loading malformed PKCS7 certificates triggers NULL dereference crashing the process.",
        "cwe_id": "CWE-476",
        "cwe_name": "NULL Pointer Dereference",
        "base_severity": Severity.MEDIUM,
        "cisa_kev": False,
        "epss_score": 0.00045,
    },
    {
        "ecosystem": "pypi",
        "name": "pyyaml",
        "cve": "CVE-2020-14343",
        "fixed_version": "5.4.0",
        "title": "Arbitrary Code Execution via FullLoader",
        "summary": "YAMLLoader / FullLoader vulnerability allows arbitrary code execution during deserialization.",
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "base_severity": Severity.CRITICAL,
        "cisa_kev": True,
        "epss_score": 0.94210,
    },
    # --- NPM Advisories ---
    {
        "ecosystem": "npm",
        "name": "lodash",
        "cve": "CVE-2021-23337",
        "fixed_version": "4.17.21",
        "title": "Command Injection via lodash.template",
        "summary": "Passing untrusted template strings to template allows command injection via variable name interpolation.",
        "cwe_id": "CWE-94",
        "cwe_name": "Improper Control of Generation of Code ('Code Injection')",
        "base_severity": Severity.HIGH,
        "cisa_kev": False,
        "epss_score": 0.00318,
    },
    {
        "ecosystem": "npm",
        "name": "axios",
        "cve": "CVE-2021-3749",
        "fixed_version": "0.21.2",
        "title": "Regular Expression Denial of Service in trim Helper",
        "summary": "Vulnerable regular expression in trim helper causes catastrophic backtracking when processing long strings.",
        "cwe_id": "CWE-1333",
        "cwe_name": "Inefficient Regular Expression Complexity",
        "base_severity": Severity.HIGH,
        "cisa_kev": False,
        "epss_score": 0.00067,
    },
    {
        "ecosystem": "npm",
        "name": "express",
        "cve": "CVE-2024-29041",
        "fixed_version": "4.19.2",
        "title": "Open Redirect via Malformed Path in static Middleware",
        "summary": "Express static middleware allows open redirect when requesting encoded path sequences.",
        "cwe_id": "CWE-601",
        "cwe_name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "base_severity": Severity.MEDIUM,
        "cisa_kev": False,
        "epss_score": 0.00088,
    },
    {
        "ecosystem": "npm",
        "name": "json5",
        "cve": "CVE-2022-46175",
        "fixed_version": "2.2.2",
        "title": "Prototype Pollution in JSON5 parse Method",
        "summary": "Parsing crafted JSON5 payloads pollutes Object.prototype properties.",
        "cwe_id": "CWE-1321",
        "cwe_name": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
        "base_severity": Severity.HIGH,
        "cisa_kev": False,
        "epss_score": 0.00120,
    },
]


class OfflineAdvisoryMatcher:
    """
    Offline vulnerability advisor matching SBOM components against
    air-gapped OSV / CVE records and evaluating code reachability.
    """

    def __init__(self, project_index: Optional[ProjectIndex] = None):
        self.project_index = project_index
        # Build lookup set of all modules imported anywhere across the project codebase
        self.imported_modules = set()
        if project_index:
            for mod in project_index.imported_modules:
                self.imported_modules.add(mod.lower())
                # Also include top-level package name
                if "." in mod:
                    self.imported_modules.add(mod.split(".")[0].lower())

    def match(self, components: List[SBOMComponent]) -> List[Finding]:
        findings: List[Finding] = []

        # Audit advisory staleness and emit warning finding if older than threshold
        is_stale, age_days, warn_msg = check_advisory_staleness()
        if is_stale and "OT-SUP-006" in RULES:
            f_path = components[0].source_file if components and components[0].source_file else "SBOM"
            findings.append(
                make_finding(
                    RULES["OT-SUP-006"],
                    path=f_path,
                    line=1,
                    evidence=warn_msg,
                    exposure="internal",
                    reachability="reachable",
                )
            )

        rule = RULES.get("OT-SUP-004")
        if not rule:
            return findings

        for comp in components:
            comp_name = comp.name.lower()
            comp_ver = comp.version
            if not comp_ver or comp_ver in ("unknown", "unspecified", "*"):
                continue

            for adv in OFFLINE_ADVISORIES:
                if adv["ecosystem"] != comp.ecosystem:
                    continue
                if adv["name"].lower() != comp_name:
                    continue

                if _version_less_than(comp_ver, adv["fixed_version"]):
                    # Reachability analysis: check if package is imported in project
                    is_reachable = (
                        comp_name in self.imported_modules
                        or any(m.startswith(comp_name) for m in self.imported_modules)
                    )

                    # VEX status
                    if is_reachable:
                        vex_status = "affected"
                        reachability = "reachable"
                        evidence_level = "reachable"
                        finding_sev = adv["base_severity"]
                        confidence = Confidence.CONFIRMED
                    else:
                        vex_status = "not_affected (component symbols not imported)"
                        reachability = "unreachable"
                        evidence_level = "static-only"
                        # Downgrade severity for unreachable dependency
                        finding_sev = Severity.LOW if adv["base_severity"] != Severity.CRITICAL else Severity.MEDIUM
                        confidence = Confidence.LIKELY

                    is_stale, age, staleness_msg = check_advisory_staleness()
                    cisa_kev = adv.get("cisa_kev", False)
                    epss_score = adv.get("epss_score", 0.0)
                    kev_str = " | CISA KEV: YES (Known Exploited)" if cisa_kev else " | CISA KEV: No"
                    epss_str = f" | EPSS: {epss_score:.4f}"
                    impact_desc = (
                        f"{adv['title']} ({adv['cve']}){kev_str}{epss_str}. Fixed in version {adv['fixed_version']}. "
                        f"VEX Status: {vex_status}. Snapshot: {ADVISORY_SNAPSHOT_DATE} ({staleness_msg}). {adv['summary']}"
                    )
                    evidence_text = (
                        f"Component '{comp.name}' version '{comp.version}' ({comp.source_file}) "
                        f"is lower than fixed version '{adv['fixed_version']}'. Reachability: {reachability}.{kev_str}{epss_str}."
                    )
                    suggested_action = (
                        f"Upgrade {comp.name} to version {adv['fixed_version']} or later in {comp.source_file}."
                    )

                    finding = make_finding(
                        rule,
                        file_path=comp.source_file,
                        line_number=1,
                        evidence=evidence_text,
                        impact=impact_desc,
                        suggested_action=suggested_action,
                        severity=finding_sev,
                        confidence=confidence,
                        evidence_level=evidence_level,
                        reachability=reachability,
                        exposure="internal",
                        check_tool="offline-advisory-matcher",
                        override_title=f"Vulnerable Dependency: {comp.name} < {adv['fixed_version']} ({adv['cve']})",
                    )
                    # Preserve advisory specific CWE if provided
                    if adv.get("cwe_id"):
                        finding.cwe_id = adv["cwe_id"]
                        finding.cwe_name = adv.get("cwe_name")

                    findings.append(finding)

        return findings
