import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from offtest.core.models import Finding, RunContext, Severity


class SARIFReportGenerator:
    """Generates an OASIS SARIF 2.1.0 report for CI/CD consumption with baseline comparison."""

    def __init__(self, context: RunContext, strip_snippets: bool = False, baseline_path: Optional[Path] = None):
        self.ctx = context
        self.strip_snippets = strip_snippets
        self.baseline_path = Path(baseline_path) if baseline_path else None
        self._baseline_fingerprints = self._load_baseline_fingerprints()

    def _load_baseline_fingerprints(self) -> set:
        if not self.baseline_path or not self.baseline_path.is_file():
            return set()
        try:
            data = json.loads(self.baseline_path.read_text(encoding="utf-8"))
            keys = set()
            for run in data.get("runs", []):
                for res in run.get("results", []):
                    pfp = res.get("partialFingerprints", {})
                    if "logicalLocationKey" in pfp:
                        keys.add(pfp["logicalLocationKey"])
                    fp = res.get("properties", {}).get("fingerprint")
                    if fp:
                        keys.add(fp)
            return keys
        except Exception:
            return set()

    def generate_sarif(self) -> Dict[str, Any]:
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in self.ctx.findings:
            rule_id = getattr(f, "rule_id", None) or f"OFFTEST-{(f.check_tool or 'scanner').upper()}-{f.id}"
            
            # Map severity to SARIF level
            if f.severity in [Severity.CRITICAL, Severity.HIGH]:
                level = "error"
            elif f.severity == Severity.MEDIUM:
                level = "warning"
            else:
                level = "note"

            if rule_id not in rules:
                rule_tags = ["security"]
                if getattr(f, "category", None):
                    rule_tags.append(str(f.category.value))
                if getattr(f, "cwe_id", None):
                    rule_tags.append(f.cwe_id)
                if getattr(f, "owasp_category", None):
                    rule_tags.append(f.owasp_category)
                if getattr(f, "asvs_chapter", None):
                    rule_tags.append(f.asvs_chapter)

                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.impact},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "tags": rule_tags,
                    },
                }

            loc_dict: Dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file_path or "repository",
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
            if f.line_number:
                loc_dict["physicalLocation"]["region"] = {
                    "startLine": f.line_number,
                    "startColumn": 1,
                }

            evidence_text = "[CODE SNIPPET STRIPPED FOR AIR-GAP EXPORT]" if self.strip_snippets else f.evidence
            
            logical_key = (f.partial_fingerprints.get("logicalLocationKey") if getattr(f, "partial_fingerprints", None) else None) or getattr(f, "fingerprint", None)
            baseline_state = "unchanged" if (logical_key and logical_key in self._baseline_fingerprints) else "new"
            f.baseline_state = baseline_state

            res_item: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "baselineState": baseline_state,
                "message": {
                    "text": f"{f.title}: {f.impact}\n\nEvidence:\n{evidence_text}\n\nSuggested Action: {f.suggested_action}"
                },
                "locations": [loc_dict],
                "properties": {
                    "priorityScore": getattr(f, "priority_score", 1.0),
                    "reachability": getattr(f, "reachability", "unknown"),
                    "exposure": getattr(f, "exposure", "internal"),
                    "evidenceLevel": getattr(f, "evidence_level", "static-only"),
                    "fingerprint": getattr(f, "fingerprint", None),
                    "rootCauseCluster": getattr(f, "root_cause_cluster", None),
                    "secondaryCwes": getattr(f, "cwe_secondary_ids", []),
                    "oracleSatisfied": getattr(f, "oracle_satisfied", False),
                    "oracleOrigin": getattr(f, "oracle_origin", None),
                    "flakyTestObserved": getattr(f, "flaky_test_observed", False),
                    "cisaKev": getattr(f, "cisa_kev", False),
                    "epssScore": getattr(f, "epss_score", None),
                },
            }

            # SARIF line-independent partialFingerprints for baselineState diffing
            if getattr(f, "partial_fingerprints", None):
                res_item["partialFingerprints"] = f.partial_fingerprints
            elif getattr(f, "fingerprint", None):
                res_item["partialFingerprints"] = {"logicalLocationKey": f.fingerprint}

            # Secondary related locations from deduplication clustering
            if getattr(f, "related_locations", None):
                res_item["relatedLocations"] = f.related_locations

            # Inline suppression handling
            if getattr(f, "suppressed", False):
                res_item["suppressions"] = [
                    {
                        "kind": "inSource",
                        "status": "accepted",
                        "justification": getattr(f, "suppression_reason", "Suppressed via inline directive"),
                    }
                ]

            # Emit SARIF codeFlows for taint / injection issues
            injection_rules = ("OT-SEC-001", "OT-SEC-002", "OT-SEC-003", "OT-SEC-004", "OT-SEC-005", "OT-SEC-007", "OT-SEC-008")
            if f.rule_id in injection_rules and f.file_path and f.line_number:
                src_line = max(1, f.line_number - 2)
                res_item["codeFlows"] = [
                    {
                        "message": {"text": f"Taint propagation trace to sink: {f.title}"},
                        "threadFlows": [
                            {
                                "locations": [
                                    {
                                        "location": {
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": f.file_path,
                                                    "uriBaseId": "%SRCROOT%",
                                                },
                                                "region": {
                                                    "startLine": src_line,
                                                    "startColumn": 1,
                                                },
                                            },
                                            "message": {
                                                "text": "Source: dynamic parameter ingestion / entry point",
                                            },
                                        },
                                        "importance": "essential",
                                    },
                                    {
                                        "location": {
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": f.file_path,
                                                    "uriBaseId": "%SRCROOT%",
                                                },
                                                "region": {
                                                    "startLine": f.line_number,
                                                    "startColumn": 1,
                                                },
                                            },
                                            "message": {
                                                "text": f"Sink: vulnerable execution without sanitization ({f.rule_id})",
                                            },
                                        },
                                        "importance": "essential",
                                    },
                                ]
                            }
                        ],
                    }
                ]

            results.append(res_item)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "offtest",
                            "semanticVersion": "0.2.0",
                            "informationUri": "https://github.com/vishalbhardwaj-source/Offline-Model-Test",
                            "rules": list(rules.values()),
                        }
                    },
                    "properties": {
                        "runId": getattr(self.ctx, "run_id", "unknown_run"),
                        "bareHostOverride": bool(getattr(self.ctx, "accept_no_kernel_isolation", False) and not getattr(self.ctx, "kernel_isolation_active", False)),
                        "kernelIsolationActive": bool(getattr(self.ctx, "kernel_isolation_active", False)),
                        "networkIsolationMode": getattr(self.ctx, "network_isolation_mode", "unknown"),
                        "offlineEnforced": bool(getattr(self.ctx, "offline_enforced", True)),
                        "languageCoverages": {k: v.model_dump() if hasattr(v, "model_dump") else v for k, v in getattr(self.ctx, "language_coverages", {}).items()},
                    },
                    "results": results,
                }
            ],
        }
        return sarif_doc

    def save_sarif(self, out_path: Path):
        data = self.generate_sarif()
        raw_sarif = json.dumps(data, indent=2)
        from offtest.intake.safety import redact_sensitive_data
        from offtest.core.evidence_store import atomic_write_text
        sanitized_sarif = redact_sensitive_data(raw_sarif)
        atomic_write_text(out_path, sanitized_sarif, encoding="utf-8")
