import json
from pathlib import Path
from typing import Any, Dict, List
from offtest.core.models import Finding, RunContext, Severity


class SARIFReportGenerator:
    """Generates an OASIS SARIF 2.1.0 report for CI/CD consumption."""

    def __init__(self, context: RunContext):
        self.ctx = context

    def generate_sarif(self) -> Dict[str, Any]:
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in self.ctx.findings:
            rule_id = f"OFFTEST-{(f.check_tool or 'scanner').upper()}-{f.id}"
            
            # Map severity to SARIF level
            if f.severity in [Severity.CRITICAL, Severity.HIGH]:
                level = "error"
            elif f.severity == Severity.MEDIUM:
                level = "warning"
            else:
                level = "note"

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.impact},
                    "defaultConfiguration": {"level": level},
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

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"{f.title}: {f.impact}\n\nEvidence:\n{f.evidence}\n\nSuggested Action: {f.suggested_action}"
                },
                "locations": [loc_dict],
            })

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
                    "results": results,
                }
            ],
        }
        return sarif_doc

    def save_sarif(self, out_path: Path):
        data = self.generate_sarif()
        raw_sarif = json.dumps(data, indent=2)
        from offtest.intake.safety import redact_sensitive_data
        sanitized_sarif = redact_sensitive_data(raw_sarif)
        out_path.write_text(sanitized_sarif, encoding="utf-8")
