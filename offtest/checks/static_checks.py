import ast
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from offtest.core.models import (
    Confidence,
    EvidenceStatus,
    FileRecord,
    Finding,
    FindingCategory,
    Severity,
)
from offtest.core.rules import RULES, make_finding
from offtest.intake.safety import scan_for_secrets

# Curated deterministic rule-to-CWE mapping table with estimated CVSS baselines
RULE_CWE_CVSS_MAP: Dict[str, Tuple[str, str, float, str]] = {
    "Documented AWS Example Key": ("CWE-798", "Use of Hard-coded Credentials", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "AWS Access Key ID": ("CWE-798", "Use of Hard-coded Credentials", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "Hardcoded Secret": ("CWE-798", "Use of Hard-coded Credentials", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "High-Entropy Secret": ("CWE-798", "Use of Hard-coded Credentials", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Insecure Authentication Endpoint": ("CWE-598", "Use of GET Request Method With Sensitive Query Strings", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"),
    "eval": ("CWE-95", "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "exec": ("CWE-95", "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Command Execution": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "Command Injection": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "os.system": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "DEBUG = True": ("CWE-489", "Active Debug Code", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Remote UNC or Network Reference": ("CWE-829", "Inclusion of Functionality from Untrusted Control Sphere", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Remote Network or UNC Dependency Reference": ("CWE-829", "Inclusion of Functionality from Untrusted Control Sphere", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Remote Package Index": ("CWE-829", "Inclusion of Functionality from Untrusted Control Sphere", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Remote Submodule URL": ("CWE-829", "Inclusion of Functionality from Untrusted Control Sphere", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Remote Git Dependency": ("CWE-829", "Inclusion of Functionality from Untrusted Control Sphere", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Remote VCS or Network Dependency": ("CWE-829", "Inclusion of Functionality from Untrusted Control Sphere", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "External Package Registry Configured": ("CWE-829", "Inclusion of Functionality from Untrusted Control Sphere", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Unpinned Python Dependency": ("CWE-1357", "Reliance on Insufficiently Trustworthy Component", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    "Floating Node.js Dependency": ("CWE-1357", "Reliance on Insufficiently Trustworthy Component", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    "YAML Deserialization": ("CWE-502", "Deserialization of Untrusted Data", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Insecure Object Deserialization": ("CWE-502", "Deserialization of Untrusted Data", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SSL Certificate Verification": ("CWE-295", "Improper Certificate Validation", 7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "Undefined Name": ("CWE-456", "Missing Initialization of a Variable", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    "Division by Zero": ("CWE-369", "Divide By Zero", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
    "Dead Code": ("CWE-561", "Dead Code", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "No-Op Function": ("CWE-561", "Dead Code", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "Uncalled Dead Code": ("CWE-561", "Dead Code", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "Constant Condition": ("CWE-570", "Expression is Always False", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
}

SANDBOX_ARTIFACT_PATTERNS = [
    re.compile(r"ConnectionRefusedError", re.IGNORECASE),
    re.compile(r"OfflineNetworkBlockedError", re.IGNORECASE),
    re.compile(r"socket\.gaierror", re.IGNORECASE),
    re.compile(r"getaddrinfo failed", re.IGNORECASE),
    re.compile(r"URLError", re.IGNORECASE),
    re.compile(r"NewConnectionError", re.IGNORECASE),
    re.compile(r"MaxRetryError", re.IGNORECASE),
    re.compile(r"PermissionError.*(?:APPDATA|USERPROFILE|\.offtest_sandbox)", re.IGNORECASE),
    re.compile(r"Read-only file system", re.IGNORECASE),
    re.compile(r"ModuleNotFoundError.*(?:pytest|sitecustomize)", re.IGNORECASE),
]


def classify_defect_confidence(
    evidence_text: str,
    oracle_origin: str = "static_rule",
    reproduced: bool = True,
    is_sandbox_artifact: Optional[bool] = None,
) -> Tuple[Confidence, bool]:
    """
    Evaluates defect confidence strictly against sandbox artifacts and oracle origin.
    - If signature matches sandbox artifacts, demotes to Possible.
    - If oracle is model_synthesized, demotes strictly to Possible (cannot be Likely or Confirmed).
    - Only reproducible findings from symbolic/human/static oracles receive Confirmed status.
    """
    matched_sandbox = is_sandbox_artifact or any(p.search(evidence_text) for p in SANDBOX_ARTIFACT_PATTERNS)
    if matched_sandbox:
        return Confidence.POSSIBLE, True
    if oracle_origin == "model_synthesized":
        return Confidence.POSSIBLE, False
    if reproduced:
        return Confidence.CONFIRMED, False
    return Confidence.LIKELY, False


def resolve_cwe_cvss(title: str) -> Tuple[Optional[str], Optional[str], Optional[float], Optional[str]]:
    # Match longest key first so specific keys (e.g. "Command Execution") always win
    # over short keys that are substrings (e.g. "exec" inside "Command Execution").
    title_lower = title.lower()
    for key in sorted(RULE_CWE_CVSS_MAP, key=len, reverse=True):
        if key.lower() in title_lower:
            cwe_id, cwe_name, cvss_score, cvss_vector = RULE_CWE_CVSS_MAP[key]
            return cwe_id, cwe_name, cvss_score, cvss_vector
    return None, None, None, None


class OfflineStaticChecker:
    def __init__(self, repo_dir: Path, files: List[FileRecord], project_index: Optional[Any] = None):
        self.repo_dir = repo_dir
        self.files = files
        self.file_hashes: Dict[str, str] = {f.path: f.sha256 for f in files if getattr(f, "sha256", None)}
        if project_index is None:
            from offtest.core.project_index import ProjectIndex
            self.project_index = ProjectIndex(repo_dir, files)
        else:
            self.project_index = project_index

    def is_fixture_or_test(self, rel_path: str, f: Optional[FileRecord] = None) -> bool:
        if f and getattr(f, "category", "") in ("test", "fixture", "test_data"):
            return True
        path_parts = [p.lower() for p in Path(rel_path).parts]
        return any(p in ("tests", "test", "fixtures", "fixture", "mocks", "mock") for p in path_parts)

    def run_all(self, branch: Optional[str] = None) -> List[Finding]:
        findings: List[Finding] = []
        counter = 1

        for f in self.files:
            if f.disposition.value != "analyzed":
                continue

            full_path = self.repo_dir / f.path
            if not full_path.is_file():
                continue

            try:
                raw_bytes = full_path.read_bytes()
                has_bom = raw_bytes.startswith(b"\xef\xbb\xbf")
                content = raw_bytes.decode("utf-8-sig", errors="ignore")
            except Exception:
                continue

            f_sha256 = self.file_hashes.get(f.path)
            path_parts = [p.lower() for p in Path(f.path).parts]
            is_test_or_doc = (
                any(p in ("tests", "test", "fixtures", "fixture", "mocks", "mock", "docs", "doc", "examples", "example") for p in path_parts)
                or f.path.lower().endswith((".example", ".sample", ".template", ".md", ".rst"))
                or getattr(f, "category", "") in ("test", "fixture", "doc", "test_data")
            )

            # 0. File encoding check (e.g. Windows UTF-8 BOM)
            if has_bom and f.language in ("Python", "JavaScript", "TypeScript", "JSON", "YAML"):
                findings.append(
                    make_finding(
                        RULES["OT-HYG-004"],
                        path=f.path,
                        line=1,
                        file_sha256=f_sha256,
                        branch=branch,
                        evidence="Line 1: File starts with 3-byte UTF-8 BOM sequence (0xEF 0xBB 0xBF)",
                        override_title="Non-Standard UTF-8 BOM (Byte Order Mark) Detected",
                    )
                )
                counter += 1

            # 1. Hardcoded secrets check
            secret_hits = scan_for_secrets(content, f.path)
            for line_no, label, preview, fingerprint in secret_hits:
                evidence_str = f"Line {line_no} [detector: {label}, fingerprint: {fingerprint}]: {preview}"
                conf, is_sandbox = classify_defect_confidence(evidence_str, oracle_origin="static_rule", reproduced=True)

                if is_test_or_doc:
                    rule = RULES["OT-SCR-004"]
                    title = f"{label} Detected (Test/Documentation File)"
                    sev = Severity.INFORMATIONAL
                    conf = Confidence.POSSIBLE
                elif "Example Key" in label:
                    rule = RULES["OT-SCR-004"]
                    title = "Documented AWS Example Key (AKIA...EXAMPLE) Detected"
                    sev = Severity.INFORMATIONAL
                    conf = Confidence.CONFIRMED
                elif "Entropy" in label:
                    rule = RULES["OT-SCR-003"]
                    title = f"{label} Detected"
                    sev = Severity.MEDIUM
                    conf = Confidence.POSSIBLE
                elif "AWS" in label:
                    rule = RULES["OT-SCR-001"]
                    title = f"{label} Detected"
                    sev = Severity.CRITICAL
                    conf = Confidence.CONFIRMED if not is_sandbox else Confidence.POSSIBLE
                else:
                    rule = RULES["OT-SCR-002"]
                    title = f"{label} Detected"
                    sev = Severity.CRITICAL
                    conf = Confidence.CONFIRMED if not is_sandbox else Confidence.POSSIBLE

                findings.append(
                    make_finding(
                        rule,
                        path=f.path,
                        line=line_no,
                        file_sha256=f_sha256,
                        branch=branch,
                        evidence=evidence_str,
                        severity=sev,
                        confidence=conf,
                        override_title=title,
                        sandbox_artifact=is_sandbox,
                    )
                )
                counter += 1

            # 2. Python specific checks (AST syntax & security)
            if f.language == "Python":
                syntax_finding, parsed_ast = self._check_python_syntax(f.path, content, counter, branch)
                if syntax_finding:
                    findings.append(syntax_finding)
                    counter += 1
                elif parsed_ast:
                    py_findings = self._check_python_security_ast(f.path, parsed_ast, counter, branch)
                    for item in py_findings:
                        findings.append(item)
                        counter += 1
                    dead_findings = self._check_python_dead_code(f.path, parsed_ast, counter, branch)
                    for item in dead_findings:
                        findings.append(item)
                        counter += 1
                    semantic_findings = self._check_python_semantic_bugs(f.path, parsed_ast, counter, branch)
                    for item in semantic_findings:
                        findings.append(item)
                        counter += 1

            # 3. Dependency and remote reference configuration analysis
            norm_name = Path(f.path).name.lower()
            if ((norm_name.startswith(("requirement", "constraint", "req")) and norm_name.endswith(".txt"))
                    or "requirements" in norm_name or "constraints" in norm_name):
                dep_findings = self._check_requirements(f.path, content, counter, branch)
                for item in dep_findings:
                    findings.append(item)
                    counter += 1

            elif norm_name == "package.json":
                pkg_findings = self._check_package_json(f.path, content, counter, branch)
                for item in pkg_findings:
                    findings.append(item)
                    counter += 1

            elif norm_name == ".gitmodules":
                gitmod_findings = self._check_gitmodules(f.path, content, counter, branch)
                for item in gitmod_findings:
                    findings.append(item)
                    counter += 1

            elif norm_name == "cargo.toml":
                cargo_findings = self._check_cargo_toml(f.path, content, counter, branch)
                for item in cargo_findings:
                    findings.append(item)
                    counter += 1

            elif norm_name in ["pyproject.toml", "setup.cfg"]:
                pyproj_findings = self._check_pyproject_or_setup_cfg(f.path, content, counter, branch)
                for item in pyproj_findings:
                    findings.append(item)
                    counter += 1

            elif norm_name in [".npmrc", "pip.conf"]:
                reg_findings = self._check_registry_config(f.path, content, counter, branch)
                for item in reg_findings:
                    findings.append(item)
                    counter += 1

        # Check project-wide unreachable functions, classes, and no-ops
        uncalled_findings = self._check_project_uncalled_code(branch, counter, existing_findings=findings)
        findings.extend(uncalled_findings)

        # 3. RBAC Access Control: Detect unauthenticated state-changing routes
        if self.project_index and getattr(self.project_index, "routes", None):
            for route in self.project_index.routes:
                meth = route.method.upper()
                if meth in ("POST", "PUT", "DELETE", "PATCH") and not getattr(route, "auth_required", False):
                    p_lower = route.path.lower()
                    if not any(k in p_lower for k in ("login", "signin", "register", "signup", "auth/token", "token")):
                        f_sha = self.file_hashes.get(route.file_path)
                        findings.append(
                            make_finding(
                                RULES["OT-SEC-012"],
                                path=route.file_path,
                                line=route.line_number,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"{meth} {route.path} (handler '{route.handler_name}') has no auth decorators or guards.",
                                override_title=f"Unauthenticated State-Changing Route ({meth} {route.path})",
                                exposure="public_unauth",
                                reachability="reachable",
                                evidence_level="reachable",
                            )
                        )
                        counter += 1

        # 4. Supply Chain: Match SBOM packages against offline CVE advisory snapshot
        try:
            from offtest.inventory.sbom import SBOMGenerator
            from offtest.inventory.advisory_matcher import OfflineAdvisoryMatcher
            sbom_gen = SBOMGenerator(self.repo_dir, self.files)
            sbom_rep = sbom_gen.generate()
            if sbom_rep.components:
                adv_matcher = OfflineAdvisoryMatcher(project_index=self.project_index)
                advisory_findings = adv_matcher.match(sbom_rep.components)
                findings.extend(advisory_findings)
        except Exception:
            pass

        # 5. Inline Suppression Parsing (# offtest: ignore[RULE_ID]) & Root-Cause Clustering
        file_lines_cache: Dict[str, List[str]] = {}
        suppression_regex = re.compile(
            r"#\s*offtest:\s*ignore(?:\[([a-zA-Z0-9_\-]+)\])?(?:\s*:\s*(.*))?",
            re.IGNORECASE,
        )

        unreachable_symbols_set = set()
        if self.project_index and getattr(self.project_index, "unreachable_symbols", None):
            unreachable_symbols_set = {
                f"{s.file_path}::{s.name}" for s in self.project_index.unreachable_symbols
            }

        for f in findings:
            # Set root cause cluster
            if not f.root_cause_cluster:
                f.root_cause_cluster = f"{f.rule_id or 'GENERAL'}::{f.file_path or 'ROOT'}"

            # Downgrade reachability if defect is in an unreachable symbol
            if f.file_path and f.line_number and unreachable_symbols_set and self.project_index:
                for sym in getattr(self.project_index, "unreachable_symbols", []):
                    if sym.file_path == f.file_path and sym.line_number <= f.line_number <= sym.end_line_number:
                        f.reachability = "unreachable"
                        f.evidence_level = "static-only"
                        break

            # Adjust exposure if inside test or docs
            if f.file_path:
                parts = [p.lower() for p in Path(f.file_path).parts]
                if any(p in ("tests", "test", "fixtures", "fixture", "mocks", "mock") for p in parts):
                    f.exposure = "test_fixture"

            # Parse inline suppression comments
            if f.file_path and f.line_number:
                if f.file_path not in file_lines_cache:
                    try:
                        fp = self.repo_dir / f.file_path
                        if fp.is_file():
                            file_lines_cache[f.file_path] = fp.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
                        else:
                            file_lines_cache[f.file_path] = []
                    except Exception:
                        file_lines_cache[f.file_path] = []

                lines_in_file = file_lines_cache[f.file_path]
                ln = f.line_number
                candidates = []
                if 1 <= ln <= len(lines_in_file):
                    candidates.append(lines_in_file[ln - 1])
                if ln > 1 and (ln - 1) <= len(lines_in_file):
                    candidates.append(lines_in_file[ln - 2])

                for cand in candidates:
                    m = suppression_regex.search(cand)
                    if m:
                        rule_target = m.group(1)
                        reason_target = m.group(2)
                        if not rule_target or (f.rule_id and rule_target.upper() == f.rule_id.upper()):
                            f.suppressed = True
                            f.suppression_reason = (
                                reason_target.strip()
                                if reason_target
                                else "Suppressed via inline comment directive"
                            )
                            break

            # Update priority score dynamically with final reachability and exposure
            from offtest.core.models import compute_priority
            f.priority_score = compute_priority(
                f.severity,
                f.confidence,
                reachability=f.reachability,
                exposure=f.exposure,
            )

        return findings

    def _check_python_syntax(self, rel_path: str, content: str, counter: int, branch: Optional[str]):
        f_sha = self.file_hashes.get(rel_path)
        try:
            tree = ast.parse(content, filename=rel_path)
            return None, tree
        except SyntaxError as se:
            finding = make_finding(
                RULES["OT-COR-001"],
                path=rel_path,
                line=se.lineno,
                file_sha256=f_sha,
                branch=branch,
                evidence=f"SyntaxError on line {se.lineno}: {se.text.strip() if se.text else se.msg}",
                override_title=f"Python Syntax Error: {se.msg}",
                confidence=Confidence.CONFIRMED,
            )
            return finding, None
        except (RecursionError, MemoryError) as re:
            finding = make_finding(
                RULES["OT-COR-001"],
                path=rel_path,
                line=1,
                file_sha256=f_sha,
                branch=branch,
                evidence=f"Parser resource exhaustion: {type(re).__name__}",
                override_title="AST Parsing Error: Pathological nesting or resource limit exceeded",
                confidence=Confidence.CONFIRMED,
            )
            return finding, None

    def _check_python_security_ast(self, rel_path: str, tree: ast.AST, counter_start: int, branch: Optional[str]) -> List[Finding]:
        findings = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)
        self_checker = self

        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self):
                self.aliases: Dict[str, str] = {}
                self.findings: List[Finding] = []

            def visit_Import(self, node: ast.Import):
                for alias in node.names:
                    name = alias.name
                    asname = alias.asname or name
                    self.aliases[asname] = name
                self.generic_visit(node)

            def visit_ImportFrom(self, node: ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    full = f"{mod}.{alias.name}" if mod else alias.name
                    asname = alias.asname or alias.name
                    self.aliases[asname] = full
                self.generic_visit(node)

            def _resolve_func_name(self, func_node: ast.AST) -> str:
                if isinstance(func_node, ast.Name):
                    return self.aliases.get(func_node.id, func_node.id)
                elif isinstance(func_node, ast.Attribute):
                    val_name = self._resolve_func_name(func_node.value)
                    return f"{val_name}.{func_node.attr}" if val_name else func_node.attr
                return ""

            def _check_auth_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr.lower() == "get":
                        if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                            route_path = dec.args[0].value.lower()
                            if any(k in route_path for k in ["login", "token", "signin", "authenticate"]):
                                arg_names = [a.arg.lower() for a in node.args.args]
                                has_pwd = any(c in arg_names for c in ["password", "secret", "passwd", "pwd"])
                                dec_line = getattr(dec, "lineno", node.lineno)
                                if has_pwd:
                                    self.findings.append(
                                        make_finding(
                                            RULES["OT-SEC-011"],
                                            path=rel_path,
                                            line=dec_line,
                                            file_sha256=f_sha,
                                            branch=branch,
                                            evidence=f"Line {dec_line} (handler '{node.name}'): @app.get('{dec.args[0].value}') accepts sensitive parameters: [{', '.join(arg_names)}]",
                                            override_title="Insecure Authentication Endpoint Defined via HTTP GET",
                                        )
                                    )
                                else:
                                    self.findings.append(
                                        make_finding(
                                            RULES["OT-HYG-008"],
                                            path=rel_path,
                                            line=dec_line,
                                            file_sha256=f_sha,
                                            branch=branch,
                                            evidence=f"Line {dec_line} (handler '{node.name}'): @app.get('{dec.args[0].value}') defines authentication route without sensitive parameter exposure.",
                                            override_title="HTTP GET Route Used for Authentication View",
                                        )
                                    )

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self._check_auth_route(node)
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                self._check_auth_route(node)
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call):
                func_name = self._resolve_func_name(node.func)

                # 1. eval / exec
                if func_name in ("eval", "exec") or (isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec")):
                    raw_id = func_name if func_name in ("eval", "exec") else node.func.id
                    is_const = node.args and isinstance(node.args[0], ast.Constant)
                    if is_const:
                        self.findings.append(
                            make_finding(
                                RULES["OT-HYG-007"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: {raw_id}(...) with static constant argument",
                                override_title=f"Static Constant Evaluated via '{raw_id}()'",
                            )
                        )
                    else:
                        self.findings.append(
                            make_finding(
                                RULES["OT-SEC-001"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: {raw_id}(...)",
                                override_title=f"Use of dangerous built-in '{raw_id}()'",
                            )
                        )

                # 2. os.system
                elif func_name == "os.system" or (isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", None) == "os" and node.func.attr == "system"):
                    is_dynamic = False
                    if node.args and not isinstance(node.args[0], ast.Constant):
                        is_dynamic = True
                    if is_dynamic:
                        self.findings.append(
                            make_finding(
                                RULES["OT-SEC-002"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: os.system(...)",
                                override_title="Dynamic Command Execution via os.system()",
                            )
                        )
                    else:
                        self.findings.append(
                            make_finding(
                                RULES["OT-HYG-006"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: os.system(...) with constant string",
                                override_title="Direct Shell Execution Present ('os.system()')",
                            )
                        )

                # 3. subprocess with shell=True
                elif func_name.startswith("subprocess.") or func_name in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"):
                    has_shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                    if has_shell_true:
                        self.findings.append(
                            make_finding(
                                RULES["OT-SEC-003"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: {func_name}(..., shell=True)",
                                override_title="Subprocess Executed with shell=True",
                            )
                        )

                # 4. yaml.load without SafeLoader
                elif func_name == "yaml.load" or (isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", None) == "yaml" and node.func.attr == "load"):
                    safe_loader = False
                    # Check positional Loader argument (e.g. yaml.load(stream, yaml.SafeLoader))
                    if len(node.args) >= 2:
                        arg1 = node.args[1]
                        arg1_name = arg1.id if isinstance(arg1, ast.Name) else (arg1.attr if isinstance(arg1, ast.Attribute) else "")
                        if any(s in arg1_name.lower() for s in ["safe", "base", "csafe"]):
                            safe_loader = True
                    for kw in node.keywords:
                        if kw.arg == "Loader":
                            loader_name = kw.value.id if isinstance(kw.value, ast.Name) else (kw.value.attr if isinstance(kw.value, ast.Attribute) else "")
                            if any(s in loader_name.lower() for s in ["safe", "base", "csafe"]):
                                safe_loader = True
                    if not safe_loader:
                        self.findings.append(
                            make_finding(
                                RULES["OT-SEC-004"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: yaml.load(...)",
                                override_title="Unsafe YAML Deserialization ('yaml.load' without SafeLoader)",
                            )
                        )

                # 5. pickle.loads / pickle.load
                elif func_name in ("pickle.load", "pickle.loads") or (isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", None) == "pickle" and node.func.attr in ("load", "loads")):
                    attr_name = node.func.attr if isinstance(node.func, ast.Attribute) else func_name.split(".")[-1]
                    is_fixture = self_checker.is_fixture_or_test(rel_path)
                    self.findings.append(
                        make_finding(
                            RULES["OT-SEC-005"],
                            path=rel_path,
                            line=node.lineno,
                            file_sha256=f_sha,
                            branch=branch,
                            severity=Severity.LOW if is_fixture else Severity.MEDIUM,
                            confidence=Confidence.POSSIBLE,
                            evidence=f"Line {node.lineno}: pickle.{attr_name}(...)",
                            override_title="Insecure Object Deserialization ('pickle.loads')",
                        )
                    )

                # 6. verify=False in requests / httpx / session
                elif any(func_name.startswith(p) for p in ["requests.", "httpx.", "session.", "client.", "http."]) and func_name.split(".")[-1] in ("get", "post", "put", "delete", "request", "head", "patch"):
                    for kw in node.keywords:
                        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            is_fixture = self_checker.is_fixture_or_test(rel_path)
                            self.findings.append(
                                make_finding(
                                    RULES["OT-SEC-006"],
                                    path=rel_path,
                                    line=node.lineno,
                                    file_sha256=f_sha,
                                    branch=branch,
                                    severity=Severity.MEDIUM if is_fixture else Severity.HIGH,
                                    confidence=Confidence.POSSIBLE if is_fixture else Confidence.LIKELY,
                                    evidence=f"Line {node.lineno}: {func_name}(..., verify=False)",
                                    override_title="Disabled SSL Certificate Verification (verify=False)",
                                )
                            )

                # 7. ssl._create_unverified_context
                elif func_name == "ssl._create_unverified_context" or (isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", None) == "ssl" and node.func.attr == "_create_unverified_context"):
                    self.findings.append(
                        make_finding(
                            RULES["OT-SEC-006"],
                            path=rel_path,
                            line=node.lineno,
                            file_sha256=f_sha,
                            branch=branch,
                            evidence=f"Line {node.lineno}: ssl._create_unverified_context()",
                            override_title="Disabled SSL Certificate Verification (ssl._create_unverified_context)",
                        )
                    )

                # 8. Archive extraction (Zip-Slip)
                elif func_name.endswith(".extractall") or (isinstance(node.func, ast.Attribute) and node.func.attr == "extractall"):
                    has_safe_filter = False
                    for kw in node.keywords:
                        if kw.arg == "filter" and isinstance(kw.value, ast.Constant) and kw.value.value in ("data", "tar"):
                            has_safe_filter = True
                    if not has_safe_filter:
                        self.findings.append(
                            make_finding(
                                RULES["OT-SEC-007"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: extractall(...) without safe extraction filter",
                                override_title="Arbitrary File Extraction via Archive (Zip Slip)",
                            )
                        )

                # 9. SQL Injection via string formatting
                elif (isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany")) or func_name.endswith((".execute", ".executemany")):
                    if node.args:
                        arg0 = node.args[0]
                        is_formatted = False
                        if isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Mod):
                            is_formatted = True
                        elif isinstance(arg0, ast.JoinedStr):
                            is_formatted = True
                        elif isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Attribute) and arg0.func.attr == "format":
                            is_formatted = True
                        if is_formatted:
                            self.findings.append(
                                make_finding(
                                    RULES["OT-SEC-008"],
                                    path=rel_path,
                                    line=node.lineno,
                                    file_sha256=f_sha,
                                    branch=branch,
                                    evidence=f"Line {node.lineno}: database query constructed via string formatting",
                                    override_title="SQL Query Constructed via String Formatting",
                                )
                            )

                # 10. tempfile.mktemp
                elif func_name == "tempfile.mktemp" or (isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", None) == "tempfile" and node.func.attr == "mktemp"):
                    self.findings.append(
                        make_finding(
                            RULES["OT-SEC-009"],
                            path=rel_path,
                            line=node.lineno,
                            file_sha256=f_sha,
                            branch=branch,
                            evidence=f"Line {node.lineno}: tempfile.mktemp()",
                            override_title="Insecure Temporary File Creation ('tempfile.mktemp')",
                        )
                    )

                # 11. Weak hashes: hashlib.md5 / hashlib.sha1
                elif func_name in ("hashlib.md5", "hashlib.sha1"):
                    used_for_sec = True
                    for kw in node.keywords:
                        if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            used_for_sec = False
                    if used_for_sec:
                        self.findings.append(
                            make_finding(
                                RULES["OT-SEC-010"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: {func_name}()",
                                override_title="Use of Broken or Weak Cryptographic Hash ('md5' / 'sha1')",
                            )
                        )

                # 12. app.run(debug=True)
                elif func_name.endswith(".run") or (isinstance(node.func, ast.Attribute) and node.func.attr == "run"):
                    for kw in node.keywords:
                        if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self.findings.append(
                                make_finding(
                                    RULES["OT-HYG-005"],
                                    path=rel_path,
                                    line=node.lineno,
                                    file_sha256=f_sha,
                                    branch=branch,
                                    evidence=f"Line {node.lineno}: {func_name}(..., debug=True)",
                                    override_title="Debug Mode Left Active ('DEBUG = True')",
                                )
                            )

                # Check CERT_NONE in any function call keyword
                for kw in node.keywords:
                    if kw.arg in ("cert_reqs", "verify_mode"):
                        if isinstance(kw.value, ast.Attribute) and kw.value.attr == "CERT_NONE":
                            self.findings.append(
                                make_finding(
                                    RULES["OT-SEC-006"],
                                    path=rel_path,
                                    line=node.lineno,
                                    file_sha256=f_sha,
                                    branch=branch,
                                    evidence=f"Line {node.lineno}: {kw.arg}=ssl.CERT_NONE",
                                    override_title="Disabled SSL Certificate Verification (CERT_NONE)",
                                )
                            )

                self.generic_visit(node)

            def visit_Assign(self, node: ast.Assign):
                # Check DEBUG = True
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEBUG":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            self.findings.append(
                                make_finding(
                                    RULES["OT-HYG-005"],
                                    path=rel_path,
                                    line=node.lineno,
                                    file_sha256=f_sha,
                                    branch=branch,
                                    evidence=f"Line {node.lineno}: DEBUG = True",
                                    override_title="Debug Mode Left Active ('DEBUG = True')",
                                )
                            )
                self.generic_visit(node)

            def visit_AnnAssign(self, node: ast.AnnAssign):
                # Check DEBUG: bool = True
                if isinstance(node.target, ast.Name) and node.target.id == "DEBUG":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        self.findings.append(
                            make_finding(
                                RULES["OT-HYG-005"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: DEBUG: ... = True",
                                override_title="Debug Mode Left Active ('DEBUG = True')",
                            )
                        )
                self.generic_visit(node)

        visitor = SecurityVisitor()
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings

    def _check_python_dead_code(self, rel_path: str, tree: ast.AST, counter_start: int, branch: Optional[str]) -> List[Finding]:
        """
        Detects unused imports and unreachable statements (dead code) via AST walk.
        Findings are LOW severity / LIKELY confidence — no CVSS score attached.
        """
        findings: List[Finding] = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)

        # Check if this file is __init__.py (re-exports are standard)
        is_init_py = Path(rel_path).name == "__init__.py"

        # --- 1. Unused top-level imports ---
        import_names: Dict[str, int] = {}  # name -> line_number

        if not is_init_py:
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        bound_name = alias.asname if alias.asname else alias.name.split(".")[0]
                        import_names[bound_name] = node.lineno
                elif isinstance(node, ast.ImportFrom):
                    # Skip compiler directives (__future__ imports e.g. annotations)
                    if node.module == "__future__":
                        continue
                    for alias in node.names:
                        if alias.name == "*":
                            continue  # star import — can't track
                        bound_name = alias.asname if alias.asname else alias.name
                        import_names[bound_name] = node.lineno

            # Collect all Name loads in the module body
            used_names: Set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    used_names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    root = node
                    while isinstance(root, ast.Attribute):
                        root = root.value
                    if isinstance(root, ast.Name):
                        used_names.add(root.id)

            # Collect names in __all__ definitions
            for stmt in getattr(tree, "body", []):
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == "__all__":
                            if isinstance(stmt.value, (ast.List, ast.Tuple, ast.Set)):
                                for elt in stmt.value.elts:
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                        used_names.add(elt.value)

            unused_imports = [name for name, line_no in import_names.items() if name not in used_names and name != "_"]
            if unused_imports:
                first_line = import_names[unused_imports[0]]
                title = f"Unused Import: '{unused_imports[0]}'" if len(unused_imports) == 1 else f"Unused Imports ({len(unused_imports)} symbols in {Path(rel_path).name})"
                findings.append(
                    make_finding(
                        RULES["OT-HYG-001"],
                        path=rel_path,
                        line=first_line,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {first_line}: Unused import(s): {', '.join(sorted(unused_imports))}",
                        override_title=title,
                    )
                )
                c += 1

        # --- 2. Unreachable statements after return/raise/break/continue ---
        terminal_nodes = (ast.Return, ast.Raise, ast.Break, ast.Continue)

        def check_block_for_unreachable(stmts: List[ast.stmt], parent_lineno: int) -> None:
            nonlocal c
            for i, stmt in enumerate(stmts):
                if isinstance(stmt, terminal_nodes):
                    unreachable = stmts[i + 1:]
                    for dead_stmt in unreachable:
                        if isinstance(dead_stmt, (ast.Pass,)):
                            continue  # `pass` after return is trivial
                        dead_line = getattr(dead_stmt, "lineno", parent_lineno)
                        findings.append(
                            make_finding(
                                RULES["OT-HYG-003"],
                                path=rel_path,
                                line=dead_line,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {dead_line}: statement follows a {type(stmt).__name__} at line {stmt.lineno}.",
                                override_title="Unreachable Statement After Control Flow Terminator",
                            )
                        )
                        c += 1
                    break  # stop processing this block further

        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if body and isinstance(body, list):
                check_block_for_unreachable(body, getattr(node, "lineno", 1))
            orelse = getattr(node, "orelse", None)
            if orelse and isinstance(orelse, list):
                check_block_for_unreachable(orelse, getattr(node, "lineno", 1))
            handlers = getattr(node, "handlers", None)
            if handlers:
                for handler in handlers:
                    if hasattr(handler, "body"):
                        check_block_for_unreachable(handler.body, handler.lineno)
            finalbody = getattr(node, "finalbody", None)
            if finalbody and isinstance(finalbody, list):
                check_block_for_unreachable(finalbody, getattr(node, "lineno", 1))

        return findings

    def _get_requirements_nesting_depth(self, current_file: str, target_arg: str, visited: set) -> int:
        clean_target = target_arg.split()[0].strip().strip("'\"")
        parent_dir = Path(current_file).parent
        target_path = (self.repo_dir / parent_dir / clean_target).resolve()
        norm_key = str(target_path)
        if norm_key in visited:
            return 999  # Cycle detected
        visited.add(norm_key)

        if not target_path.is_file():
            return 1

        try:
            content = target_path.read_text(encoding="utf-8-sig", errors="ignore")
        except Exception:
            return 1

        max_sub = 0
        for line in content.splitlines():
            line_str = line.strip()
            if line_str.startswith(("-r", "--requirement")):
                sub_arg = line_str.split(maxsplit=1)[1].strip() if len(line_str.split()) > 1 else ""
                if sub_arg:
                    sub_d = self._get_requirements_nesting_depth(str(parent_dir / clean_target), sub_arg, visited.copy())
                    if sub_d > max_sub:
                        max_sub = sub_d
        return 1 + max_sub

    def _check_requirements(self, rel_path: str, content: str, counter_start: int, branch: Optional[str]) -> List[Finding]:
        findings = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)
        lines = content.splitlines()
        unpinned_items = []

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check for remote package indexes (--index-url, --extra-index-url, --find-links, -i, -f)
            index_patterns = [
                re.compile(r"""(?:--index-url|--extra-index-url|-i)\s+(['"]?(?:https?://|//)[^\s'"]+)""", re.IGNORECASE),
                re.compile(r"""(?:--find-links|-f)\s+(['"]?(?:https?://|//)[^\s'"]+)""", re.IGNORECASE),
            ]
            found_remote_index = False
            for ipat in index_patterns:
                m = ipat.search(stripped)
                if m:
                    idx_target = m.group(1).strip("'\"")
                    if not any(local in idx_target for local in ["127.0.0.1", "localhost"]):
                        findings.append(
                            make_finding(
                                RULES["OT-POL-001"],
                                path=rel_path,
                                line=idx,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {idx}: {stripped}",
                                override_title="Remote Package Index or Registry Reference in Dependency File",
                            )
                        )
                        c += 1
                        found_remote_index = True
                        break

            if found_remote_index:
                continue

            # Check for nested -r depth limit
            if stripped.startswith(("-r", "--requirement")):
                nested_target = stripped.split(maxsplit=1)[1].strip() if len(stripped.split()) > 1 else ""
                if nested_target:
                    depth = self._get_requirements_nesting_depth(rel_path, nested_target, visited=set())
                    if depth > 5:
                        findings.append(
                            make_finding(
                                RULES["OT-SUP-003"],
                                path=rel_path,
                                line=idx,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {idx}: {stripped} (chain depth: {depth})",
                                override_title="Excessive Recursion Depth in Requirements Inclusion (-r)",
                            )
                        )
                        c += 1

            # Check for remote UNC or Network references in requirements.txt (e.g. -r \\host\x, -e \\host\x, file://)
            from offtest.intake.intake import is_unc_or_remote_path
            target_arg = stripped
            if stripped.startswith(("-r", "-e")):
                target_arg = stripped[2:].strip()
            if is_unc_or_remote_path(target_arg):
                findings.append(
                    make_finding(
                        RULES["OT-POL-002"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: {stripped}",
                        override_title="Remote UNC or Network Reference in Dependency Specification",
                    )
                )
                c += 1
                continue

            # Check for unpinned dependencies (e.g. 'requests' or 'flask>=2.0' without exact pin '==')
            if "==" not in stripped and "@" not in stripped and not stripped.startswith("-"):
                unpinned_items.append((idx, stripped))

        # Aggregate unpinned dependencies per file to prevent report flooding
        if unpinned_items:
            first_idx, first_raw = unpinned_items[0]
            pkg_list = [raw.split(">=")[0].split("<=")[0].split("~=")[0].split(">")[0].split("<")[0].strip() for _, raw in unpinned_items]
            ev = "; ".join(f"L{i}: {r}" for i, r in unpinned_items[:6])
            if len(unpinned_items) > 6:
                ev += f"; ... and {len(unpinned_items) - 6} more"
            title = f"Unpinned Python Dependency: '{pkg_list[0]}'" if len(unpinned_items) == 1 else f"Unpinned Python Dependencies ({len(unpinned_items)} unpinned packages in {Path(rel_path).name})"
            findings.append(
                make_finding(
                    RULES["OT-SUP-001"],
                    path=rel_path,
                    line=first_idx,
                    file_sha256=f_sha,
                    branch=branch,
                    evidence=f"Unpinned package specifications: {ev}",
                    override_title=title,
                )
            )
            c += 1

        return findings

    def _check_gitmodules(self, rel_path: str, content: str, counter_start: int, branch: Optional[str]) -> List[Finding]:
        findings = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("url"):
                parts = stripped.split("=", 1)
                if len(parts) == 2:
                    url = parts[1].strip().strip("'\"")
                    if url.startswith(("http://", "https://", "git://", "ssh://", "git@")) or "://" in url:
                        findings.append(
                            make_finding(
                                RULES["OT-POL-004"],
                                path=rel_path,
                                line=idx,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {idx}: {stripped}",
                                override_title="Remote Submodule URL in .gitmodules",
                            )
                        )
                        c += 1
        return findings

    def _check_cargo_toml(self, rel_path: str, content: str, counter_start: int, branch: Optional[str]) -> List[Finding]:
        import os
        findings = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            # Remote git dependency
            git_m = re.search(r"""git\s*=\s*['"]([^'"]+)['"]""", stripped)
            if git_m:
                findings.append(
                    make_finding(
                        RULES["OT-POL-002"],
                        path=rel_path,
                        line=idx,
                        file_sha256=f_sha,
                        branch=branch,
                        evidence=f"Line {idx}: {stripped}",
                        override_title="Remote Git Dependency in Cargo.toml",
                    )
                )
                c += 1

            # Escaping path dependency
            path_m = re.search(r"""path\s*=\s*['"]([^'"]+)['"]""", stripped)
            if path_m:
                local_p = path_m.group(1)
                parent_dir = Path(rel_path).parent.as_posix()
                lexical_p = os.path.normpath(os.path.join(parent_dir, local_p)).replace("\\", "/")
                if lexical_p.startswith("..") or lexical_p.startswith("/") or ":" in lexical_p:
                    findings.append(
                        make_finding(
                            RULES["OT-POL-002"],
                            path=rel_path,
                            line=idx,
                            file_sha256=f_sha,
                            branch=branch,
                            evidence=f"Line {idx}: {stripped}",
                            override_title="Escaping Path Dependency in Cargo.toml",
                        )
                    )
                    c += 1
        return findings

    def _check_pyproject_or_setup_cfg(self, rel_path: str, content: str, counter_start: int, branch: Optional[str]) -> List[Finding]:
        findings = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)
        current_section = ""
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                current_section = stripped.strip("[]").strip().lower()
                continue

            # Skip metadata/documentation sections like [project.urls], [tool.poetry.urls], [metadata]
            if any(sec in current_section for sec in ["project.urls", "tool.poetry.urls", "metadata", "project.scripts"]):
                continue

            # Skip metadata key-value assignments
            line_lower = stripped.lower()
            if any(line_lower.startswith(k) for k in ["repository =", "homepage =", "documentation =", "issues =", "changelog =", "url ="]):
                continue

            if any(proto in stripped for proto in ["git+http://", "git+https://", "git+ssh://", "https://", "http://"]):
                is_dep_section = any(sec in current_section for sec in ["dependencies", "requires", "tool.poetry.dependencies", "tool.poetry.dev-dependencies"])
                has_dep_indicator = any(dep_k in line_lower for dep_k in ["dependencies", "requires", "@", "find-links", "index-url"])
                if is_dep_section or has_dep_indicator:
                    findings.append(
                        make_finding(
                            RULES["OT-POL-002"],
                            path=rel_path,
                            line=idx,
                            file_sha256=f_sha,
                            branch=branch,
                            evidence=f"Line {idx}: {stripped}",
                            override_title="Remote VCS or Network Dependency in Python Manifest",
                        )
                    )
                    c += 1
        return findings

    def _check_registry_config(self, rel_path: str, content: str, counter_start: int, branch: Optional[str]) -> List[Finding]:
        findings = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith(";"):
                continue
            reg_m = re.search(r"""(?:registry|index-url|extra-index-url)\s*=\s*(['"]?https?://[^\s'"]+)""", stripped, re.IGNORECASE)
            if reg_m:
                url = reg_m.group(1).strip("'\"")
                if not any(loc in url for loc in ["127.0.0.1", "localhost"]):
                    findings.append(
                        make_finding(
                            RULES["OT-POL-003"],
                            path=rel_path,
                            line=idx,
                            file_sha256=f_sha,
                            branch=branch,
                            evidence=f"Line {idx}: {stripped}",
                            override_title=f"External Package Registry Configured in {Path(rel_path).name}",
                        )
                    )
                    c += 1
        return findings

    def _check_package_json(self, rel_path: str, content: str, counter_start: int, branch: Optional[str]) -> List[Finding]:
        import json
        findings = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)
        try:
            data = json.loads(content)
        except Exception:
            return findings

        has_lockfile = any(
            Path(f.path).name.lower() in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
            for f in self.files
        )

        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for pkg, ver in deps.items():
            try:
                ver_str = str(ver).strip()
                from offtest.intake.intake import is_unc_or_remote_path
                if is_unc_or_remote_path(ver_str) or ver_str.startswith(("git://", "git+http", "git+ssh", "http://", "https://")):
                    findings.append(
                        make_finding(
                            RULES["OT-POL-002"],
                            path=rel_path,
                            line=None,
                            file_sha256=f_sha,
                            branch=branch,
                            evidence=f"\"{pkg}\": \"{ver_str}\"",
                            override_title=f"Remote Network or UNC Dependency Reference in package.json: '{pkg}'",
                        )
                    )
                    c += 1
                elif ver_str.startswith("^") or ver_str.startswith("~") or ver_str == "*" or ver_str == "latest":
                    if not has_lockfile:
                        findings.append(
                            make_finding(
                                RULES["OT-SUP-002"],
                                path=rel_path,
                                line=None,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"\"{pkg}\": \"{ver_str}\"",
                                override_title=f"Floating Node.js Dependency: '{pkg}'",
                            )
                        )
                        c += 1
            except Exception:
                continue
        return findings

    def _check_python_semantic_bugs(self, rel_path: str, tree: ast.AST, counter_start: int, branch: Optional[str]) -> List[Finding]:
        findings: List[Finding] = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)

        import builtins
        builtins_set = set(dir(builtins)) | {
            "__name__", "__file__", "__doc__", "__all__", "__path__", "__package__",
            "__spec__", "True", "False", "None", "self", "cls"
        }

        # 1. Collect top-level globals and imports
        global_names: Set[str] = set()
        for stmt in getattr(tree, "body", []):
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    global_names.add(bound)
            elif isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    if alias.name != "*":
                        bound = alias.asname or alias.name
                        global_names.add(bound)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                global_names.add(stmt.name)
            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    for n in ast.walk(target):
                        if isinstance(n, ast.Name):
                            global_names.add(n.id)
            elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                target = stmt.target
                if isinstance(target, ast.Name):
                    global_names.add(target.id)

        # 2. Scope-based undefined name checker and zero division / constant conditions
        class BugVisitor(ast.NodeVisitor):
            def __init__(self):
                self.scope_stack: List[Set[str]] = []

            def visit_BinOp(self, node: ast.BinOp):
                nonlocal c
                if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                    is_zero = False
                    ev = ""
                    if isinstance(node.right, ast.Constant) and node.right.value == 0:
                        is_zero = True
                        ev = f"Line {node.lineno}: division by literal zero ('{ast.unparse(node)}')"
                    elif isinstance(node.right, ast.BinOp) and isinstance(node.right.op, ast.Sub):
                        try:
                            l_str = ast.unparse(node.right.left).strip()
                            r_str = ast.unparse(node.right.right).strip()
                            if l_str == r_str and l_str:
                                is_zero = True
                                ev = f"Line {node.lineno}: division by expression '{l_str} - {r_str}' which evaluates identically to zero ('{ast.unparse(node)}')"
                        except Exception:
                            pass
                    if is_zero:
                        findings.append(
                            make_finding(
                                RULES["OT-COR-003"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=ev,
                                override_title="Division by Zero Detected in Binary Operation",
                            )
                        )
                        c += 1
                self.generic_visit(node)

            def visit_If(self, node: ast.If):
                nonlocal c
                if isinstance(node.test, ast.Constant):
                    val = node.test.value
                    if val in (False, 0, "", None, [], {}):
                        findings.append(
                            make_finding(
                                RULES["OT-COR-004"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: 'if {ast.unparse(node.test)}:' is permanently false.",
                                override_title=f"Unreachable Code: Constant False Condition ('if {val}:')",
                            )
                        )
                        c += 1
                    elif val in (True, 1) and node.orelse:
                        findings.append(
                            make_finding(
                                RULES["OT-COR-004"],
                                path=rel_path,
                                line=node.lineno,
                                file_sha256=f_sha,
                                branch=branch,
                                evidence=f"Line {node.lineno}: 'if {ast.unparse(node.test)}:' has an unreachable else block.",
                                override_title="Unreachable Else Block: Constant True Condition ('if True:')",
                            )
                        )
                        c += 1
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self._check_func(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                self._check_func(node)

            def _check_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
                nonlocal c
                local_vars: Set[str] = set()
                for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                    local_vars.add(arg.arg)
                if node.args.vararg:
                    local_vars.add(node.args.vararg.arg)
                if node.args.kwarg:
                    local_vars.add(node.args.kwarg.arg)

                for stmt in node.body:
                    for n in ast.walk(stmt):
                        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                            local_vars.add(n.id)
                        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            local_vars.add(n.name)

                self.scope_stack.append(local_vars)

                for stmt in node.body:
                    for n in ast.walk(stmt):
                        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                            name_id = n.id
                            in_scope = any(name_id in scope for scope in self.scope_stack)
                            if not in_scope and name_id not in global_names and name_id not in builtins_set:
                                findings.append(
                                    make_finding(
                                        RULES["OT-COR-002"],
                                        path=rel_path,
                                        line=n.lineno,
                                        file_sha256=f_sha,
                                        branch=branch,
                                        evidence=f"Line {n.lineno}: '{name_id}' loaded in function '{node.name}' is undefined.",
                                        override_title=f"Undefined Name: '{name_id}' Used in Function '{node.name}'",
                                    )
                                )
                                c += 1
                self.generic_visit(node)
                self.scope_stack.pop()

        visitor = BugVisitor()
        visitor.visit(tree)
        return findings

    def _check_project_uncalled_code(
        self,
        branch: Optional[str],
        counter_start: int,
        existing_findings: Optional[List[Finding]] = None,
    ) -> List[Finding]:
        """
        Reports uncalled functions, classes, and no-op stubs discovered via project-wide call graph.
        Consolidates internal defects located within uncalled functions into a single finding to minimize noise.
        """
        findings: List[Finding] = []
        c = counter_start

        if not hasattr(self, "project_index") or self.project_index is None:
            return findings

        def _severity_rank(sev: Severity) -> int:
            ranks = {
                Severity.CRITICAL: 5,
                Severity.HIGH: 4,
                Severity.MEDIUM: 3,
                Severity.LOW: 2,
                Severity.INFORMATIONAL: 1,
            }
            return ranks.get(sev, 0)

        # 1. Unreachable functions and classes from call graph
        for sym in self.project_index.unreachable_symbols:
            f_sha = self.file_hashes.get(sym.file_path)
            conf = Confidence.CONFIRMED if sym.is_private else Confidence.LIKELY
            if sym.name in self.project_index.dynamic_names or sym.name in self.project_index.exported_names:
                conf = Confidence.POSSIBLE

            # Check if existing findings fall inside this uncalled symbol
            internal_findings: List[Finding] = []
            if existing_findings:
                to_remove = []
                for ef in existing_findings:
                    if (
                        ef.file_path == sym.file_path
                        and ef.line_number is not None
                        and sym.line_number <= ef.line_number <= sym.end_line_number
                    ):
                        internal_findings.append(ef)
                        to_remove.append(ef)
                for rem in to_remove:
                    existing_findings.remove(rem)

            defect_labels: List[str] = []
            for ef in internal_findings:
                st = ef.title
                if "Division by Zero" in st:
                    defect_labels.append("Division by Zero")
                elif "Undefined Name" in st:
                    defect_labels.append(st)
                elif "Constant False" in st:
                    defect_labels.append("Constant False Condition ('if False:')")
                elif "Unreachable Statement" in st:
                    defect_labels.append("Unreachable Statement After Return")
                else:
                    defect_labels.append(st)

            if sym.is_noop:
                defect_labels.append(f"No-Op Function: '{sym.name}()'")
            if sym.raises_not_implemented:
                defect_labels.append(f"Unimplemented Function Stub: '{sym.name}()' Always Raises NotImplementedError")

            if defect_labels or internal_findings:
                top_defect = (
                    max(internal_findings, key=lambda f: _severity_rank(f.severity))
                    if internal_findings
                    else None
                )
                title_defect = "; ".join(defect_labels)
                finding_title = f"Uncalled Dead Code: {sym.symbol_type.capitalize()} '{sym.name}' Is Never Called ({title_defect})"
                impact_str = (
                    f"{sym.symbol_type.capitalize()} '{sym.name}' defined at line {sym.line_number} is unreachable from any application entry point or test (dead code)."
                )
                if internal_findings:
                    impact_str += " In addition, it contains internal defect(s): " + " ".join(f.impact for f in internal_findings)
                elif sym.is_noop:
                    impact_str += f" Function executes no operational logic ({sym.noop_reason})."
                elif sym.raises_not_implemented:
                    impact_str += " Function unconditionally raises NotImplementedError."

                evidence_str = (
                    f"{sym.file_path}:{sym.line_number}: {sym.symbol_type} '{sym.name}' has 0 incoming call references in the project call graph."
                )
                if internal_findings:
                    evidence_str += " Internal defects: " + "; ".join(f.evidence for f in internal_findings)
                elif sym.noop_reason:
                    evidence_str += f" {sym.noop_reason}"

                sev = top_defect.severity if top_defect else (Severity.MEDIUM if sym.raises_not_implemented else Severity.LOW)
                cwe_id = top_defect.cwe_id if top_defect else "CWE-561"
                cwe_name = top_defect.cwe_name if top_defect else "Dead Code"
                cvss_score = top_defect.cvss_score_estimate if top_defect else None
                cvss_vector = top_defect.cvss_vector_estimate if top_defect else None
                cvss_is_est = top_defect.cvss_is_estimate if top_defect else False

                findings.append(
                    Finding(
                        id=f"FIND-{c:04d}",
                        rule_id="OT-HYG-003",
                        category=FindingCategory.HYGIENE,
                        title=finding_title,
                        severity=sev,
                        confidence=Confidence.CONFIRMED if any(f.confidence == Confidence.CONFIRMED for f in internal_findings) else conf,
                        provenance="symbolic",
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=sym.file_path,
                        line_number=sym.line_number,
                        file_sha256=f_sha,
                        impact=impact_str,
                        evidence=evidence_str,
                        suggested_action="Remove uncalled code or repair internal defects before wiring into active application workflows.",
                        check_tool="project-callgraph-analyzer",
                        cwe_id=cwe_id,
                        cwe_name=cwe_name,
                        cvss_score_estimate=cvss_score,
                        cvss_vector_estimate=cvss_vector,
                        cvss_is_estimate=cvss_is_est,
                        environmental_context_assumed="Cross-file call graph reachability analysis from entry points (routes, CLI, __main__, tests).",
                        oracle_origin="symbolic_invariant",
                        reproduced=True,
                        sandbox_artifact=False,
                    )
                )
                c += 1
            else:
                findings.append(
                    Finding(
                        id=f"FIND-{c:04d}",
                        rule_id="OT-HYG-003",
                        category=FindingCategory.HYGIENE,
                        title=f"Uncalled Dead Code: {sym.symbol_type.capitalize()} '{sym.name}' Is Never Called",
                        severity=Severity.LOW,
                        confidence=conf,
                        provenance="symbolic",
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=sym.file_path,
                        line_number=sym.line_number,
                        file_sha256=f_sha,
                        impact=f"{sym.symbol_type.capitalize()} '{sym.name}' defined at line {sym.line_number} is unreachable from any application entry point or test.",
                        evidence=f"{sym.file_path}:{sym.line_number}: {sym.symbol_type} '{sym.name}' has 0 incoming call references in the project call graph.",
                        suggested_action="Remove uncalled code or wire it into an active application workflow.",
                        check_tool="project-callgraph-analyzer",
                        cwe_id="CWE-561",
                        cwe_name="Dead Code",
                        cvss_score_estimate=None,
                        cvss_vector_estimate=None,
                        cvss_is_estimate=False,
                        environmental_context_assumed="Cross-file call graph reachability analysis from entry points (routes, CLI, __main__, tests).",
                        oracle_origin="symbolic_invariant",
                        reproduced=True,
                        sandbox_artifact=False,
                    )
                )
                c += 1

        # 2. No-op functions and NotImplemented stubs for reachable symbols
        unreachable_keys = {f"{s.file_path}::{s.name}" for s in self.project_index.unreachable_symbols}
        for sym in self.project_index.symbols.values():
            if "test" in sym.file_path.lower():
                continue
            key = f"{sym.file_path}::{sym.name}"
            if key in unreachable_keys:
                continue
            f_sha = self.file_hashes.get(sym.file_path)
            if sym.is_noop:
                findings.append(
                    Finding(
                        id=f"FIND-{c:04d}",
                        rule_id="OT-HYG-002",
                        category=FindingCategory.HYGIENE,
                        title=f"No-Op Function: '{sym.name}()' Has Empty Body",
                        severity=Severity.LOW,
                        confidence=Confidence.LIKELY,
                        provenance="symbolic",
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=sym.file_path,
                        line_number=sym.line_number,
                        file_sha256=f_sha,
                        impact=f"Function '{sym.name}()' executes no operational logic ({sym.noop_reason}).",
                        evidence=f"{sym.file_path}:{sym.line_number}: {sym.noop_reason}",
                        suggested_action="Implement functional logic or remove no-op function stub.",
                        check_tool="python-semantic-analyzer",
                        cwe_id="CWE-561",
                        cwe_name="Dead Code",
                        cvss_score_estimate=None,
                        cvss_vector_estimate=None,
                        cvss_is_estimate=False,
                        oracle_origin="symbolic_invariant",
                        reproduced=True,
                        sandbox_artifact=False,
                    )
                )
                c += 1
            elif sym.raises_not_implemented:
                findings.append(
                    Finding(
                        id=f"FIND-{c:04d}",
                        rule_id="OT-HYG-002",
                        category=FindingCategory.HYGIENE,
                        title=f"Unimplemented Function Stub: '{sym.name}()' Always Raises NotImplementedError",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LIKELY,
                        provenance="symbolic",
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=sym.file_path,
                        line_number=sym.line_number,
                        file_sha256=f_sha,
                        impact=f"Invoking '{sym.name}()' immediately terminates with NotImplementedError.",
                        evidence=f"{sym.file_path}:{sym.line_number}: function body unconditionally raises NotImplementedError.",
                        suggested_action="Provide concrete implementation for function.",
                        check_tool="python-semantic-analyzer",
                        cwe_id="CWE-561",
                        cwe_name="Dead Code",
                        cvss_score_estimate=None,
                        cvss_vector_estimate=None,
                        cvss_is_estimate=False,
                        oracle_origin="symbolic_invariant",
                        reproduced=True,
                        sandbox_artifact=False,
                    )
                )
                c += 1

        return findings
