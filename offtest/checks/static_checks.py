import ast
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from offtest.core.models import (
    Confidence,
    EvidenceStatus,
    FileRecord,
    Finding,
    Severity,
)
from offtest.discovery.anchor_verifier import verify_source_anchor
from offtest.intake.safety import scan_for_secrets

# Curated deterministic rule-to-CWE mapping table with estimated CVSS baselines
RULE_CWE_CVSS_MAP: Dict[str, Tuple[str, str, float, str]] = {
    "Documented AWS Example Key": ("CWE-798", "Use of Hard-coded Credentials", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "AWS Access Key ID": ("CWE-798", "Use of Hard-coded Credentials", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "Hardcoded Secret": ("CWE-798", "Use of Hard-coded Credentials", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "High-Entropy Secret": ("CWE-798", "Use of Hard-coded Credentials", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Insecure Authentication Endpoint": ("CWE-598", "Use of GET Request Method With Sensitive Query Strings", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"),
    "eval": ("CWE-95", "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Command Execution": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "Command Injection": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "os.system": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "DEBUG = True": ("CWE-489", "Active Debug Code", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Unpinned Python Dependency": ("CWE-1357", "Reliance on Insufficiently Trustworthy Component", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    "Floating Node.js Dependency": ("CWE-1357", "Reliance on Insufficiently Trustworthy Component", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    "YAML Deserialization": ("CWE-502", "Deserialization of Untrusted Data", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Insecure Object Deserialization": ("CWE-502", "Deserialization of Untrusted Data", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SSL Certificate Verification": ("CWE-295", "Improper Certificate Validation", 7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
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
    for key, (cwe_id, cwe_name, cvss_score, cvss_vector) in RULE_CWE_CVSS_MAP.items():
        if key.lower() in title.lower():
            return cwe_id, cwe_name, cvss_score, cvss_vector
    return None, None, None, None


class OfflineStaticChecker:
    def __init__(self, repo_dir: Path, files: List[FileRecord]):
        self.repo_dir = repo_dir
        self.files = files
        self.file_hashes: Dict[str, str] = {f.path: f.sha256 for f in files if getattr(f, "sha256", None)}

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

            # 0. File encoding check (e.g. Windows UTF-8 BOM)
            if has_bom and f.language in ("Python", "JavaScript", "TypeScript", "JSON", "YAML"):
                findings.append(
                    Finding(
                        id=f"FIND-{counter:04d}",
                        title="Non-Standard UTF-8 BOM (Byte Order Mark) Detected",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        provenance="rule",
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=f.path,
                        line_number=1,
                        file_sha256=f_sha256,
                        impact="File begins with a UTF-8 Byte Order Mark (0xEF 0xBB 0xBF / U+FEFF). While standard Python runtimes strip the BOM automatically when running files from disk, strict CI linters, non-Windows compilers, or string-based AST parsers may flag or mishandle BOM characters.",
                        evidence="Line 1: File starts with 3-byte UTF-8 BOM sequence (0xEF 0xBB 0xBF)",
                        suggested_action="Re-save file as standard UTF-8 without BOM to ensure universal cross-platform and linter compatibility.",
                        check_tool="file-encoding-checker",
                        cwe_id=None,
                        cwe_name=None,
                        cvss_score_estimate=None,
                        cvss_vector_estimate=None,
                        cvss_is_estimate=False,
                        environmental_context_assumed="Assumes standard source repository formatting expectations.",
                        oracle_origin="static_rule",
                        reproduced=True,
                        sandbox_artifact=False,
                    )
                )
                counter += 1

            # 1. Hardcoded secrets check
            secret_hits = scan_for_secrets(content, f.path)
            for line_no, label, preview, fingerprint in secret_hits:
                severity = Severity.CRITICAL
                title = f"{label} Detected"
                
                if "Example Key" in label:
                    severity = Severity.INFORMATIONAL
                    title = "Documented AWS Example Key (AKIA...EXAMPLE) Detected"
                    impact = "Token matches public sample/example AWS Access Key ID from documentation (e.g. AWS SDK documentation). Low operational risk, but recommended to remove before production."
                    suggested_action = "Remove documentation sample key and configure credentials via local environment variables."
                elif "AWS" in label:
                    impact = "Detected non-example token matching AWS credential structure (prefix 'AKIA'). High risk of AWS cloud credential exposure if repository is shared."
                    suggested_action = "Rotate AWS credentials immediately via AWS IAM and move secrets to local environment variables."
                elif "Entropy" in label:
                    impact = "Detected high-entropy string exceeding randomness threshold. High likelihood of custom API key, token, or secret."
                    suggested_action = "Rotate token and move credentials to local environment variables or an offline secret store."
                else:
                    impact = "High risk of credential exposure if repository is shared or breached."
                    suggested_action = "Rotate credentials immediately and move secrets to local environment variables or an offline vault."

                evidence_str = f"Line {line_no} [detector: {label}, fingerprint: {fingerprint}]: {preview}"
                conf, is_sandbox = classify_defect_confidence(evidence_str, oracle_origin="static_rule", reproduced=True)
                cwe_id, cwe_name, cvss_score, cvss_vector = resolve_cwe_cvss(title)

                findings.append(
                    Finding(
                        id=f"FIND-{counter:04d}",
                        title=title,
                        severity=severity,
                        confidence=conf,
                        provenance="rule",
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=f.path,
                        line_number=line_no,
                        file_sha256=f_sha256,
                        impact=impact,
                        evidence=evidence_str,
                        suggested_action=suggested_action,
                        check_tool="offtest-secret-scanner",
                        cwe_id=cwe_id,
                        cwe_name=cwe_name,
                        cvss_score_estimate=cvss_score,
                        cvss_vector_estimate=cvss_vector,
                        cvss_is_estimate=True,
                        environmental_context_assumed="Assumes standard exposure; static scan cannot evaluate live environmental firewall/auth controls.",
                        oracle_origin="static_rule",
                        reproduced=True,
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

            # 3. Dependency configuration analysis
            if f.path.endswith("requirements.txt"):
                dep_findings = self._check_requirements(f.path, content, counter, branch)
                for item in dep_findings:
                    findings.append(item)
                    counter += 1

            elif f.path.endswith("package.json"):
                pkg_findings = self._check_package_json(f.path, content, counter, branch)
                for item in pkg_findings:
                    findings.append(item)
                    counter += 1

        return findings

    def _check_python_syntax(self, rel_path: str, content: str, counter: int, branch: Optional[str]):
        f_sha = self.file_hashes.get(rel_path)
        try:
            tree = ast.parse(content, filename=rel_path)
            return None, tree
        except SyntaxError as se:
            finding = Finding(
                id=f"FIND-{counter:04d}",
                title=f"Python Syntax Error: {se.msg}",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                provenance="rule",
                status=EvidenceStatus.OBSERVED,
                branch=branch,
                file_path=rel_path,
                line_number=se.lineno,
                file_sha256=f_sha,
                impact="Code fails to compile or execute in Python runtime (code-quality defect).",
                evidence=f"SyntaxError on line {se.lineno}: {se.text.strip() if se.text else se.msg}",
                suggested_action="Fix syntax error to ensure valid Python execution.",
                check_tool="python-ast-validator",
                cwe_id=None,
                cwe_name=None,
                cvss_score_estimate=None,
                cvss_vector_estimate=None,
                cvss_is_estimate=False,
                oracle_origin="static_rule",
                reproduced=True,
                sandbox_artifact=False,
            )
            return finding, None
        except (RecursionError, MemoryError) as re:
            finding = Finding(
                id=f"FIND-{counter:04d}",
                title="AST Parsing Error: Pathological nesting or resource limit exceeded",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                provenance="rule",
                status=EvidenceStatus.OBSERVED,
                branch=branch,
                file_path=rel_path,
                line_number=1,
                file_sha256=f_sha,
                impact="File contains pathological nesting or excessive token complexity that triggers parser memory/recursion limits (code-quality defect).",
                evidence=f"Parser resource exhaustion: {type(re).__name__}",
                suggested_action="Refactor code structure to reduce excessive expression or block nesting.",
                check_tool="python-ast-validator",
                cwe_id=None,
                cwe_name=None,
                cvss_score_estimate=None,
                cvss_vector_estimate=None,
                cvss_is_estimate=False,
                oracle_origin="static_rule",
                reproduced=True,
                sandbox_artifact=False,
            )
            return finding, None

    def _check_python_security_ast(self, rel_path: str, tree: ast.AST, counter_start: int, branch: Optional[str]) -> List[Finding]:
        findings = []
        c = counter_start

        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self):
                self.issues = []

            def visit_FunctionDef(self, node: ast.FunctionDef):
                # Check decorators for GET method with auth/login route
                for dec in node.decorator_list:
                    # e.g. @app.get("/api/v1/auth/login")
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr.lower() == "get":
                        if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                            route_path = dec.args[0].value.lower()
                            if any(k in route_path for k in ["login", "token", "signin", "authenticate"]):
                                arg_names = [a.arg.lower() for a in node.args.args]
                                has_pwd = any(c in arg_names for c in ["password", "secret", "passwd", "pwd"])
                                if has_pwd:
                                    conf = Confidence.HIGH
                                    trigger = f"GET query parameters accept sensitive arguments: [{', '.join(arg_names)}]"
                                else:
                                    conf = Confidence.MEDIUM
                                    trigger = f"Route-name heuristic matched authentication path '{dec.args[0].value}' on HTTP GET (handler arguments: [{', '.join(arg_names) or 'none'}]; no explicit password parameter detected)"
                                dec_line = getattr(dec, "lineno", node.lineno)
                                self.issues.append((
                                    dec_line,
                                    "Insecure Authentication Endpoint Defined via HTTP GET",
                                    Severity.HIGH,
                                    conf,
                                    "Authentication, login, and token issuance endpoints must not use HTTP GET. Query parameters in GET requests are persisted in plain text within web server access logs, browser history, and HTTP Referer headers.",
                                    f"Line {dec_line} (handler '{node.name}' at line {node.lineno}): @app.get('{dec.args[0].value}') uses HTTP GET for an authentication route. Trigger: {trigger}.",
                                    "Change the HTTP route method from GET to POST and accept credentials/payload within the request body."
                                ))
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call):
                # Check eval() / exec()
                if isinstance(node.func, ast.Name):
                    if node.func.id in ("eval", "exec"):
                        self.issues.append((
                            node.lineno,
                            f"Use of dangerous built-in '{node.func.id}()'",
                            Severity.HIGH,
                            Confidence.HIGH,
                            f"Direct execution of dynamic strings via {node.func.id}() can lead to remote code execution.",
                            f"Line {node.lineno}: {node.func.id}(...)",
                            f"Refactor to avoid {node.func.id}() using safe static data parsing (e.g. ast.literal_eval, json.loads)."
                        ))
                    elif node.func.id == "open":
                        pass

                # Check os.system(...)
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id == "os" and node.func.attr == "system":
                            is_dynamic = False
                            if node.args:
                                arg0 = node.args[0]
                                if not isinstance(arg0, ast.Constant):
                                    is_dynamic = True
                            if is_dynamic:
                                self.issues.append((
                                    node.lineno,
                                    "Dynamic Command Execution via os.system()",
                                    Severity.HIGH,
                                    Confidence.LIKELY,
                                    "os.system executes shell commands with dynamic parameters without escaping, creating high risk of command injection if arguments incorporate external input (taint is unverified statically).",
                                    f"Line {node.lineno}: os.system(...)",
                                    "Replace os.system() with subprocess.run(..., shell=False) passing command arguments as a list."
                                ))
                            else:
                                self.issues.append((
                                    node.lineno,
                                    "Direct Shell Execution Present ('os.system()')",
                                    Severity.INFORMATIONAL,
                                    Confidence.POSSIBLE,
                                    "Advisory observation: Process spawns an OS shell with fixed constant arguments. Not a defect or command injection; informational observation only.",
                                    f"Line {node.lineno}: os.system(...)",
                                    "Consider replacing os.system() with subprocess.run(..., shell=False) passing arguments as a list."
                                ))
                        # Check yaml.load without SafeLoader
                        elif node.func.value.id == "yaml" and node.func.attr == "load":
                            safe_loader = False
                            for kw in node.keywords:
                                if kw.arg == "Loader":
                                    loader_name = ""
                                    if isinstance(kw.value, ast.Name):
                                        loader_name = kw.value.id
                                    elif isinstance(kw.value, ast.Attribute):
                                        loader_name = kw.value.attr
                                    if "safe" in loader_name.lower():
                                        safe_loader = True
                            if not safe_loader:
                                self.issues.append((
                                    node.lineno,
                                    "Unsafe YAML Deserialization ('yaml.load' without SafeLoader)",
                                    Severity.HIGH,
                                    Confidence.POSSIBLE,
                                    "Calling yaml.load() without SafeLoader allows arbitrary Python object instantiation (AST rule match; exploitability unconfirmed).",
                                    f"Line {node.lineno}: yaml.load(...)",
                                    "Use yaml.safe_load(...) or specify Loader=yaml.SafeLoader."
                                ))
                        # Check pickle.loads
                        elif node.func.value.id == "pickle" and node.func.attr in ("load", "loads"):
                            is_fixture = any(t in rel_path.lower() for t in ["test", "fixture", "mock"])
                            self.issues.append((
                                node.lineno,
                                "Insecure Object Deserialization ('pickle.loads')",
                                Severity.LOW if is_fixture else Severity.MEDIUM,
                                Confidence.POSSIBLE,
                                "Pickle deserialization AST call detected. Rule match on call syntax; exploitability depends on whether external untrusted data reaches the call.",
                                f"Line {node.lineno}: pickle.{node.func.attr}(...)",
                                "Use safer serialization formats like JSON or Protocol Buffers for untrusted payloads."
                            ))
                        # Check verify=False in requests
                        elif node.func.value.id == "requests" and node.func.attr in ("get", "post", "put", "delete", "request"):
                            for kw in node.keywords:
                                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                                    is_fixture = any(t in rel_path.lower() for t in ["test", "fixture", "mock"])
                                    conf = Confidence.POSSIBLE if is_fixture else Confidence.LIKELY
                                    self.issues.append((
                                        node.lineno,
                                        "Disabled SSL Certificate Verification (verify=False)",
                                        Severity.MEDIUM if is_fixture else Severity.HIGH,
                                        conf,
                                        "Disabling SSL verification allows man-in-the-middle attacks.",
                                        f"Line {node.lineno}: requests.{node.func.attr}(..., verify=False)",
                                        "Remove verify=False and ensure valid local CA certificates are provided."
                                    ))
                        # Check ssl._create_unverified_context
                        elif node.func.value.id == "ssl" and node.func.attr == "_create_unverified_context":
                            self.issues.append((
                                node.lineno,
                                "Disabled SSL Certificate Verification (ssl._create_unverified_context)",
                                Severity.HIGH,
                                Confidence.LIKELY,
                                "Creating unverified SSL context disables server certificate validation.",
                                f"Line {node.lineno}: ssl._create_unverified_context()",
                                "Use ssl.create_default_context() with trusted certificates."
                            ))

                # Check CERT_NONE in any function call keyword
                for kw in node.keywords:
                    if kw.arg in ("cert_reqs", "verify_mode"):
                        if isinstance(kw.value, ast.Attribute) and kw.value.attr == "CERT_NONE":
                            self.issues.append((
                                node.lineno,
                                "Disabled SSL Certificate Verification (CERT_NONE)",
                                Severity.HIGH,
                                Confidence.LIKELY,
                                "Setting SSL verify_mode to CERT_NONE bypasses certificate checks.",
                                f"Line {node.lineno}: {kw.arg}=ssl.CERT_NONE",
                                "Require valid certificates (ssl.CERT_REQUIRED)."
                            ))

                self.generic_visit(node)

            def visit_Assign(self, node: ast.Assign):
                # Check DEBUG = True
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEBUG":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            self.issues.append((
                                node.lineno,
                                "Debug Mode Left Active ('DEBUG = True')",
                                Severity.MEDIUM,
                                Confidence.HIGH,
                                "Debug mode reveals sensitive stack traces, environment details, and internal state.",
                                f"Line {node.lineno}: DEBUG = True",
                                "Set DEBUG = False or load dynamically from non-production configuration."
                            ))
                self.generic_visit(node)

        visitor = SecurityVisitor()
        visitor.visit(tree)

        f_sha = self.file_hashes.get(rel_path)
        for line_no, title, sev, conf, impact, ev, action in visitor.issues:
            cwe_id, cwe_name, cvss_score, cvss_vector = resolve_cwe_cvss(title)
            # Principle: CVSS base estimates MUST NOT be attached to unverified / Possible findings
            if conf == Confidence.POSSIBLE:
                cvss_score = None
                cvss_vector = None
            findings.append(
                Finding(
                    id=f"FIND-{c:04d}",
                    title=title,
                    severity=sev,
                    confidence=conf,
                    provenance="symbolic",
                    status=EvidenceStatus.OBSERVED,
                    branch=branch,
                    file_path=rel_path,
                    line_number=line_no,
                    file_sha256=f_sha,
                    impact=impact,
                    evidence=ev,
                    suggested_action=action,
                    check_tool="python-ast-security-checker",
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    cvss_score_estimate=cvss_score,
                    cvss_vector_estimate=cvss_vector,
                    cvss_is_estimate=True,
                    environmental_context_assumed="Assumes standard network exposure; offline static analysis cannot determine local firewall/VPC boundary or runtime auth middleware without environmental configuration.",
                    oracle_origin="symbolic_invariant",
                    reproduced=True,
                    sandbox_artifact=False,
                )
            )
            c += 1

        return findings

    def _check_requirements(self, rel_path: str, content: str, counter_start: int, branch: Optional[str]) -> List[Finding]:
        findings = []
        c = counter_start
        f_sha = self.file_hashes.get(rel_path)
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check for remote UNC or Network references in requirements.txt (e.g. -r \\host\x, -e \\host\x, file://)
            from offtest.intake.intake import is_unc_or_remote_path
            target_arg = stripped
            if stripped.startswith(("-r", "-e")):
                target_arg = stripped[2:].strip()
            if is_unc_or_remote_path(target_arg):
                findings.append(
                    Finding(
                        id=f"FIND-{c:04d}",
                        title="Remote UNC or Network Reference in Dependency Specification",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        provenance="rule",
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=rel_path,
                        line_number=idx,
                        file_sha256=f_sha,
                        impact="Dependency file specifies a remote UNC, SMB, or external network target. Installing or resolving this requirement can trigger an outbound connection or NTLM credential leak.",
                        evidence=f"Line {idx}: {stripped}",
                        suggested_action="Remove remote network reference and vendor dependency locally inside the repository.",
                        check_tool="dependency-pin-checker",
                        cwe_id="CWE-829",
                        cwe_name="Inclusion of Functionality from Untrusted Control Sphere",
                        cvss_score_estimate=7.5,
                        cvss_vector_estimate="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cvss_is_estimate=True,
                        environmental_context_assumed="Assumes strict offline air-gap build requirements.",
                        oracle_origin="static_rule",
                        reproduced=True,
                        sandbox_artifact=False,
                    )
                )
                c += 1
                continue

            # Check for unpinned dependencies (e.g. 'requests' or 'flask>=2.0' without exact pin '==')
            if "==" not in stripped and "@" not in stripped and not stripped.startswith("-"):
                is_min_constraint = any(op in stripped for op in [">=", "<=", "~=", ">", "<"])
                title = "Minimum Version Constraint (Unpinned Python Dependency)" if is_min_constraint else "Unpinned Python Dependency"
                impact = (
                    f"Dependency specifies a minimum or range constraint ('{stripped}') rather than an exact pinned version ('=='). While standard during local development, unpinned builds can pull unexpected upstream changes and cause non-deterministic offline environments."
                    if is_min_constraint else
                    "Unpinned dependencies without version constraints can introduce breaking changes or untracked upstream supply-chain differences when running offline."
                )
                pkg_base = stripped.split(">=")[0].split("<=")[0].split("~=")[0].split(">")[0].split("<")[0].strip()
                suggested_action = (
                    f"Pin exact version in requirements.txt (e.g. {pkg_base}==x.y.z) for deterministic offline builds."
                )
                cwe_id, cwe_name, cvss_score, cvss_vector = resolve_cwe_cvss("Unpinned Python Dependency")
                findings.append(
                    Finding(
                        id=f"FIND-{c:04d}",
                        title=title,
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        provenance="rule",
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=rel_path,
                        line_number=idx,
                        file_sha256=f_sha,
                        impact=impact,
                        evidence=f"Line {idx}: {stripped}",
                        suggested_action=suggested_action,
                        check_tool="dependency-pin-checker",
                        cwe_id=cwe_id,
                        cwe_name=cwe_name,
                        cvss_score_estimate=cvss_score,
                        cvss_vector_estimate=cvss_vector,
                        cvss_is_estimate=True,
                        oracle_origin="static_rule",
                        reproduced=True,
                        sandbox_artifact=False,
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
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg, ver in deps.items():
                if ver.startswith("^") or ver.startswith("~") or ver == "*" or ver == "latest":
                    cwe_id, cwe_name, cvss_score, cvss_vector = resolve_cwe_cvss("Floating Node.js Dependency")
                    findings.append(
                        Finding(
                            id=f"FIND-{c:04d}",
                            title=f"Floating Node.js Dependency: '{pkg}'",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            provenance="rule",
                            status=EvidenceStatus.OBSERVED,
                            branch=branch,
                            file_path=rel_path,
                            line_number=None,
                            file_sha256=f_sha,
                            impact="Floating dependency range requires network resolution unless exact package-lock.json is committed.",
                            evidence=f"\"{pkg}\": \"{ver}\"",
                            suggested_action=f"Pin exact version or ensure package-lock.json / offline cache is provided.",
                            check_tool="npm-package-pin-checker",
                            cwe_id=cwe_id,
                            cwe_name=cwe_name,
                            cvss_score_estimate=cvss_score,
                            cvss_vector_estimate=cvss_vector,
                            cvss_is_estimate=True,
                            oracle_origin="static_rule",
                            reproduced=True,
                            sandbox_artifact=False,
                        )
                    )
                    c += 1
        except Exception:
            pass
        return findings
