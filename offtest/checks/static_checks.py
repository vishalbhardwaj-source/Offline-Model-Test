import ast
import re
from pathlib import Path
from typing import List, Optional
from offtest.core.models import (
    Confidence,
    EvidenceStatus,
    FileRecord,
    Finding,
    Severity,
)
from offtest.intake.safety import scan_for_secrets


class OfflineStaticChecker:
    def __init__(self, repo_dir: Path, files: List[FileRecord]):
        self.repo_dir = repo_dir
        self.files = files

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
                content = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

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

                findings.append(
                    Finding(
                        id=f"FIND-{counter:04d}",
                        title=title,
                        severity=severity,
                        confidence=Confidence.HIGH,
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=f.path,
                        line_number=line_no,
                        impact=impact,
                        evidence=f"Line {line_no} [detector: {label}, fingerprint: {fingerprint}]: {preview}",
                        suggested_action=suggested_action,
                        check_tool="offtest-secret-scanner",
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
        try:
            tree = ast.parse(content, filename=rel_path)
            return None, tree
        except SyntaxError as se:
            finding = Finding(
                id=f"FIND-{counter:04d}",
                title=f"Python Syntax Error: {se.msg}",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=EvidenceStatus.OBSERVED,
                branch=branch,
                file_path=rel_path,
                line_number=se.lineno,
                impact="Code fails to compile or execute in Python runtime.",
                evidence=f"SyntaxError on line {se.lineno}: {se.text.strip() if se.text else se.msg}",
                suggested_action="Fix syntax error to ensure valid Python execution.",
                check_tool="python-ast-validator",
            )
            return finding, None
        except (RecursionError, MemoryError) as re:
            finding = Finding(
                id=f"FIND-{counter:04d}",
                title="AST Parsing Error: Pathological nesting or resource limit exceeded",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=EvidenceStatus.OBSERVED,
                branch=branch,
                file_path=rel_path,
                line_number=1,
                impact="File contains pathological nesting or excessive token complexity that triggers parser memory/recursion limits.",
                evidence=f"Parser resource exhaustion: {type(re).__name__}",
                suggested_action="Refactor code structure to reduce excessive expression or block nesting.",
                check_tool="python-ast-validator",
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
                            self.issues.append((
                                node.lineno,
                                "Insecure Process Execution with 'os.system()'",
                                Severity.HIGH,
                                Confidence.HIGH,
                                "os.system executes shell commands without argument escaping, risking command injection.",
                                f"Line {node.lineno}: os.system(...)",
                                "Replace os.system() with subprocess.run(..., shell=False) passing command arguments as a list."
                            ))
                        # Check yaml.load without SafeLoader
                        elif node.func.value.id == "yaml" and node.func.attr == "load":
                            has_loader = False
                            for kw in node.keywords:
                                if kw.arg == "Loader":
                                    has_loader = True
                            if not has_loader:
                                self.issues.append((
                                    node.lineno,
                                    "Unsafe YAML Deserialization ('yaml.load' without SafeLoader)",
                                    Severity.HIGH,
                                    Confidence.HIGH,
                                    "Calling yaml.load() without explicit SafeLoader can allow arbitrary Python object instantiations.",
                                    f"Line {node.lineno}: yaml.load(...)",
                                    "Use yaml.safe_load(...) instead."
                                ))
                        # Check pickle.loads
                        elif node.func.value.id == "pickle" and node.func.attr in ("load", "loads"):
                            self.issues.append((
                                node.lineno,
                                "Insecure Object Deserialization ('pickle.loads')",
                                Severity.MEDIUM,
                                Confidence.MEDIUM,
                                "Pickle deserialization of untrusted payloads enables arbitrary code execution.",
                                f"Line {node.lineno}: pickle.{node.func.attr}(...)",
                                "Use safer serialization formats like JSON or Protocol Buffers for untrusted data."
                            ))
                        # Check verify=False in requests
                        elif node.func.value.id == "requests" and node.func.attr in ("get", "post", "put", "delete", "request"):
                            for kw in node.keywords:
                                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                                    self.issues.append((
                                        node.lineno,
                                        "Disabled SSL Certificate Verification (verify=False)",
                                        Severity.HIGH,
                                        Confidence.HIGH,
                                        "Disabling SSL verification allows man-in-the-middle attacks.",
                                        f"Line {node.lineno}: requests.{node.func.attr}(..., verify=False)",
                                        "Remove verify=False and ensure valid local CA certificates are provided."
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

        for line_no, title, sev, conf, impact, ev, action in visitor.issues:
            findings.append(
                Finding(
                    id=f"FIND-{c:04d}",
                    title=title,
                    severity=sev,
                    confidence=conf,
                    status=EvidenceStatus.OBSERVED,
                    branch=branch,
                    file_path=rel_path,
                    line_number=line_no,
                    impact=impact,
                    evidence=ev,
                    suggested_action=action,
                    check_tool="python-ast-security-checker",
                )
            )
            c += 1

        return findings

    def _check_requirements(self, rel_path: str, content: str, counter_start: int, branch: Optional[str]) -> List[Finding]:
        findings = []
        c = counter_start
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Check for unpinned dependencies (e.g. 'requests' or 'flask>=2.0' without exact pin '==')
            if "==" not in stripped and "@" not in stripped and not stripped.startswith("-"):
                findings.append(
                    Finding(
                        id=f"FIND-{c:04d}",
                        title="Unpinned Python Dependency",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        status=EvidenceStatus.OBSERVED,
                        branch=branch,
                        file_path=rel_path,
                        line_number=idx,
                        impact="Unpinned dependencies can introduce breaking changes or untracked upstream supply-chain differences when running offline.",
                        evidence=f"Line {idx}: {stripped}",
                        suggested_action=f"Pin exact version in requirements.txt (e.g. {stripped.split('>')[0].split('<')[0]}==x.y.z) for deterministic offline builds.",
                        check_tool="dependency-pin-checker",
                    )
                )
                c += 1
        return findings

    def _check_package_json(self, rel_path: str, content: str, counter_start: int, branch: Optional[str]) -> List[Finding]:
        import json
        findings = []
        c = counter_start
        try:
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg, ver in deps.items():
                if ver.startswith("^") or ver.startswith("~") or ver == "*" or ver == "latest":
                    findings.append(
                        Finding(
                            id=f"FIND-{c:04d}",
                            title=f"Floating Node.js Dependency: '{pkg}'",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            status=EvidenceStatus.OBSERVED,
                            branch=branch,
                            file_path=rel_path,
                            line_number=None,
                            impact="Floating dependency range requires network resolution unless exact package-lock.json is committed.",
                            evidence=f"\"{pkg}\": \"{ver}\"",
                            suggested_action=f"Pin exact version or ensure package-lock.json / offline cache is provided.",
                            check_tool="npm-package-pin-checker",
                        )
                    )
                    c += 1
        except Exception:
            pass
        return findings
