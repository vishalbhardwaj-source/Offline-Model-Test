"""tests/test_multi_language_adapters.py

Test suite validating multi-language adapter architecture (TypeScript, React, Java, Spring Boot, Python)
as specified in 'Offline Testing Model: TypeScript, React, Python and Java Support' (Oct 30, 2026 @Ankit):
1. Adapter interface and per-language coverage reporting (symbols, call graph, reachability, routes & auth, taint & rules, test synthesis).
2. Heuristic reachability constraint: non-Python heuristic reachability and Spring beans can ONLY produce 'unknown', never 'unreachable'.
3. React rules: dangerouslySetInnerHTML, javascript: URLs, localStorage tokens, browser env secrets (REACT_APP_, VITE_, NEXT_PUBLIC_), eval/new Function.
4. Java and Spring rules: SQL string concat (JDBC/JPA), ObjectInputStream deserialization, XXE in XML parsers, missing method-level security on controllers, permissive CSRF/CORS, hardcoded credentials in application.properties/yml.
5. Node and Express rules: NoSQL injection, child_process execution, missing helmet in Express.
6. Auth detection: Express middleware, NestJS guards, Spring Security filter chains & @PreAuthorize; React route wrappers flagged as UX only; 'no auth visible in code' / 'auth status unknown'.
7. Java SBOM gap: pom.xml without offline resolved dependency tree or Gradle lockfile reported as 'incomplete', not clean.
8. Generated bundles: skipping dist, build, target, .next, .gradle and reporting skipped counts.
9. Non-Python findings capped at 'static-only' evidence level.
"""
import tempfile
from pathlib import Path
from offtest.adapters.java_adapter import JavaAdapter
from offtest.adapters.python_adapter import PythonAdapter
from offtest.adapters.registry import get_adapter_for_language, get_all_adapters, get_all_coverages
from offtest.adapters.typescript_adapter import TypeScriptAdapter
from offtest.checks.planner import CheckPlanner
from offtest.checks.static_checks import OfflineStaticChecker
from offtest.core.models import FeatureDepth, FileDisposition, FileRecord, Severity
from offtest.core.project_index import ProjectIndex
from offtest.inventory.classifier import classify_file
from offtest.inventory.sbom import SBOMGenerator
from offtest.orchestrator import AssessmentOrchestrator
from offtest.reports.detailed import DetailedReportGenerator


def test_adapter_coverage_declarations():
    """Verify that Python, TypeScript/React, and Java declare explicit FeatureDepth coverage."""
    coverages = get_all_coverages()
    assert "python" in coverages
    assert "typescript" in coverages
    assert "java" in coverages

    # Python has full semantic depth + pytest test synthesis
    py_cov = coverages["python"]
    assert py_cov.symbols == FeatureDepth.SEMANTIC
    assert py_cov.reachability == FeatureDepth.SEMANTIC
    assert py_cov.test_synthesis == FeatureDepth.SEMANTIC

    # TypeScript / React declares heuristic symbols/rules, heuristic reachability, none test synthesis
    ts_cov = coverages["typescript"]
    assert ts_cov.symbols == FeatureDepth.HEURISTIC
    assert ts_cov.reachability == FeatureDepth.HEURISTIC
    assert ts_cov.test_synthesis == FeatureDepth.NONE

    # Java / Spring declares heuristic symbols/rules, heuristic reachability, none test synthesis
    java_cov = coverages["java"]
    assert java_cov.symbols == FeatureDepth.HEURISTIC
    assert java_cov.reachability == FeatureDepth.HEURISTIC
    assert java_cov.test_synthesis == FeatureDepth.NONE


def test_react_and_typescript_rules_and_roots():
    """Verify React-specific security rules, entry roots, and static-only evidence capping."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        # 1. React App entry and component
        react_comp = root / "App.tsx"
        react_comp.write_text("""
import React, { useEffect } from 'react';

export const UserProfile = ({ userBio, redirectUrl }: any) => {
    // OT-SEC-021: dangerouslySetInnerHTML
    const markup = { __html: userBio };

    // OT-SEC-023: localStorage auth token
    useEffect(() => {
        localStorage.setItem('auth_token', 'xyz-jwt-token');
    }, []);

    // OT-SEC-024: Sensitive secret in REACT_APP_ variable
    const apiSecret = process.env.REACT_APP_API_SECRET;

    // OT-SEC-025: Client-side eval
    const computed = eval("2 + 2");

    return (
        <div>
            <div dangerouslySetInnerHTML={markup} />
            <a href="javascript:alert(1)">Click Me</a>
            <p>Secret: {apiSecret}</p>
        </div>
    );
};
export default UserProfile;
""", encoding="utf-8")

        files = [
            FileRecord(
                path="App.tsx",
                size_bytes=len(react_comp.read_text(encoding="utf-8")),
                sha256="hash_react_app",
                language="TypeScript (TSX)",
                category="source",
                disposition=FileDisposition.ANALYZED,
                disposition_reason="Supported language",
            )
        ]

        proj_index = ProjectIndex(root, files)
        checker = OfflineStaticChecker(root, files, project_index=proj_index)
        findings = checker.run_all()

        rule_ids = {f.rule_id for f in findings}
        # Check all 5 React-specific rules triggered
        assert "OT-SEC-021" in rule_ids  # dangerouslySetInnerHTML
        assert "OT-SEC-022" in rule_ids  # javascript: URL
        assert "OT-SEC-023" in rule_ids  # localStorage token
        assert "OT-SEC-024" in rule_ids  # REACT_APP_ secret
        assert "OT-SEC-025" in rule_ids  # eval / new Function

        # Ensure all non-Python findings are capped at static-only evidence level
        for f in findings:
            if f.rule_id in ("OT-SEC-021", "OT-SEC-022", "OT-SEC-023", "OT-SEC-024", "OT-SEC-025"):
                assert f.evidence_level == "static-only"

        # Ensure heuristic reachability produced unknown, never unreachable
        assert len(proj_index.unreachable_symbols) == 0


def test_node_and_express_rules():
    """Verify Node/Express rules: NoSQL injection, child_process, and missing helmet."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        server_js = root / "server.js"
        server_js.write_text("""
const express = require('express');
const child_process = require('child_process');
const app = express();

// Express route with command injection and NoSQL injection
app.post('/api/run', (req, res) => {
    const cmd = req.body.command;
    child_process.exec("ping " + cmd);
    db.collection('users').find({ $where: "this.name == '" + req.body.name + "'" });
    res.send('ok');
});

app.listen(3000, () => {
    console.log('Server listening');
});
""", encoding="utf-8")

        files = [
            FileRecord(
                path="server.js",
                size_bytes=len(server_js.read_text(encoding="utf-8")),
                sha256="hash_server_js",
                language="JavaScript",
                category="source",
                disposition=FileDisposition.ANALYZED,
                disposition_reason="Supported language",
            )
        ]

        proj_index = ProjectIndex(root, files)
        checker = OfflineStaticChecker(root, files, project_index=proj_index)
        findings = checker.run_all()

        rule_ids = {f.rule_id for f in findings}
        assert "OT-SEC-032" in rule_ids  # NoSQL injection ($where)
        assert "OT-SEC-033" in rule_ids  # child_process.exec with string concat
        assert "OT-SEC-034" in rule_ids  # Missing helmet in Express server
        assert "OT-SEC-012" in rule_ids  # Unauthenticated state-changing POST route


def test_java_and_spring_rules_and_beans():
    """Verify Java and Spring Boot rules: SQL injection, ObjectInputStream, XXE, method security, CSRF, and hardcoded credentials."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        # 1. Spring Controller with SQLi, ObjectInputStream, XXE, and missing method-level security
        controller_java = root / "OrderController.java"
        controller_java.write_text("""
package com.example.demo;

import org.springframework.web.bind.annotation.*;
import java.io.ObjectInputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import java.sql.Statement;

@RestController
@RequestMapping("/orders")
public class OrderController {

    private Statement statement;

    @PostMapping("/create")
    public String createOrder(@RequestParam String orderId, ObjectInputStream in) throws Exception {
        // OT-SEC-026: SQL built by string concat
        statement.executeQuery("SELECT * FROM orders WHERE id = '" + orderId + "'");
        
        // OT-SEC-027: Unsafe deserialization
        in.readObject();

        // OT-SEC-028: XXE without disallow-doctype-decl
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        return "created";
    }
}
""", encoding="utf-8")

        # 2. Spring Security configuration with CSRF disabled
        sec_config = root / "SecurityConfig.java"
        sec_config.write_text("""
package com.example.demo;

import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }
}
""", encoding="utf-8")

        # 3. application.properties with hardcoded credentials
        app_props = root / "application.properties"
        app_props.write_text("""
server.port=8080
spring.datasource.password=superSecretPassword123
spring.datasource.username=root
""", encoding="utf-8")

        files = [
            FileRecord(
                path="OrderController.java",
                size_bytes=len(controller_java.read_text(encoding="utf-8")),
                sha256="hash_order_ctrl",
                language="Java",
                category="source",
                disposition=FileDisposition.ANALYZED,
                disposition_reason="Supported language",
            ),
            FileRecord(
                path="SecurityConfig.java",
                size_bytes=len(sec_config.read_text(encoding="utf-8")),
                sha256="hash_sec_cfg",
                language="Java",
                category="source",
                disposition=FileDisposition.ANALYZED,
                disposition_reason="Supported language",
            ),
            FileRecord(
                path="application.properties",
                size_bytes=len(app_props.read_text(encoding="utf-8")),
                sha256="hash_app_props",
                language="Properties",
                category="config",
                disposition=FileDisposition.ANALYZED,
                disposition_reason="Supported language",
            ),
        ]

        proj_index = ProjectIndex(root, files)
        checker = OfflineStaticChecker(root, files, project_index=proj_index)
        findings = checker.run_all()

        rule_ids = {f.rule_id for f in findings}
        assert "OT-SEC-026" in rule_ids  # Java SQL injection via string concat
        assert "OT-SEC-027" in rule_ids  # ObjectInputStream deserialization
        assert "OT-SEC-028" in rule_ids  # XXE in XML parser
        assert "OT-SEC-029" in rule_ids  # Missing method-level security on @PostMapping
        assert "OT-SEC-030" in rule_ids  # CSRF disabled
        assert "OT-SEC-031" in rule_ids  # Hardcoded password in application.properties

        # Java reachability: unreferenced Spring beans must remain unknown, never unreachable
        assert len(proj_index.unreachable_symbols) == 0


def test_java_sbom_incomplete_handling():
    """Verify that pom.xml without offline resolved dependency tree reports SBOM as 'incomplete', not clean."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        pom_xml = root / "pom.xml"
        pom_xml.write_text("""<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>3.1.0</version>
    </dependency>
  </dependencies>
</project>""", encoding="utf-8")

        files = [
            FileRecord(
                path="pom.xml",
                size_bytes=len(pom_xml.read_text(encoding="utf-8")),
                sha256="hash_pom",
                language="XML",
                category="config",
                disposition=FileDisposition.ANALYZED,
                disposition_reason="Supported manifest",
            )
        ]

        # Case 1: Only pom.xml without offline resolved lockfile or tree -> INCOMPLETE
        generator = SBOMGenerator(root, files)
        sbom_report = generator.generate()
        assert sbom_report.total_dependencies == 1
        assert sbom_report.status == "incomplete"
        assert "pom.xml lists direct dependencies only" in (sbom_report.notes or "")

        # Case 2: When an offline resolved dependency tree is present -> COMPLETE
        tree_file = root / "dependency-tree.txt"
        tree_file.write_text("org.springframework.boot:spring-boot-starter-web:jar:3.1.0:compile\n", encoding="utf-8")
        files.append(
            FileRecord(
                path="dependency-tree.txt",
                size_bytes=len(tree_file.read_text(encoding="utf-8")),
                sha256="hash_tree",
                language="Plain Text",
                category="config",
                disposition=FileDisposition.ANALYZED,
                disposition_reason="Resolved dependency tree",
            )
        )
        gen2 = SBOMGenerator(root, files)
        sbom2 = gen2.generate()
        assert sbom2.status == "complete"


def test_generated_code_and_bundle_skipping():
    """Verify that dist, build, target, .next, and .gradle caches are skipped for static rules and counted."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        # Dist bundle with a planted secret pattern
        dist_dir = root / "dist"
        dist_dir.mkdir()
        bundle_file = dist_dir / "bundle.js"
        bundle_file.write_text("var secret = 'AKIA1234567890ABCDEF';", encoding="utf-8")

        files = [
            FileRecord(
                path="dist/bundle.js",
                size_bytes=len(bundle_file.read_text(encoding="utf-8")),
                sha256="hash_dist_bundle",
                language="JavaScript",
                category="source",
                disposition=FileDisposition.ANALYZED,
                disposition_reason="In build directory",
            )
        ]

        checker = OfflineStaticChecker(root, files)
        findings = checker.run_all()
        # Ensure static rules skipped the dist bundle
        assert len(findings) == 0
        assert checker.skipped_bundle_count == 1
