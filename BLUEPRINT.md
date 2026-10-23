# Offline App and Website Testing Model — Master Blueprint & Specification

A comprehensive planning blueprint for an autonomous, fully air-gapped system that ingests a codebase and running application/website, maps every feature, workflow, and code branch, tests them, and produces verifiable reports.

---

## 1. Goal and Honest Scope Check

### Primary Goal
Build a testing system that operates **100% offline**, reads a target codebase alongside a running app or website, autonomously constructs a structural and behavioral model of all features, workflows, and code branches, generates and executes targeted tests, and produces two synchronized reports:
1. **Detailed Technical Report:** An exhaustive investigation record for engineering, QA, and security audit teams.
2. **Issues-Highlight Report:** An executive-level scorecard prioritizing verified defects, coverage gaps, and immediate remediation steps.

### Honest Scope & Theoretical Boundaries
No automated testing tool can guarantee finding every bug, exercising every code path, or fully comprehending undecidable logic (Halting Problem, Rice's Theorem). In complex applications:
- Certain code branches are unreachable under any runtime configuration (dead code or defensive programming).
- Some execution paths depend on dynamic runtime payloads, non-deterministic timers, external third-party integrations, or hardware state.
- Purely generative AI models hallucinate defects, invent phantom APIs, and produce uncompilable test scripts if left unconstrained.

**The Realistic Operational Target:**
The system must be built around **provable measurement and gap accounting**:
- **Measure what was covered** across 7 distinct dimensions (Statements, Branches, Conditions, Functions, Routes/APIs, Workflows, and Features).
- **Explicitly account for what was not covered**, publishing the exact reason for every gap (e.g., blocked by missing role credentials, dependency on unmocked external payment gateway, unreachable branch condition, or resource timeout).
- **Zero Hallucination Tolerance:** Deterministic tools (AST parsers, symbolic engines, dynamic instrumentation, coverage collectors) provide empirical ground truth; local AI models provide reasoning, test synthesis, and semantic interpretation. Every AI assertion must be verified by a deterministic compiler, execution trace, or runtime log before inclusion in reports.

---

## 2. Design Principles

1. **Offline by Construction:** Zero internet access at runtime. All runtimes, packages, container base images, browser binaries, security rule packs, and AI model weights are staged once, cryptographically hashed, and verified in an air-gapped environment. Outbound network sockets are physically or virtually blocked with default-deny firewall policies.
2. **Facts First, AI Second (Neuro-Symbolic Architecture):** Deterministic static analysis, symbolic execution, and instrumentation provide absolute ground truth. The local LLM interprets structure, devises complex multi-step user scenarios, and writes test scripts, but its outputs must pass strict AST parsing, compilation, and sandbox execution before being accepted.
3. **Multi-Dimensional Honest Measurement:** Every pipeline stage publishes its exact denominator and numerator. Passing tests do not imply 100% coverage; 80% line coverage does not imply 80% workflow coverage.
4. **Deterministic Reproducibility:** Fixed seeds, pinned tool versions, immutable container images, and isolated mock time clocks guarantee identical inputs yield identical findings.
5. **Non-Destructive Isolated Sandboxing:** Target applications execute within ephemeral, network-isolated containers or micro-VMs. Local state, mock databases, and storage are rolled back after every test cycle.
6. **Language & Framework Pluggable Core:** A single language-agnostic orchestration engine interfaces with modular, per-language AST, linting, instrumentation, and test execution adapters.
7. **Complete Data Privacy & Zero Exfiltration:** Source code, environment configurations, synthetic test data, screenshots, and findings never leave the local workstation or secure enclave.

---

## 3. High-Level Pipeline Architecture

The pipeline consists of **9 sequential stages with an active feedback loop**:

```
[ Stage 1: Intake & Environment Synthesis ]
                     │
                     ▼
[ Stage 2: Multi-Language Static Analysis & Symbolic Grounding ]
                     │
                     ▼
[ Stage 3: Feature, Workflow & State-Machine Discovery ]
                     │
                     ▼
[ Stage 4: Autonomous Dynamic Exploration & Crawling ]
                     │
                     ▼
[ Stage 5: Risk-Prioritized Test Planning ]
                     │
                     ▼
[ Stage 6: Neuro-Symbolic Test Generation & Self-Healing ]
                     │
                     ▼
[ Stage 7: Instrumented Sandbox Execution & Telemetry ] ◄──┐
                     │                                     │ Feedback Loop
                     ▼                                     │ (Targeting
[ Stage 8: Analysis, Deduplication & Triage ] ────────────┘  Uncovered Branches)
                     │
                     ▼
[ Stage 9: Dual Report Generation & Evidence Packaging ]
```

---

## 4. Detailed Stage Specifications & New Features

### Stage 1: Intake & Environment Synthesis
- **Intake Sources:** Accepts local directories, `.zip`/`.tar.gz` archives, or locally running URLs.
- **Git State Capture:** Records HEAD commit, branch list, clean/dirty working tree status, and diffs without contacting remote servers.
- **Automated Stack & Dependency Detection:** Identifies languages, package managers (`npm`, `pip`, `poetry`, `maven`, `cargo`), entry points, build scripts, and required backing services.
- **New Feature — Offline SBOM Generation:** Generates a Software Bill of Materials (CycloneDX / SPDX JSON format) entirely offline from lockfiles (`package-lock.json`, `poetry.lock`, `Cargo.lock`, `requirements.txt`).
- **New Feature — Secret & Sensitive Data Scrubbing:** Scans intake files for passwords, API keys, certificates, and private tokens; masks them before passing code to AST or LLM layers.
- **New Feature — Container/Service Auto-Synthesis:** Automatically synthesizes a local Docker Compose or Podman definition containing mock backing stores (PostgreSQL, Redis, RabbitMQ, local SMTP sink) required by the target app.

### Stage 2: Deep Static Analysis & Symbolic Grounding
- **AST Parsing:** Uses `tree-sitter` multi-language grammars for robust, syntax-error-tolerant parsing of Python, TypeScript/JavaScript, Java, Go, PHP, Rust, C#, Ruby, and HTML/CSS.
- **Control-Flow Graph (CFG) & Call Graph:** Constructs per-function CFGs identifying every branch condition (`if/else`, `switch`, ternary, exception handlers, loop invariants) and inter-procedural call graphs.
- **New Feature — SMT / Symbolic Path Extraction:** Integrates lightweight offline symbolic / abstract interpretation heuristics (e.g., Z3 solver hooks or constraint extractors) to compute input predicates necessary to satisfy guarded branches.
- **New Feature — Taint & Data-Flow Tracking:** Maps untrusted external inputs (HTTP query params, headers, request bodies, CLI args) across data-flow paths to security-sensitive sinks (database queries, system exec, file I/O).
- **Rule-Based Static Scans:** Executes offline static security and linter rule packs (Semgrep Community Rules, Bandit, ESLint, Flake8) matched against local rule caches.
- **New Feature — AST Diff Analysis on Git Branches:** When testing feature branches against a base branch (`main`/`develop`), isolates AST diff nodes to identify altered logic, modified routes, and affected downstream functions.

### Stage 3: Feature, Workflow & State-Machine Discovery
- **Route & Endpoint Inventory:** Extracts all HTTP routes, REST endpoints, GraphQL queries/mutations, WebSocket channels, and UI page views.
- **New Feature — Offline OpenAPI / Schema Reconstruction:** Automatically synthesizes an OpenAPI 3.1 specification or GraphQL schema from code routes, serializers, and Pydantic/Zod schemas.
- **New Feature — Role-Based Access Control (RBAC) Matrix:** Parses auth guards, middleware (`@login_required`, `role: 'admin'`, JWT claims) to construct an endpoint-to-role permissions matrix.
- **Workflow & Journey Synthesis:** Traces cross-component execution chains (e.g., `Register -> Verify Email -> Login -> Update Profile -> Checkout`).
- **Local AI Semantic Labeling:** The local LLM annotates discovered routes and call chains with human-readable feature descriptions, strictly grounding every claim in source code references (`file:line`).

### Stage 4: Autonomous Dynamic Exploration
- **Sandbox Orchestration:** Boots the target app and mock services inside network-isolated containers or headless local subprocesses.
- **Autonomous Headless Browser Crawling:** Drives Chromium/Firefox via Playwright using deterministic offline navigation algorithms.
- **New Feature — DOM-Diff State Machine Crawler:** Traverses UI states by observing DOM mutations, modal openings, and form states; detects unlinked views, dynamic dropdowns, and multi-step wizards.
- **New Feature — Synthetic Persona & Form Filling:** Dynamically generates contextually relevant mock data (synthetic names, credit cards, emails, edge-case strings, boundary values) to complete multi-step forms.
- **Multi-Role Exploration:** Executes crawl sessions under distinct credentials (Anonymous, Standard User, Administrator, Suspended User) to observe permission divergence.
- **New Feature — Network & Console Interception:** Captures client-side JavaScript console errors, failed AJAX/Fetch requests, unhandled promise rejections, and latency spikes. Compares observed routes against Stage 2 static inventory to flag unreachable endpoints.

### Stage 5: Risk-Prioritized Test Planning
- **Equivalence Partitioning & Boundary Value Analysis:** For each conditional branch extracted in Stage 2, calculates target input vectors (e.g., `< 0`, `== 0`, `> 0`, `NaN`, `null`, empty string, boundary limits).
- **Security-First Risk Scoring:** Prioritizes tests targeting high-risk attack surfaces: authentication, authorization bypass, financial calculation, data destruction, and file uploads.
- **New Feature — Metamorphic Test Planning:** Formulates metamorphic relation properties (e.g., adding an item and removing it should leave inventory invariant; changing sort order should not alter row counts).

### Stage 6: Neuro-Symbolic Test Generation & Self-Healing
- **Multi-Tier Test Synthesis:**
  - **Unit Tests:** Mock-heavy tests targeting isolated functions and edge branches.
  - **API Contract Tests:** Parameterized request/response validation against inferred schemas.
  - **End-to-End UI Tests:** Playwright/Pytest-BDD scripts exercising full user workflows.
  - **Property-Based Tests:** Hypothesis / FastCheck fuzz generators testing algebraic properties.
  - **Security Probes:** Local-only injection, path traversal, and CSRF probes against the sandbox.
- **New Feature — Constrained Grammatical Decoding:** Local LLM test generation is constrained via structured schemas (JSON Schema / AST templates) to eliminate syntax errors at generation time.
- **New Feature — Self-Healing Test Generation Loop:** Generated test scripts are automatically compiled and executed against a validation runner. If a test fails to compile or crashes due to outdated selectors, the compiler error and DOM snapshot are fed back to the local model to heal the test before committing it to the test suite.

### Stage 7: Instrumented Sandbox Execution & Telemetry
- **Multi-Layer Coverage Capture:**
  - Statement and line coverage (`coverage.py`, `c8`/`Istanbul`, `JaCoCo`).
  - Branch and decision condition coverage.
  - API endpoint and route coverage.
  - Feature and workflow journey coverage.
- **New Feature — Flakiness Quarantine & Bisecting:** Every failing test is automatically re-run $N$ times ($N \ge 3$). Tests exhibiting non-deterministic outcomes are quarantined, tagged as `Flaky`, and isolated from regression blocking.
- **New Feature — Resource & Memory Leak Profiling:** Telemetry monitors memory consumption, open file descriptors, event loop lag, and CPU spikes during test execution, detecting memory leaks and slow database queries.

### Stage 8: Analysis, Deduplication & Triage
- **Unified Issue Aggregation:** Ingests static analysis alerts, dynamic crawl failures, unhandled runtime exceptions, and test assertion failures into a single normalized data structure.
- **New Feature — AST & Call-Stack Root Cause Deduplication:** Groups multiple test failures that originate from the same underlying AST function or stack trace into a single root-cause issue.
- **Severity & Confidence Scoring:**
  - **Severity:** `Critical` (crash, data loss, auth bypass), `High` (broken core feature, security vulnerability), `Medium` (validation bug, accessibility violation, degraded performance), `Low` (minor UI defect, styling inconsistency, code smell).
  - **Confidence:** `Confirmed` (empirically reproduced via test execution), `Likely` (heuristic/static finding with high confidence rule), `Possible` (inferred by LLM or partial static match, requiring manual audit).
- **New Feature — Automated CWE & CVSS Scoring:** Maps confirmed security findings to standardized Common Weakness Enumeration (CWE) IDs and estimates CVSS v3.1 base vectors.
- **Active Coverage Feedback Loop:** Uncovered branches and routes trigger dynamic re-planning (Stage 5) and generation (Stage 6) for up to $K$ iterations or until a defined time budget is exhausted.

### Stage 9: Dual Report Generation & Evidence Packaging
- **Report A (Detailed Engineering Report):** Exhaustive technical audit document covering run summary, architecture maps, complete inventory, branch maps, 7-dimensional coverage breakdown, issue register with full reproduction steps, tool version ledger, and limitations.
- **Report B (Issues-Highlight Executive Report):** 1–3 page executive briefing detailing overall health score, top critical issues, severity distribution, risk hotspots, coverage headline, quick wins, and prioritized next actions.
- **New Feature — Self-Contained Offline Interactive HTML/WASM Viewer:** Generates a single, zero-dependency, self-contained HTML file bundling an offline WebAssembly SQL/search engine (SQLite-WASM or DuckDB-WASM), allowing engineers to search, filter, and inspect findings, logs, and screenshots without an internet connection or running web server.

---

## 5. Architectural & Technical Implementation Components

| Component Layer | Technology / Tool Stack | Offline Role & Preparation |
| :--- | :--- | :--- |
| **Local LLM Runtime** | `llama.cpp` / `vLLM` / `Ollama` | Runs quantised (GGUF / AWQ) code models locally without network sockets. |
| **Base AI Models** | Qwen 2.5 Coder (7B–32B), DeepSeek-Coder-V2, Mistral-Codestral | Code understanding, AST-guided test generation, issue explanation. |
| **Embeddings & Vector Index** | `nomic-embed-code` / `bge-small-en-v1.5` + `Chromadb` / `FAISS` / SQLite | Local semantic search across repository files and documentation. |
| **Grammar & Parsing** | `tree-sitter` + multi-language grammar packages | Offline AST generation, CFG construction, and call-graph traversal. |
| **Static Analyzers & Linters** | Semgrep (offline rules cache), ESLint, Bandit, Flake8, Ruff | Multi-language static bug and security scanning. |
| **Dynamic Automation** | Playwright (bundled Chromium, Firefox, WebKit binaries) | Headless browser execution, DOM crawl, and screenshot capture. |
| **Mock Backing Services** | Local mock SQLite/PostgreSQL, WireMock, Fake SMTP sink | Replaces external payment, email, and cloud APIs inside sandbox. |
| **Container Isolation** | Docker / Podman (with pre-cached images & disabled network) | Strict ephemeral sandbox execution. |
| **Coverage Instrumentation** | `coverage.py`, `c8`/`Istanbul`, `JaCoCo`, `gcov` | Multi-language statement, branch, and route coverage calculation. |
| **Local Evidence Store** | SQLite + structured JSON artifact files | Unified store for code elements, branches, runs, issues, and logs. |

---

## 6. Seven-Dimension Coverage Model

The system rejects blanket coverage declarations in favor of explicit, mathematically grounded ratios:

$$\text{Coverage Score} = \frac{\text{Count}(\text{Exercised Elements})}{\text{Count}(\text{Discovered Elements}) - \text{Count}(\text{Provably Unreachable Elements})}$$

| Coverage Dimension | Evaluator / Metric | Explicit Denominator |
| :--- | :--- | :--- |
| **1. Repository Inventory** | `Files Analyzed / (Total Files - Excluded Files)` | Every file discovered in repository. |
| **2. Static Analysis** | `Parsed & Scanned Nodes / Total AST Nodes` | All discovered source code files. |
| **3. Test Execution** | `Passed + Failed Tests Executed / Total Discovered Tests` | All pre-existing + generated tests. |
| **4. Code & Branch** | Line, statement, and branch coverage percentages | Measured by runtime instrumentation. |
| **5. Route / API** | `Tested Endpoints / Total Discovered Static Endpoints` | All extracted HTTP routes and screens. |
| **6. Workflow** | `Exercised Multi-Step Journeys / Discovered Workflows` | All end-to-end user journeys mapped. |
| **7. Feature** | `Validated Features / Discovered Features` | All functional features cataloged. |

---

## 7. Operational, Security, and Engineering Guidelines

### Guideline 1: Air-Gap Cryptographic Integrity & Zero-Exfiltration
- **Rule 1.1:** The testing engine must execute with zero active network dependencies. All runtime commands must enforce offline flags (`PIP_NO_INDEX=1`, `npm_config_offline=true`, `GOPROXY=off`, `CARGO_NET_OFFLINE=true`).
- **Rule 1.2:** Subprocesses must be wrapped with system-level network namespace isolation (Linux `unshare -n` / container bridge disconnection / Windows null route proxy).
- **Rule 1.3:** Every bundled tool, model weight file, browser binary, and package archive must have its SHA-256 checksum recorded in a signed `manifest.json`. Verification runs prior to execution; any hash mismatch halts the pipeline.
- **Rule 1.4:** Generated reports must be completely self-contained (base64 embedded images, embedded CSS/JS, zero external CDN links).

### Guideline 2: The Neuro-Symbolic Ground Truth Principle
- **Rule 2.1:** No AI model assertion may be reported as a defect without deterministic validation.
- **Rule 2.2:** An issue is marked as `Confirmed` only if it produces a reproducible non-zero exit code, unhandled exception trace, failed assertion, or tool-verified vulnerability.
- **Rule 2.3:** Unverified AI hypotheses must be explicitly categorized as `Inferred` or `Possible` and kept in a separate advisory section of the report.
- **Rule 2.4:** Every code reference generated by an AI model must be checked against the AST index. If the referenced file, line, or symbol does not exist, the finding is discarded as a hallucination.

### Guideline 3: Non-Destructive Isolated Execution & Clean-Slate Rollback
- **Rule 3.1:** Target repository code must never execute directly on the host operating system without explicit administrative approval (`--allow-scripts`).
- **Rule 3.2:** All dynamic exploration and test execution must take place inside disposable containers or temporary directory sandboxes.
- **Rule 3.3:** Database migrations and test transactions must run against disposable mock instances or use transaction rollbacks after each test case.
- **Rule 3.4:** The testing system must provide synthetic system clocks (mock time) to safely test date-dependent logic (e.g., subscription expiry, leap years) without altering the host clock.

### Guideline 4: Multi-Dimensional Honest Coverage & Gap Accounting
- **Rule 4.1:** The system shall never output a single aggregated "100% Tested" badge unless all 7 coverage dimensions mathematically achieve 100%.
- **Rule 4.2:** Every untested branch, route, or workflow must be cataloged in the Coverage Gap Registry with an assigned reason code:
  - `GAP_UNREACHABLE`: Dead code or provably contradictory conditional predicate.
  - `GAP_AUTH_BLOCKED`: Required authentication credentials or roles unavailable.
  - `GAP_EXTERNAL_DEPENDENCY`: Requires third-party cloud service or hardware API not mocked.
  - `GAP_TIMEOUT`: Execution time budget exceeded before test could execute.
  - `GAP_SYNTAX_ERROR`: Code failed to compile or parse.

### Guideline 5: Flakiness Quarantine & Deterministic Repeatability
- **Rule 5.1:** Tests failing non-deterministically across $N$ consecutive executions under identical parameters must be isolated into a quarantine group.
- **Rule 5.2:** Quarantined flaky tests must be reported separately and excluded from blocking pass/fail health gates.
- **Rule 5.3:** The orchestrator must record and log all pseudo-random number seeds, environment variables, and execution parameters to ensure byte-level test reproduction.

### Guideline 6: PII, Credential & Sensitive Artifact Redaction
- **Rule 6.1:** All intake code, environment variables, configuration files, and runtime outputs must pass through an automated entropy and regex redaction filter prior to storage or display.
- **Rule 6.2:** Detected API keys, private certificates, JWT tokens, and database passwords must be replaced with deterministic redaction tokens (e.g., `[REDACTED_AWS_KEY_1]`).
- **Rule 6.3:** Screenshots captured during dynamic crawling must be passed through a local optical masking filter if form inputs contain credit card or PII patterns.

### Guideline 7: Safe Failure & Graceful Degradation
- **Rule 7.1:** Individual tool failures (e.g., a linter crashing or a browser timeout) must not terminate the entire pipeline run.
- **Rule 7.2:** If dynamic sandbox initialization fails (e.g., Docker daemon unavailable), the pipeline must gracefully degrade to static analysis and report mode, explicitly logging the degradation in the executive summary.
- **Rule 7.3:** Strict CPU, memory, and wall-clock execution limits must be enforced on all generated tests to prevent denial-of-service loops (e.g., infinite `while` loops).

---

## 8. Data Model & Schema (Project Store)

The local SQLite project store maintains relational consistency and complete bidirectional traceability:

```
[Project] ──< [Run] ──< [RunCoverage]
                │
                ├──< [Artifact] ──< [CodeElement] ──< [Branch]
                │                                       │
                │                                       ▼
                ├──< [TestPlan] ──< [GeneratedTest] ──< [TestExecution]
                │                                             │
                │                                             ▼
                └──< [IssueRegister] ◄────────────────────────┘
```

1. **Project:** `project_id`, `name`, `repo_path`, `created_at`
2. **Run:** `run_id`, `project_id`, `git_commit`, `git_branch`, `base_branch`, `start_time`, `end_time`, `status`, `flags`
3. **Artifact (File):** `artifact_id`, `run_id`, `rel_path`, `language`, `sha256`, `disposition`, `disposition_reason`
4. **CodeElement:** `element_id`, `artifact_id`, `type` (function/class/route), `name`, `start_line`, `end_line`, `complexity`
5. **Branch:** `branch_id`, `element_id`, `condition_expression`, `start_line`, `is_covered`, `covering_test_id`
6. **RouteEndpoint:** `route_id`, `run_id`, `path`, `http_method`, `auth_required`, `required_roles`, `is_crawled`
7. **Feature:** `feature_id`, `run_id`, `name`, `description`, `linked_routes`, `linked_elements`, `status`
8. **Workflow:** `workflow_id`, `run_id`, `name`, `steps_json`, `status`
9. **GeneratedTest:** `test_id`, `run_id`, `target_branch_id`, `test_type`, `code_body`, `validation_status`
10. **TestExecution:** `exec_id`, `test_id`, `run_id`, `exit_code`, `duration_ms`, `stdout`, `stderr`, `is_flaky`
11. **IssueRegister:** `issue_id`, `run_id`, `title`, `category`, `severity`, `confidence`, `cwe_id`, `location`, `evidence`, `reproduction_steps`, `suggested_fix`, `status`
12. **CoverageRecord:** `coverage_id`, `run_id`, `dimension`, `numerator`, `denominator`, `percentage`, `gap_reasons_json`

---

## 9. Implementation Roadmap & Phased Execution

```
Phase 0: Architecture & Environment Pinned Manifests (Weeks 1–2)
Phase 1: Air-Gapped Foundation & Core Runner Sandbox (Weeks 3–5)
Phase 2: Tree-Sitter AST, CFG & Static Analysis Engine (Weeks 6–9)
Phase 3: Autonomous Dynamic Crawler & Sandbox Services (Weeks 10–13)
Phase 4: Feature & Workflow Discovery via Local LLM (Weeks 14–16)
Phase 5: Neuro-Symbolic Test Generation & Self-Healing Loop (Weeks 17–22)
Phase 6: Multi-Dimensional Triage & Dual Report Engine (Weeks 23–25)
Phase 7: Hardening, Benchmarking & Multi-Language Expansion (Ongoing)
```

---

## 10. Verification Benchmarks & Quality Gates

To ensure the testing system operates with high precision and reliability:
1. **Seeded-Defect Benchmark (Recall & Precision Gate):** Run against curated, intentionally vulnerable applications (e.g., OWASP Juice Shop, DVWA, custom seeded Python/TS test repos). Target: $\ge 85\%$ defect recall with $\le 10\%$ false-positive rate.
2. **Branch Coverage Threshold:** Target $\ge 80\%$ measured branch coverage on supported target languages, with 100% of remaining gaps classified with verifiable reason codes.
3. **Bit-Level Reproducibility Audit:** Running two back-to-back evaluations against the same codebase revision must produce identical issue identifiers and severity scores.
4. **Air-Gap Verification Check:** Execution of `offtest verify-offline` must pass without any permitted outbound IP packets on all network interfaces.
