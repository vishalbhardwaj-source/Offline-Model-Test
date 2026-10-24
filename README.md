# Offline App and Website Testing Model (`offtest`)

An offline pipeline and analysis engine that ingests, catalogs, analyzes, and tests application and website repositories without sending repository data, secrets, or test results over any network.

Designed directly against the **[Master Blueprint](file:///c:/Users/visha/Downloads/Testing%20model/BLUEPRINT.md)**.

---

## Key Capabilities

- **Strict Offline Operation & Air-Gap Enforcement:**
  - Multi-layer defense: Environment proxy sinkholes (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `PIP_NO_INDEX=1`, `npm_config_offline=true`).
  - Child-process Python socket interceptor (`sitecustomize.py`) blocking raw TCP (`connect`), UDP (`sendto`), and DNS (`getaddrinfo`) calls to non-loopback addresses while allowing safe local mock servers (`127.0.0.1`, `localhost`).
  - Host secret shielding: Redirects `USERPROFILE`, `HOME`, and `APPDATA` to an ephemeral sandbox to protect host credentials (`~/.ssh`, `~/.aws`).
  - Process tree kill on timeout (`taskkill /F /T` on Windows, `killpg` on Unix) to prevent orphaned background processes.
- **Offline Software Bill of Materials (SBOM):** Automatically extracts and catalogs all dependencies from `package-lock.json`, `package.json`, `poetry.lock`, `Cargo.lock`, and `requirements.txt` into a CycloneDX 1.5-compatible schema offline.
- **RBAC Permission Matrix & OpenAPI 3.1 Spec Generator:** Inters role-based access control policies (`Anonymous`, `Authenticated`, `Admin`) and automatically reconstructs an offline OpenAPI 3.1 specification from route signatures.
- **Constrained Branch Test Generator:** Parses AST conditional branches (comparisons, null checks, boolean expressions) and synthesizes syntax-validated, self-healing unit test suites.
- **Flakiness Bisection & Quarantine Runner:** Automatically performs multi-run bisection testing ($N \ge 3$) on tests to detect and quarantine non-deterministic tests from blocking release gates.
- **Exhaustive Inventory:** Discovers and classifies 100% of discovered files into recorded dispositions (`analyzed`, `excluded`, `generated`, `binary`, `unsupported`, or `failed_to_inspect`) with explicit reasons.
- **Application Structure & Workflow Discovery:** Extracts routes, APIs, pages, integrations, and feature toggles with explicit evidence status:
  - `Observed`: Directly present in code/config.
  - `Inferred`: Deduced through naming/relationships.
  - `Unverified`: Lacking confirmation.
- **Safe Branch Analysis:** Enumerates and compares local Git branches and tags without ever contacting remote servers.
- **Operational Safeguards:**
  - Automated detection and redaction of credentials, API keys, and connection strings.
  - Explicit approval required (`--allow-scripts`) before executing untrusted repository test suites.
  - Execution timeouts and isolated subprocess wrappers.
- **7-Dimension Coverage Model:**
  1. Repository inventory coverage
  2. Static analysis coverage
  3. Test suite execution coverage
  4. Code coverage (statement/branch - explicitly marked `Unavailable` if offline artifact is missing)
  5. Workflow coverage
  6. Feature coverage
  7. Branch coverage
- **Two Complete Report Formats:**
  - **Report 1 (Detailed Report):** Full 10-section investigation report covering inventory, SBOM, RBAC matrix, OpenAPI specs, branch diffs, checks, flakiness quarantine, findings, and 7 coverage dimensions.
  - **Report 2 (Issue-Focused Report):** Prioritized, actionable issue list grouped by severity with reproduction evidence, impact, quarantined flaky tests, next actions, blocked checks, and coverage gaps.
- **Evidence Store & Report Reproduction:** Saves complete run contexts as structured JSON and reproduces reports on demand without re-running checks.

---

## Installation & Quickstart

### Prerequisites
- Python 3.10+ (Standard library, `click`, and `pydantic`)
- Git (local)

Install locally in editable mode:
```bash
pip install -e .
```

### CLI Commands

#### 1. Assess a Repository
```bash
# Standard assessment (intake, SBOM, RBAC, OpenAPI, static scans, test generation)
python -m offtest assess /path/to/repo --base main --branch feature/payment

# Run with flakiness bisection and quarantine enabled
python -m offtest assess /path/to/repo --base main --detect-flaky

# Approve executing repository test scripts in offline isolation
python -m offtest assess /path/to/repo --base main --allow-scripts
```

#### 2. Reproduce Reports from Run Evidence
```bash
# Reproduce both reports from a previous run ID or JSON evidence file
python -m offtest report run_20261023_172221_e5691f --out ./exported_reports
```

#### 3. Inspect Offline Tool Manifest
```bash
python -m offtest manifest
```

#### 4. Verify Network Isolation
```bash
python -m offtest verify-offline
```

---

## Project Structure

```
├── offtest/
│   ├── core/
│   │   ├── config.py           # Offline flags, timeouts, sensitive data regexes
│   │   ├── models.py           # Pydantic data models (SBOM, RBAC, Flakiness, Findings)
│   │   └── evidence_store.py   # Persistent JSON evidence store & loader
│   ├── intake/
│   │   ├── intake.py           # Archive (.zip, .tar.gz) and path intake with Zip Slip protection
│   │   ├── git_manager.py      # Local Git branch inspection and diffing (NO network fetches)
│   │   └── safety.py           # Secret scanning & sensitive data redaction
│   ├── inventory/
│   │   ├── classifier.py       # Language and disposition classifier (analyzed, excluded, binary...)
│   │   ├── engine.py           # File walker and inventory summary generator
│   │   └── sbom.py             # Offline Software Bill of Materials (CycloneDX 1.5)
│   ├── discovery/
│   │   ├── app_mapper.py       # Route, API, feature toggle, and workflow extractor
│   │   └── rbac_and_schema.py  # RBAC permission matrix & OpenAPI 3.1 spec generator
│   ├── generator/
│   │   └── test_generator.py   # Constrained branch predicate analysis & test synthesizer
│   ├── checks/
│   │   ├── isolated_runner.py  # Subprocess isolation with offline env variables & timeouts
│   │   ├── sandbox_interceptor.py # Socket/DNS interceptor blocking outbound TCP/UDP
│   │   ├── static_checks.py    # AST syntax, security flaws (eval, os.system, debug), dependency pins
│   │   ├── test_adapter.py     # Test discovery & execution with explicit script approval guard
│   │   ├── flakiness.py        # Multi-run bisection & flakiness quarantine runner
│   │   └── planner.py          # Coordinates checks and tool manifest
│   ├── coverage/
│   │   └── evaluator.py        # Calculates 7 coverage dimensions with explicit denominators
│   ├── reports/
│   │   ├── detailed.py         # Report 1: Detailed 10-section report
│   │   └── issue_focused.py    # Report 2: Actionable issue-focused report
│   ├── orchestrator.py         # Multi-stage assessment pipeline coordinator
│   └── cli.py                  # Click CLI interface
├── tests/                      # Pytest test suite covering all 16 components
└── sample_repos/               # Fixtures and test applications
```

---

## Acceptance Criteria Conformance

| Acceptance Criterion | Implementation Status |
| :--- | :---: |
| Run assessment with networking disabled | Verified (`IsolatedRunner` + environment controls) |
| Offline Software Bill of Materials (SBOM) | Verified (`SBOMGenerator`, CycloneDX-compatible) |
| Role-Based Access Control (RBAC) Matrix | Verified (`RBACAndSchemaExtractor`) |
| Offline OpenAPI 3.1 Specification Synthesis | Verified (`OpenAPISpecRecord` generation) |
| Flakiness Bisection & Quarantine Runner | Verified (`FlakinessBisectionRunner` $N \ge 3$) |
| Constrained Branch Test Generation | Verified (`ConstrainedTestGenerator` AST analysis) |
| Record tested revision and selected local branches | Verified (`GitManager` without remote fetch) |
| Inventory files with explicit exclusions/dispositions | Verified (`InventoryEngine`, 100% cataloged) |
| Discover checks without silently fetching dependencies | Verified (offline manifests & offline runner) |
| Isolate execution, preserve logs & test results | Verified (redacted logs, exit codes, durations) |
| Produce both report formats from same evidence | Verified (`DetailedReportGenerator` & `IssueFocusedReportGenerator`) |
| Separate confirmed results from inferred/unverified | Verified (`EvidenceStatus` tags on all entities) |
| Show test and workflow gaps without claiming complete detection | Verified (explicit denominators & unavailable tracking) |
| Reproduce a report from stored local run data | Verified (`EvidenceStore.load_run` & `offtest report`) |
