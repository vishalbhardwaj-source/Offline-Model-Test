# Offline App and Website Testing Model — Blueprint

## 1. Purpose
This document defines a plan for building an offline system that analyzes and tests application and website repositories. It covers the pipeline, components, preparation requirements, branch handling, and two report formats.

The system should discover and assess source code, application workflows, features, and Git branches without sending repository data or test results over a network.

**Important limitation:** No automated system can guarantee detection of every defect or fully understand every behavior in arbitrary software. The system should instead aim for exhaustive repository inventory, broad test coverage, explicit uncertainty reporting, and clear evidence for each finding.

## 2. Goals
The system should:
1. Run with networking disabled after its required tools, models, and dependencies have been prepared.
2. Accept supported application and website repositories as input.
3. Inventory source files, configurations, tests, assets, routes, APIs, features, and workflows.
4. Identify relevant Git branches and compare them safely.
5. Run available checks and tests in an isolated environment.
6. Identify uncovered areas and report limitations rather than implying complete coverage.
7. Produce:
   - A detailed report for investigation and review.
   - An issue-focused report that highlights actionable problems.

## 3. Non-goals and boundaries
- It cannot prove that software is defect-free.
- It cannot reliably infer the purpose of undocumented code in every project.
- It should not automatically change or commit application source code.
- It should not execute untrusted repository code outside a controlled environment.
- It should not claim that a feature or branch was tested when the necessary environment, credentials, data, or dependencies were unavailable.
- Any optional AI model must be local. AI-generated conclusions must be labeled as suggestions and supported by evidence where possible.

## 4. High-level pipeline
1. **Prepare the offline environment**: Install or cache approved runtimes, compilers, browsers, test tools, package archives, and optional local models. Record tool versions and verify that the environment works without network access.
2. **Ingest the repository**: Accept a local repository path or an offline archive. Record repository identity, current revision, remotes, and working-tree state. Do not fetch from remotes.
3. **Inventory the repository**: Identify languages, frameworks, build systems, package managers, entry points, tests, configuration, assets, and generated files. Classify every discovered file as `analyzed`, `excluded`, `generated`, `binary`, `unsupported`, or `failed_to_inspect`.
4. **Map branches and changes**: List locally available branches and tags. Identify the requested branch set and its comparison base. Compare changes and determine which checks need to run per branch. Report branches that could not be checked out or tested.
5. **Discover application structure**: Extract routes, screens, APIs, services, data stores, feature flags, workflows, and external integrations where detectable. Link discovered features to source files, tests, and configuration. Mark inferred relationships as inferred, not confirmed.
6. **Plan checks**: Select checks based on detected languages, frameworks, and project configuration. Include existing project tests and approved static-analysis tools. Identify missing tools, unavailable dependencies, and checks that cannot run offline.
7. **Run checks in isolation**: Use disposable workspaces or containers/virtual machines where available. Disable network access by default. Apply resource limits and timeouts. Preserve logs, exit codes, tool versions, and test artifacts.
8. **Collect and correlate evidence**: Deduplicate findings from different tools. Associate findings with files, lines, branches, features, workflows, and test results when possible. Track whether a result is confirmed, inferred, or unverified.
9. **Assess coverage and gaps**: Report source-file inventory coverage, test execution coverage, branch coverage, workflow coverage, and unsupported areas separately. Do not treat a passing test suite as evidence that every feature or code path is covered.
10. **Generate the two reports**: Produce a detailed report and an issue-focused report from the same structured results. Keep both reports traceable to the tested revision and tool configuration.

## 5. Required components
- **5.1 Repository intake and safety**: Local intake, revision recorder, file-type detection, secret scanning & sensitive-data redaction, isolation & approval controls for repository scripts.
- **5.2 Offline tool and dependency manager**: Inventory of tools, local package-manager configuration (prevent network access), checksums, tool manifest.
- **5.3 Repository discovery engine**: Languages, frameworks, entry points, routes, APIs, services, persistence, feature flags, tests, workflow definitions, recorded file dispositions.
- **5.4 Code and workflow analysis**: AST parsing, dependency mapping, static/security checks, route/API extraction, observed vs inferred vs unverified markers.
- **5.5 Test execution engine**: Formatting, linting, type checking, unit/integration tests, offline security checks, execution logging, failure logging without inventing success.
- **5.6 Branch and change analysis**: Enumerate local branches, diff against base branch, isolated workspaces, changed file mapping.
- **5.7 Reporting and evidence store**: Structured local JSON runs, redaction of secrets, report reproducibility from local store.

## 6. Preparation checklist
- Environment: offline workstation, runtimes, clock/timezone, disk space.
- Tools and dependencies: local packages, caches, static tools.
- Project information: startup info, test commands, configs, non-prod test data.

## 7. Coverage model
1. Repository inventory coverage
2. Static-analysis coverage
3. Test execution coverage
4. Code coverage
5. Workflow coverage
6. Feature coverage
7. Branch coverage

## 8. Report 1 — Detailed report
Run summary, Executive summary, Repository inventory, Application map, Branch & change analysis, Checks & test results, Findings, Coverage & gaps, Reproducibility details, Limitations.

## 9. Report 2 — Issue-focused report
Status summary & issue count, Grouped by severity & branch/feature, Impact, Evidence/reproduction, Suggested action, Unverified/blocked section, Coverage gaps.

## 10. Finding severity and confidence
- Severity: Critical, High, Medium, Low, Informational
- Confidence: High, Medium, Low

## 11. Acceptance criteria
See blueprint text.
