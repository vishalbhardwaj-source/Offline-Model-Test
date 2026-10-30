from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class FindingCategory(str, Enum):
    VULNERABILITY = "vulnerability"
    SECRET = "secret_exposure"
    SUPPLY_CHAIN = "supply_chain"
    POLICY = "policy_violation"
    CORRECTNESS = "correctness"
    HYGIENE = "hygiene"


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    POSSIBLE = "Possible"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class EvidenceStatus(str, Enum):
    OBSERVED = "Observed"
    INFERRED = "Inferred"
    UNVERIFIED = "Unverified"


class FileDisposition(str, Enum):
    ANALYZED = "analyzed"
    EXCLUDED = "excluded"
    GENERATED = "generated"
    BINARY = "binary"
    UNSUPPORTED = "unsupported"
    FAILED_TO_INSPECT = "failed_to_inspect"


class CheckStatus(str, Enum):
    PASSED = "Passed"
    FAILED = "Failed"
    SKIPPED = "Skipped"
    BLOCKED = "Blocked"


class FileRecord(BaseModel):
    path: str
    size_bytes: int
    sha256: str
    language: Optional[str] = None
    category: str = "source"  # source, config, test, asset, doc, build, other
    disposition: FileDisposition
    disposition_reason: str
    line_count: Optional[int] = None


class RouteRecord(BaseModel):
    path: str
    method: str = "GET"
    handler: Optional[str] = None
    file_path: str
    line_number: Optional[int] = None
    file_sha256: Optional[str] = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    notes: Optional[str] = None


class APIRecord(BaseModel):
    endpoint: str
    method: str = "GET"
    handler: Optional[str] = None
    file_path: str
    line_number: Optional[int] = None
    file_sha256: Optional[str] = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    auth_required: Optional[bool] = None
    notes: Optional[str] = None


class FeatureRecord(BaseModel):
    name: str
    flag_key: Optional[str] = None
    file_path: str
    line_number: Optional[int] = None
    file_sha256: Optional[str] = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    linked_tests: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class WorkflowRecord(BaseModel):
    name: str
    description: str
    entry_point: Optional[str] = None
    related_files: List[str] = Field(default_factory=list)
    linked_tests: List[str] = Field(default_factory=list)
    status: EvidenceStatus = EvidenceStatus.INFERRED
    steps: List[str] = Field(default_factory=list)
    is_advisory: bool = True
    symbolic_edges_verified: bool = False
    initiated_by: Optional[str] = None
    initiation_triggers: List[Tuple[str, str]] = Field(default_factory=list)
    processing_pipeline: List[str] = Field(default_factory=list)
    pipeline_substeps: Dict[str, List[str]] = Field(default_factory=dict)
    where_it_leads: Optional[str] = None
    where_it_leads_points: List[str] = Field(default_factory=list)
    subgraph: Optional[str] = None
    nodes: List[Dict[str, str]] = Field(default_factory=list)
    connections: List[Tuple[str, str]] = Field(default_factory=list)


class IntegrationRecord(BaseModel):
    name: str
    category: str  # e.g., "Database", "Authentication", "Payment", "Email", "External API"
    detected_in: List[str] = Field(default_factory=list)
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    details: Optional[str] = None


class BranchRecord(BaseModel):
    name: str
    is_current: bool = False
    is_base: bool = False
    head_commit: Optional[str] = None
    commit_message: Optional[str] = None
    status: str = "available"  # available, checked_out, uncheckoutable, skipped
    error_details: Optional[str] = None


class BranchDiffRecord(BaseModel):
    branch_name: str
    base_branch: str
    added_files: List[str] = Field(default_factory=list)
    modified_files: List[str] = Field(default_factory=list)
    deleted_files: List[str] = Field(default_factory=list)
    total_changed_files: int = 0
    diff_summary: Optional[str] = None


class CheckResult(BaseModel):
    tool_name: str
    tool_version: str
    check_name: str
    check_type: str  # syntax, security, lint, typecheck, unit_test, dependency
    command: str
    exit_code: int
    duration_sec: float
    stdout: str = ""
    stderr: str = ""
    status: CheckStatus
    execution_status: str = "Completed"  # Completed, Blocked, Error, Skipped
    gate_outcome: str = "Pass"          # Pass, Fail, Blocked, Neutral
    skip_or_blocked_reason: Optional[str] = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory = FindingCategory.VULNERABILITY
    rule_id: Optional[str] = None
    provenance: str = "rule"  # rule, symbolic, model
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    branch: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    file_sha256: Optional[str] = None
    impact: str
    evidence: str
    suggested_action: str
    check_tool: Optional[str] = None
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    cvss_score_estimate: Optional[float] = None
    cvss_vector_estimate: Optional[str] = None
    cvss_is_estimate: bool = True
    environmental_context_assumed: Optional[str] = None
    oracle_origin: Optional[str] = None
    reproduced: bool = True
    sandbox_artifact: bool = False
    owasp_category: Optional[str] = None
    asvs_chapter: Optional[str] = None
    evidence_level: str = "static-only"  # static-only, reachable, test-confirmed, model-hypothesis
    exposure: str = "internal"           # public_unauth, public_auth, internal, test_fixture
    reachability: str = "unknown"        # reachable, unreachable, unknown
    priority_score: float = 1.0
    fingerprint: Optional[str] = None
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    root_cause_cluster: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    cwe_secondary_ids: List[str] = Field(default_factory=list)
    related_locations: List[Dict[str, Any]] = Field(default_factory=list)
    partial_fingerprints: Dict[str, str] = Field(default_factory=dict)
    oracle_satisfied: bool = False
    flaky_test_observed: bool = False
    cisa_kev: bool = False
    epss_score: Optional[float] = None


def compute_priority(
    severity: Severity,
    confidence: Confidence,
    reachability: str = "unknown",
    exposure: str = "internal",
    evidence_level: str = "static-only",
    cisa_kev: bool = False,
    epss_score: Optional[float] = None,
) -> float:
    """
    Computes a benchmark-calibrated Priority Score normalized to 0.0 - 100.0:
    Priority = min(100.0, round(Severity_Weight * Confidence * Evidence_Multiplier * Reachability_Factor * Exposure_Factor, 1))

    Calibrated Precision Scales:
    - Severity Weight: Critical (100.0), High (70.0), Medium (40.0), Low (20.0), Informational (5.0)
    - Confidence (Rule Precision): Confirmed (1.00), High/Likely (0.85), Medium (0.65), Low/Possible (0.40)
    - Evidence Level Multiplier (Orthogonal verification pedigree, no double-counting with Reachability):
      * test-confirmed: 1.20 (exploit oracle satisfied in dynamic test execution)
      * static-only: 1.00 (deterministic AST or pattern verification baseline)
      * model-hypothesis: 0.50 (unverified neural synthesis, strictly capped at 25.0)
      (Note: flaky-test no longer demotes; findings retain static-only 1.00 with a flaky annotation)
    - Reachability Factor:
      * reachable: 1.00 (called/imported from entry point)
      * unknown / non-code default (secrets, configs): 0.70 (or 1.00 for active secrets)
      * unreachable: 0.20 (dead code or unreferenced package)
    - Exposure Factor:
      * public_unauth: 1.00 (unauthenticated internet-facing route/CLI)
      * public_auth: 0.75 (authenticated user-facing route)
      * internal: 0.50 (internal backend service or config)
      * test_fixture: 0.20 (test mock or fixture)

    Hard Floor Overrides:
    - Known Exploited Vulnerability (CISA KEV): sets floor priority at 80.0 (instant gate failure).
    """
    sev_map = {
        Severity.CRITICAL: 100.0,
        Severity.HIGH: 70.0,
        Severity.MEDIUM: 40.0,
        Severity.LOW: 20.0,
        Severity.INFORMATIONAL: 5.0,
    }
    conf_map = {
        Confidence.CONFIRMED: 1.00,
        Confidence.HIGH: 0.85,
        Confidence.LIKELY: 0.85,
        Confidence.MEDIUM: 0.65,
        Confidence.LOW: 0.40,
        Confidence.POSSIBLE: 0.40,
    }
    # Orthogonal evidence pedigree: reachability is NOT double-counted here.
    # Flaky tests do NOT demote below static-only (1.00).
    ev_map = {
        "test-confirmed": 1.20,
        "static-only": 1.00,
        "reachable": 1.00,  # Legacy alias fallback
        "flaky-test": 1.00,   # Non-demoting: retains baseline with annotation
        "model-hypothesis": 0.50,
    }
    reach_map = {
        "reachable": 1.00,
        "unknown": 0.70,
        "unreachable": 0.20,
    }
    expo_map = {
        "public_unauth": 1.00,
        "public_auth": 0.75,
        "internal": 0.50,
        "test_fixture": 0.20,
    }
    s = sev_map.get(severity, 40.0)
    c = conf_map.get(confidence, 0.65)
    ev = ev_map.get(evidence_level, 1.00)
    r = reach_map.get(reachability, 0.70)
    e = expo_map.get(exposure, 0.50)
    raw = s * c * ev * r * e

    if cisa_kev:
        raw = max(raw, 80.0)

    if evidence_level == "model-hypothesis":
        return min(25.0, round(raw, 1))
    return min(100.0, round(raw, 1))


def deduplicate_and_cluster_findings(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicates findings using the hierarchical cluster key:
    `{file}:{rule}:{parent}` (uniform notation across all reports, cards, and diagrams).
    - If a shared utility helper causes the same flaw across call sites, clusters by
      `{origin_file}:{rule}:{helper_func}`.
    - Consolidates multiple occurrences into a single primary representative
      (the one with highest priority score; ties broken by severity then exposure).
    - Attaches secondary occurrences to the primary finding as `related_locations`
      (formatted for SARIF relatedLocations).
    - Preserves logicalLocationKey partial fingerprints independent of line numbers.
    """
    sev_rank = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFORMATIONAL: 1,
    }
    expo_rank = {
        "public_unauth": 4,
        "public_auth": 3,
        "internal": 2,
        "test_fixture": 1,
    }

    clusters: Dict[str, List[Finding]] = {}
    for f in findings:
        # Determine parent scope from context or fallback
        parent = "global"
        origin_file = str(f.file_path or "UNKNOWN").replace("\\", "/")
        if f.context and f.context.get("parent_scope"):
            parent = f.context["parent_scope"]
        elif f.context and f.context.get("helper_func"):
            parent = f.context["helper_func"]
            if f.context.get("origin_file"):
                origin_file = str(f.context["origin_file"]).replace("\\", "/")
        elif f.root_cause_cluster and "::" in f.root_cause_cluster:
            parent = f.root_cause_cluster.split("::")[-1]

        rule_key = f.rule_id or "GENERAL"
        key = f"{origin_file}:{rule_key}:{parent}"
        clusters.setdefault(key, []).append(f)

    deduplicated: List[Finding] = []
    for key, group in clusters.items():
        # Sort group with explicit tie-breakers:
        # 1. priority_score descending
        # 2. severity rank descending
        # 3. exposure rank descending
        group.sort(
            key=lambda item: (
                getattr(item, "priority_score", 0.0),
                sev_rank.get(item.severity, 0),
                expo_rank.get(getattr(item, "exposure", "internal"), 0),
            ),
            reverse=True,
        )
        primary = group[0]

        # Attach other occurrences as related_locations
        if len(group) > 1:
            rel_locs = list(primary.related_locations or [])
            for sec in group[1:]:
                if sec.file_path:
                    loc_entry = {
                        "physicalLocation": {
                            "artifactLocation": {"uri": sec.file_path.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                        },
                        "message": {
                            "text": f"Secondary occurrence in cluster '{key}' at line {sec.line_number or 1}",
                        },
                    }
                    if sec.line_number:
                        loc_entry["physicalLocation"]["region"] = {"startLine": sec.line_number, "startColumn": 1}
                    rel_locs.append(loc_entry)
            primary.related_locations = rel_locs

        deduplicated.append(primary)

    return deduplicated


class CoverageDimension(BaseModel):
    name: str
    value_pct: Optional[float] = None
    numerator: Optional[int] = None
    denominator: Optional[int] = None
    unit: str = "files"
    is_available: bool = True
    explanation: str


class CoverageReport(BaseModel):
    dimensions: List[CoverageDimension] = Field(default_factory=list)
    summary_notes: List[str] = Field(default_factory=list)


class ToolManifestItem(BaseModel):
    name: str
    version: str
    path: Optional[str] = None
    category: str
    is_available: bool = True
    checksum: Optional[str] = None
    notes: Optional[str] = None


class RepositoryInventorySummary(BaseModel):
    total_files: int = 0
    analyzed_count: int = 0
    excluded_count: int = 0
    generated_count: int = 0
    binary_count: int = 0
    unsupported_count: int = 0
    failed_to_inspect_count: int = 0
    languages: Dict[str, int] = Field(default_factory=dict)
    frameworks: List[str] = Field(default_factory=list)
    build_systems: List[str] = Field(default_factory=list)
    package_managers: List[str] = Field(default_factory=list)
    entry_points: List[str] = Field(default_factory=list)
    test_files_count: int = 0


# --- New Feature Data Models ---

class SBOMComponent(BaseModel):
    name: str
    version: str
    ecosystem: str  # npm, pypi, cargo, maven, composer, etc.
    license: Optional[str] = None
    purl: Optional[str] = None
    source_file: str
    direct: bool = True
    is_approximate_range: bool = False


class SBOMReport(BaseModel):
    spec_version: str = "CycloneDX-1.5"
    total_dependencies: int = 0
    direct_dependencies: int = 0
    ecosystems: List[str] = Field(default_factory=list)
    components: List[SBOMComponent] = Field(default_factory=list)


class RBACPermissionRecord(BaseModel):
    endpoint: str
    method: str = "GET"
    auth_required: bool = False
    required_roles: List[str] = Field(default_factory=list)
    file_path: str
    line_number: Optional[int] = None
    file_sha256: Optional[str] = None
    derived_guard_syntax: Optional[str] = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED


class RBACMatrix(BaseModel):
    roles: List[str] = Field(default_factory=lambda: ["Anonymous", "Authenticated", "Admin"])
    endpoints_count: int = 0
    permissions: List[RBACPermissionRecord] = Field(default_factory=list)
    role_to_endpoints_map: Dict[str, List[str]] = Field(default_factory=dict)


class OpenAPISpecRecord(BaseModel):
    openapi_version: str = "3.1.0"
    title: str = "Inferred Application API"
    version: str = "1.0.0"
    paths_count: int = 0
    paths: Dict[str, Any] = Field(default_factory=dict)
    is_valid: bool = True


class QuarantinedTestRecord(BaseModel):
    test_identifier: str
    total_runs: int = 3
    passed_runs: int = 0
    failed_runs: int = 0
    is_flaky: bool = False
    durations_sec: List[float] = Field(default_factory=list)
    variance_sec: float = 0.0
    failure_messages: List[str] = Field(default_factory=list)


class FlakinessReport(BaseModel):
    enabled: bool = False
    tested_count: int = 0
    deterministic_passed_count: int = 0
    deterministic_failed_count: int = 0
    quarantined_flaky_count: int = 0
    quarantined_tests: List[QuarantinedTestRecord] = Field(default_factory=list)


class BranchConditionRecord(BaseModel):
    file_path: str
    function_name: Optional[str] = None
    line_number: int
    condition_expr: str
    predicate_type: str = "comparison"  # comparison, null_check, membership, boolean
    suggested_inputs: List[Dict[str, Any]] = Field(default_factory=list)


class GeneratedTestCase(BaseModel):
    test_id: str
    target_file: str
    target_branch_line: int
    test_type: str  # boundary, null_check, negative_auth, type_check
    description: str
    test_code: str
    validation_status: str = "synthesized, unverified"  # synthesized, unverified; synthesized, healed; failed_syntax
    heal_iterations: int = 0
    heal_diff: Optional[str] = None
    oracle_type: str = "predicate_reachability"


class GeneratedTestSuite(BaseModel):
    total_generated: int = 0
    verified_count: int = 0
    repaired_count: int = 0
    healed_count: int = 0
    target_branches_covered: int = 0
    test_cases: List[GeneratedTestCase] = Field(default_factory=list)
    suite_file_path: Optional[str] = None
    heal_diffs: List[str] = Field(default_factory=list)
    mutation_score_pct: Optional[float] = None
    compile_rate_pct: Optional[float] = None


class RunContext(BaseModel):
    schema_version: str = "1.1.0"
    run_id: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    repo_path: str
    repo_name: str
    commit_hash: Optional[str] = None
    working_tree_clean: bool = True
    remotes: List[str] = Field(default_factory=list)
    active_branch: Optional[str] = None
    comparison_base: Optional[str] = None
    selected_branches: List[str] = Field(default_factory=list)
    platform: str
    python_version: str
    offline_enforced: bool = True
    network_isolation_mode: str = "environment_level_best_effort"
    allow_scripts: bool = False
    accept_no_kernel_isolation: bool = False
    kernel_isolation_active: bool = False
    
    tools_manifest: List[ToolManifestItem] = Field(default_factory=list)
    inventory_summary: RepositoryInventorySummary = Field(default_factory=RepositoryInventorySummary)
    files: List[FileRecord] = Field(default_factory=list)
    routes: List[RouteRecord] = Field(default_factory=list)
    apis: List[APIRecord] = Field(default_factory=list)
    features: List[FeatureRecord] = Field(default_factory=list)
    workflows: List[WorkflowRecord] = Field(default_factory=list)
    integrations: List[IntegrationRecord] = Field(default_factory=list)
    branches: List[BranchRecord] = Field(default_factory=list)
    branch_diffs: List[BranchDiffRecord] = Field(default_factory=list)
    check_results: List[CheckResult] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    coverage: CoverageReport = Field(default_factory=CoverageReport)
    limitations: List[str] = Field(default_factory=list)
    execution_assumptions: List[str] = Field(default_factory=list)

    # Extended features
    sbom: SBOMReport = Field(default_factory=SBOMReport)
    rbac_matrix: RBACMatrix = Field(default_factory=RBACMatrix)
    openapi_spec: OpenAPISpecRecord = Field(default_factory=OpenAPISpecRecord)
    flakiness: FlakinessReport = Field(default_factory=FlakinessReport)
    generated_test_suite: GeneratedTestSuite = Field(default_factory=GeneratedTestSuite)
