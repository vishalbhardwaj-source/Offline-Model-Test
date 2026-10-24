from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Confidence(str, Enum):
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
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    notes: Optional[str] = None


class APIRecord(BaseModel):
    endpoint: str
    method: str = "GET"
    handler: Optional[str] = None
    file_path: str
    line_number: Optional[int] = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    auth_required: Optional[bool] = None
    notes: Optional[str] = None


class FeatureRecord(BaseModel):
    name: str
    flag_key: Optional[str] = None
    file_path: str
    line_number: Optional[int] = None
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
    skip_or_blocked_reason: Optional[str] = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    branch: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    impact: str
    evidence: str
    suggested_action: str
    check_tool: Optional[str] = None


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
    validation_status: str = "verified"  # verified, repaired, failed_syntax


class GeneratedTestSuite(BaseModel):
    total_generated: int = 0
    verified_count: int = 0
    repaired_count: int = 0
    target_branches_covered: int = 0
    test_cases: List[GeneratedTestCase] = Field(default_factory=list)
    suite_file_path: Optional[str] = None


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
