"""Versioned wire authority. Target files are data, never imported or executed."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "claim-auditor/1"
POLICY_VERSION = "declared-static/1"
TOOL_VERSION = "0.1.0"
ClaimKind: TypeAlias = Literal[
    "path_exists", "symbol_declared", "config_literal", "dependency_declared",
    "metadata_declared", "cli_entry_declared", "env_reference", "bounded_code_fact",
    "behavioral", "operational", "marketing", "other",
]
Verdict: TypeAlias = Literal["verified", "partial", "missing", "unknown"]
Relation: TypeAlias = Literal["supports", "contradicts", "mixed", "no_evidence"]
Scalar: TypeAlias = str | int | float | bool | None
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: object) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    def encode_model(item: object) -> object:
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json")
        raise TypeError(f"unsupported canonical JSON type: {type(item).__name__}")
    return json.dumps(value, default=encode_model, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def stable_id(namespace: str, *parts: object) -> str:
    return f"{namespace}:{sha256(canonical_json(list(parts)))}"


def validate_relative_path(value: str) -> str:
    """Portable ordinary-file path; platform-specific link checks are separate."""
    if not value or "\\" in value or "\x00" in value or value.startswith("/"):
        raise ValueError("path must be nonempty portable relative path")
    pieces = value.split("/")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    for piece in pieces:
        if piece in {"", ".", ".."} or any(ord(c) < 32 for c in piece):
            raise ValueError("unsafe path component")
        if any(c in '<>:"|?*' for c in piece) or piece.endswith((" ", ".")):
            raise ValueError("nonportable path component")
        if piece.split(".", 1)[0].upper() in reserved:
            raise ValueError("reserved path component")
    return value


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


class Limits(WireModel):
    version: str = "limits/1"
    max_entries: int = 5000
    max_total_bytes: int = 20 * 1024 * 1024
    max_file_bytes: int = 512 * 1024
    max_readme_bytes: int = 128 * 1024
    max_atoms: int = 200
    max_lines: int = 10000
    max_line_bytes: int = 16 * 1024
    audit_seconds: int = 120
    parser_seconds: int = 30
    parser_memory_bytes: int = 512 * 1024 * 1024


class SnapshotEntry(WireModel):
    """One tracked path. `sha256` is the raw-bytes digest whenever the bytes were read.

    An entry excluded with gap reason `file_byte_limit` is never read beyond the per-file cap,
    so its `sha256` is instead the unread-marker digest from `snapshot.unread_entry_digest`
    (canonical JSON of reason, declared size and Git object ID or null), never a content digest.
    `size` is then the declared full size. Excluded entries never support evidence or absence.
    """

    path: str
    sha256: Digest
    size: int = Field(ge=0)
    mode: str
    status: Literal["included", "excluded", "unavailable"]

    _path = field_validator("path")(validate_relative_path)


class ScopeGap(WireModel):
    path: str | None
    reason: str


class Snapshot(WireModel):
    schema_version: Literal["claim-auditor/1"] = SCHEMA_VERSION
    policy_version: Literal["declared-static/1"] = POLICY_VERSION
    snapshot_id: str
    source_kind: Literal["git_commit", "fixture_inventory"]
    source_identity: str
    commit: str | None
    hash_algorithm: Literal["sha1", "sha256"] | None
    tree_identity: str
    content_digest: Digest
    manifest_digest: Digest
    entries: list[SnapshotEntry]
    exclusions: list[ScopeGap]
    complete: bool
    scope_id: str

    @model_validator(mode="after")
    def identities(self) -> Snapshot:
        paths = [entry.path for entry in self.entries]
        if paths != sorted(paths) or len({p.casefold() for p in paths}) != len(paths):
            raise ValueError("snapshot entries must be sorted and casefold-unique")
        if self.source_kind == "git_commit":
            size = {"sha1": 40, "sha256": 64}.get(self.hash_algorithm or "")
            if not size or not self.commit or not re.fullmatch(rf"[a-f0-9]{{{size}}}", self.commit):
                raise ValueError("git snapshot requires full lowercase object identity")
        elif self.commit is not None or self.hash_algorithm is not None:
            raise ValueError("fixture identity must not impersonate Git revision")
        if self.complete and (self.exclusions or any(e.status != "included" for e in self.entries)):
            raise ValueError("complete snapshot cannot contain unavailable scope")
        return self


class Span(WireModel):
    snapshot_id: str
    file_sha256: Digest
    path: str
    start_byte: int = Field(ge=0)
    end_byte: int = Field(ge=0)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    quote: str
    quote_sha256: Digest

    _path = field_validator("path")(validate_relative_path)

    @model_validator(mode="after")
    def byte_bounds(self) -> Span:
        if self.end_byte < self.start_byte or self.end_line < self.start_line:
            raise ValueError("reversed span")
        raw = self.quote.encode("utf-8")
        if len(raw) != self.end_byte - self.start_byte or sha256(raw) != self.quote_sha256:
            raise ValueError("quote bytes do not match span")
        return self


class Predicate(WireModel):
    predicate_id: str
    kind: ClaimKind
    subject: str
    module: str | None
    path: str | None
    key: str | None
    expected: Scalar
    negated: bool
    condition: str | None
    qualifiers: list[str]
    pattern: str | None


class Claim(WireModel):
    claim_id: str
    parent_id: str
    atom_ordinal: int = Field(ge=0)
    kind: ClaimKind
    normalized: str
    span: Span
    predicates: list[Predicate]
    extraction_method: str
    extraction_version: str
    uncertainty: list[str]


class InventoryBlock(WireModel):
    block_id: str
    block_kind: str
    span: Span
    claim_ids: list[str]
    status: Literal["extracted", "unsupported", "unparsed", "nonassertion"]
    reason: str | None


class PipelineError(WireModel):
    stage: str
    reason: str
    detail: str


class Inventory(WireModel):
    schema_version: Literal["claim-auditor/1"] = SCHEMA_VERSION
    snapshot_id: str
    readme_path: str
    readme_sha256: Digest
    claims: list[Claim]
    blocks: list[InventoryBlock]
    complete: bool
    errors: list[PipelineError]
    extraction_version: str


class CoverageReport(WireModel):
    coverage_id: str
    snapshot_id: str
    scope_id: str
    query: Predicate
    normalization: str
    examined_files: list[SnapshotEntry]
    parse_failures: list[ScopeGap]
    exclusions: list[ScopeGap]
    dynamic_flags: list[str]
    matched_count: int = Field(ge=0)
    near_misses: list[str]
    complete: bool
    parser_version: str
    index_version: str
    pattern_version: str
    artifact_digest: Digest


class Evidence(WireModel):
    evidence_id: str
    kind: Literal["positive", "contrary", "negative"]
    span: Span | None
    coverage_id: str | None
    query: Predicate
    scope_id: str
    parser_version: str
    index_version: str
    pattern_version: str

    @model_validator(mode="after")
    def evidence_shape(self) -> Evidence:
        if self.kind == "negative":
            if self.coverage_id is None or self.span is not None:
                raise ValueError("negative evidence requires coverage and no span")
        elif self.span is None:
            raise ValueError("positive/contrary evidence requires span")
        return self


class PredicateResult(WireModel):
    predicate_id: str
    state: Literal["established", "absent", "contradicted", "unknown"]
    reason: str
    evidence: list[Evidence]
    coverage: list[CoverageReport]
    complete: bool


class Finding(WireModel):
    # `model_proposal` is a wire field; opt out of pydantic's protected `model_` namespace (merged with WireModel config).
    model_config = ConfigDict(protected_namespaces=())

    claim: Claim
    verdict: Verdict
    support_relation: Relation
    reason: str
    supported_predicate_ids: list[str]
    unresolved_predicate_ids: list[str]
    accused_predicate_ids: list[str]
    evidence_ids: list[str]
    complete: bool
    citation_validation: Literal["valid", "not_applicable", "failed"]
    model_proposal: str | None


class Attempt(WireModel):
    attempt_id: str
    mode: Literal["rules", "replay", "live"]
    provider: str | None
    model: str | None
    input_digest: Digest
    prompt_digest: Digest | None
    policy_version: str
    status: str
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: float | None
    elapsed_seconds: float | None
    error: str | None


class ProvenanceIdentity(WireModel):
    value: str | None
    basis: Literal["observed", "owner_declared", "unknown"]
    source: str

    @model_validator(mode="after")
    def classification(self) -> ProvenanceIdentity:
        if not self.source.strip():
            raise ValueError("provenance source/explanation must be explicit")
        if (self.value is None) != (self.basis == "unknown"):
            raise ValueError("null provenance value iff unknown")
        if self.value is not None and not self.value.strip():
            raise ValueError("known provenance value must be nonblank")
        return self


class RunDeclarations(WireModel):
    owner_id: str
    tool_revision: str | None
    workflow_revision: str | None
    workflow_run_url: str | None
    trigger_revision: str | None
    trigger_kind: str | None

    @model_validator(mode="after")
    def explicit_declarations(self) -> RunDeclarations:
        if not self.owner_id.strip() or any(value is not None and not value.strip() for value in (
                self.tool_revision, self.workflow_revision, self.workflow_run_url, self.trigger_revision, self.trigger_kind)):
            raise ValueError("declaration owner and supplied values must be explicit/nonblank")
        return self


class RunContext(WireModel):
    context_version: Literal["run-context/1"]
    context_id: str
    run_id: str
    started_at: str
    snapshot_id: str
    snapshot_manifest_digest: Digest
    tool_version: str
    tool_code: ProvenanceIdentity
    python_version: ProvenanceIdentity
    python_implementation: ProvenanceIdentity
    dependencies: dict[str, ProvenanceIdentity]
    mode: Literal["rules", "replay", "live"]
    provider: ProvenanceIdentity
    model: ProvenanceIdentity
    prompt_digest: ProvenanceIdentity
    packet_digest: ProvenanceIdentity
    tool_revision: ProvenanceIdentity
    workflow_revision: ProvenanceIdentity
    workflow_run_url: ProvenanceIdentity
    trigger_revision: ProvenanceIdentity
    trigger_kind: ProvenanceIdentity

    @model_validator(mode="after")
    def identity_and_date(self) -> RunContext:
        from datetime import datetime

        if not all(value.strip() for value in (self.context_id, self.run_id, self.snapshot_id, self.tool_version)):
            raise ValueError("run context identities/version must be explicit")
        if datetime.fromisoformat(self.started_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("run start must be timezone aware")
        if any(not key.strip() for key in self.dependencies):
            raise ValueError("dependency names must be explicit")
        return self


class RunManifest(WireModel):
    schema_version: Literal["claim-auditor/1"] = SCHEMA_VERSION
    policy_version: Literal["declared-static/1"] = POLICY_VERSION
    run_id: str
    tool_version: str
    dependencies: dict[str, str]
    snapshot_id: str
    snapshot_manifest_digest: Digest
    mode: Literal["rules", "replay", "live"]
    provider: str | None
    model: str | None
    prompt_digest: Digest | None
    packet_digest: Digest | None
    started_at: str
    completed_at: str | None
    state: Literal["created", "input_validated", "inventoried", "resolved", "citations_validated", "complete", "incomplete", "failed_integrity", "failed_input"]
    limits: Limits
    attempts: list[Attempt]
    errors: list[PipelineError]
    report_hashes: dict[str, Digest]
    source_revision: str | None
    workflow_revision: str | None
    workflow_run_url: str | None
    runtime_validation: Literal["unverified"] = "unverified"
    run_context: RunContext | None = None
    context_digest: Digest | None = None


class AuditReport(WireModel):
    schema_version: Literal["claim-auditor/1"] = SCHEMA_VERSION
    policy_version: Literal["declared-static/1"] = POLICY_VERSION
    snapshot: Snapshot
    inventory: Inventory
    findings: list[Finding]
    evidence: list[Evidence]
    coverage: list[CoverageReport]
    errors: list[PipelineError]
    mode: Literal["rules", "replay", "live"]
    evaluation_status: str
    run_context: RunContext | None = None


class ReplayEnvelope(WireModel):
    schema_version: Literal["claim-auditor/1"] = SCHEMA_VERSION
    policy_version: str
    input_digest: Digest
    prompt_digest: Digest
    model: str
    claims: list[Claim]
    claims_digest: Digest


class Reservation(WireModel):
    reservation_id: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_usd: float = Field(ge=0)
    seconds: float = Field(ge=0)
    reserved_at: float


class BudgetState(WireModel):
    remaining_input_tokens: int = Field(ge=0)
    remaining_output_tokens: int = Field(ge=0)
    remaining_cost_usd: float = Field(ge=0)
    remaining_seconds: float = Field(ge=0)
    pending: Reservation | None
    unknown_settlement: bool


class EvaluationLock(WireModel):
    schema_version: Literal["claim-auditor/1"] = SCHEMA_VERSION
    protocol_id: str
    admitted: bool
    admitted_by: str | None
    admitted_at: str | None
    code_digest: Digest
    taxonomy_version: str
    matcher_version: str
    packet_version: str
    arm_names: list[str]
    provider_models: dict[str, str]
    source_seal_digest: Digest
    gold_seal_digest: Digest
    source_rights_receipt: str
    custody_receipt: str
    heldout_accessed: bool
    max_input_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
    max_remote_seconds: int = Field(gt=0)
    max_cost_usd: float | None


class GoldAtom(WireModel):
    gold_id: str
    family_id: str
    claim: Claim
    verdict: Verdict
    support_relation: Relation
    answerable: bool
    supported_predicate_ids: list[str]
    unresolved_predicate_ids: list[str]
    accused_predicate_ids: list[str]
    annotator_type: Literal["agent", "human"]
    annotator_id: str
    rationale: str
    adjudicated_at: str | None
    disagreements: list[str]


class PredictionRow(WireModel):
    prediction_id: str
    family_id: str
    finding: Finding | None
    accused_predicate_ids: list[str]
    status: Literal["prediction", "invalid_output", "abstention_screened", "input_too_large", "citation_failure", "execution_failure"]
    error: str | None


class ScoredItem(WireModel):
    gold_id: str | None
    prediction_id: str | None
    family_id: str
    status: str
    expected: str | None
    actual: str | None


class BootstrapInterval(WireModel):
    metric: str
    low: float | None
    high: float | None
    families: int = Field(ge=0)
    resamples: int = Field(ge=0)
    seed: int
    status: Literal["exploratory", "inconclusive"]


class AttemptSummary(WireModel):
    attempts: int = Field(ge=0)
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: float | None
    reported_known_cost_usd: float = Field(ge=0)
    known_cost_attempts: int = Field(ge=0)
    unknown_cost_attempts: int = Field(ge=0)
    median_seconds: float | None
    p95_seconds: float | None
    unknown_latency_attempts: int = Field(ge=0)
    mode_counts: dict[str, int]


class EvaluationResult(WireModel):
    schema_version: Literal["claim-auditor/1"] = SCHEMA_VERSION
    matcher_version: str
    human_adjudicated: bool
    comparative_complete: bool
    counts: dict[str, int]
    metrics: dict[str, float | None]
    confusion: dict[str, dict[str, int]]
    items: list[ScoredItem]
    intervals: dict[str, BootstrapInterval]
    attempt_summary: AttemptSummary | None
    limitations: list[str]


class PacketBaseline(WireModel):
    mode: Literal["packet_grep"]
    packet_digest: Digest
    predictions: list[PredictionRow]
    evidence: list[Evidence]
    limitations: list[str]


class PacketExcerpt(WireModel):
    path: str
    start_byte: int = Field(ge=0)
    end_byte: int = Field(ge=0)
    file_sha256: Digest
    quote: str
    anchor: str

    _path = field_validator("path")(validate_relative_path)


class EvaluationPacket(WireModel):
    schema_version: Literal["claim-auditor/1"] = SCHEMA_VERSION
    packet_version: str
    snapshot_id: str
    snapshot_manifest_digest: Digest
    readme_path: str
    readme_sha256: Digest
    readme_text: str
    excerpts: list[PacketExcerpt]
    scope_entries: list[SnapshotEntry]
    exclusions: list[ScopeGap]
    candidate_count: int = Field(ge=0)
    omitted_count: int = Field(ge=0)
    complete: bool
    absence_certificates: bool
    packet_digest: Digest


class EvaluationPreparation(WireModel):
    schema_version: Literal["claim-auditor/1"] = SCHEMA_VERSION
    protocol_id: str
    packet_digest: Digest
    mode: Literal["prepared_only"]
    arm_status: dict[str, str]
    comparative_complete: bool
    human_adjudicated: bool
    source_only: bool
    limitations: list[str]


class AuditError(Exception):
    """Expected input/integrity/runtime-limit failure with stable CLI exit."""

    def __init__(self, reason: str, detail: str, exit_code: int = 2) -> None:
        self.reason = reason
        self.detail = detail
        self.exit_code = exit_code
        super().__init__(f"{reason}: {detail}")


# Sole run-state -> CLI exit table (audit and verify-report). Non-terminal crashed states are incomplete.
RUN_STATE_EXIT = {"complete": 0, "failed_input": 2, "incomplete": 3, "failed_integrity": 4}


def exit_for_state(state: str) -> int:
    return RUN_STATE_EXIT.get(state, 3)


# Refusal code for verifying a non-complete run: one code, one exit, keyed beside RUN_STATE_EXIT.
RUN_STATE_REFUSAL = {"failed_input": "run_failed_input", "failed_integrity": "run_failed_integrity"}


def refusal_for_state(state: str) -> tuple[str, int]:
    return RUN_STATE_REFUSAL.get(state, "run_incomplete"), exit_for_state(state)


class ProviderCaps(WireModel):
    """Shared per-packet ceilings and worst-case liability per physical attempt."""

    total_input_tokens: int = Field(gt=0, le=32000)
    total_output_tokens: int = Field(gt=0, le=8000)
    total_seconds: float = Field(gt=0, le=60)
    total_cost_usd: float = Field(ge=0)
    request_input_tokens: int = Field(gt=0)
    request_output_tokens: int = Field(gt=0)
    request_seconds: float = Field(gt=0, le=30)
    request_cost_usd: float = Field(ge=0)
    max_logical_requests: int = Field(ge=1, le=2)
    max_retries: int = Field(ge=0, le=1)

    @model_validator(mode="after")
    def liabilities(self) -> ProviderCaps:
        if (self.request_input_tokens > self.total_input_tokens
                or self.request_output_tokens > self.total_output_tokens
                or self.request_seconds > self.total_seconds
                or self.request_cost_usd > self.total_cost_usd):
            raise ValueError("attempt liability exceeds shared cap")
        return self


class AnnotationRuling(WireModel):
    ruling_id: str
    source_manifest_digest: Digest
    claim_digest: Digest
    evidence_digest: Digest
    atom: GoldAtom
    recorded_at: str
    supersedes_ruling_id: str | None
    human_action_id: str | None

    @model_validator(mode="after")
    def identities(self) -> AnnotationRuling:
        from datetime import datetime

        if sha256(canonical_json(self.atom.claim)) != self.claim_digest:
            raise ValueError("ruling claim digest differs from exact atom claim")
        if self.atom.annotator_type == "agent" and self.human_action_id is not None:
            raise ValueError("agent ruling cannot carry a human action")
        if self.atom.annotator_type == "human" and not (self.human_action_id or "").strip():
            raise ValueError("human ruling requires explicit human action identity")
        if not self.atom.annotator_id.strip() or not self.atom.rationale.strip():
            raise ValueError("ruling requires annotator identity and rationale")
        if datetime.fromisoformat(self.recorded_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("ruling timestamp must be timezone aware")
        if self.supersedes_ruling_id == self.ruling_id:
            raise ValueError("ruling cannot supersede itself")
        return self


class ProviderRequest(WireModel):
    arm: Literal["extraction", "single_pass"]
    packet: EvaluationPacket
    input_digest: Digest
    prompt_digest: Digest
    model: str = Field(min_length=1, max_length=200)
    policy_version: Literal["declared-static/1"]
    caps: ProviderCaps


class ProviderProposal(WireModel):
    candidate_id: str
    claim: Claim
    relation: Relation | None
    evidence_spans: list[Span] = Field(max_length=200)


class SimulatedUsage(WireModel):
    """Fixture bookkeeping, never actual provider observations."""

    input_tokens: int | None = Field(ge=0)
    output_tokens: int | None = Field(ge=0)
    cost_usd: float | None = Field(ge=0)
    elapsed_seconds: float | None = Field(ge=0)


class ProviderFixture(WireModel):
    request_digest: Digest
    proposals: list[ProviderProposal] = Field(max_length=200)
    simulated_usage: SimulatedUsage
    error: str | None
    retryable: bool

    @model_validator(mode="after")
    def outcome(self) -> ProviderFixture:
        if self.error is None and self.retryable:
            raise ValueError("successful fixture cannot request retry")
        if self.error is not None and self.proposals:
            raise ValueError("failed fixture cannot carry proposals")
        return self


class ProviderResponse(WireModel):
    request_digest: Digest
    status: Literal["proposed", "abstention_screened", "invalid_output", "execution_failure", "incomplete"]
    proposals: list[ProviderProposal]
    attempts: list[Attempt]
    simulated_usage: list[SimulatedUsage]
    error: str | None
    mode: Literal["fake", "replay"]
    comparative_complete: Literal[False]


class PairedRunConfig(WireModel):
    """Local input configuration, never a measured output artifact."""

    mode: Literal["fake", "replay"]
    caps: ProviderCaps
    prompts: dict[str, Digest]
    models: dict[str, str]
    fixtures: dict[str, list[ProviderFixture]]
    replay_files: dict[str, list[str]]
    include_full_index: bool

    @model_validator(mode="after")
    def arm_keys(self) -> PairedRunConfig:
        keys = {"extraction", "single_pass"}
        if set(self.prompts) != keys or set(self.models) != keys:
            raise ValueError("exact extraction and single_pass identities required")
        if any(not model.strip() for model in self.models.values()):
            raise ValueError("explicit model labels required")
        if self.mode == "fake":
            if set(self.fixtures) != keys or self.replay_files:
                raise ValueError("fake config requires only both fixture arms")
            values = self.fixtures.values()
        else:
            if set(self.replay_files) != keys or self.fixtures:
                raise ValueError("replay config requires only both replay-file arms")
            for paths in self.replay_files.values():
                for path in paths:
                    validate_relative_path(path)
            values = self.replay_files.values()
        if any(not 1 <= len(items) <= 2 for items in values):
            raise ValueError("supply one or two explicit attempt fixtures per arm")
        return self


class LiveEvidencePointer(WireModel):
    path: str
    start_byte: int = Field(ge=0)
    end_byte: int = Field(gt=0)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    quote: str = Field(min_length=1, max_length=1024)

    _path = field_validator("path")(validate_relative_path)


class LiveAtomProposal(WireModel):
    start_byte: int = Field(ge=0)
    end_byte: int = Field(gt=0)
    quote: str = Field(min_length=1, max_length=131072)
    kind: ClaimKind
    relation: Relation | None
    evidence: list[LiveEvidencePointer] = Field(max_length=200)


class LiveProposalPayload(WireModel):
    """Model supplies coordinates/content, never authoritative IDs or verdicts."""

    atoms: list[LiveAtomProposal] = Field(max_length=200)


class LiveAuthorization(WireModel):
    enabled: bool
    authorization_id: str = Field(min_length=1)
    authorized_by: str = Field(min_length=1)
    expires_at: str
    provider: Literal["openai_compatible", "anthropic"]
    endpoint: str
    request_digest: Digest
    payload_digest: Digest
    snapshot_manifest_digest: Digest
    allowed_paths: list[str]
    input_token_upper_bound: int = Field(gt=0)
    tokenizer_receipt: str = Field(min_length=1)
    worst_case_cost_receipt: str = Field(min_length=1)
    max_request_bytes: int = Field(gt=0, le=1024 * 1024)
    max_response_bytes: int = Field(gt=0, le=2 * 1024 * 1024)
    anthropic_version: str | None

    @field_validator("allowed_paths")
    @classmethod
    def paths(cls, value: list[str]) -> list[str]:
        if not value or len(value) != len(set(value)):
            raise ValueError("authorized scope must be explicit and unique")
        for path in value:
            validate_relative_path(path)
        return value


class DatedRateCard(WireModel):
    rate_card_id: str
    provider: Literal["openai_compatible", "anthropic"]
    resolved_model: str
    valid_from: str
    valid_until: str
    currency: Literal["USD"]
    units: Literal["USD_per_million_tokens"]
    usage_semantics: Literal["openai-chat-inclusive/1", "anthropic-cache-split/1"]
    service_tier: Literal["standard"]
    rates: dict[str, Annotated[str, Field(pattern=r"^[0-9]{1,12}(?:\.[0-9]{1,12})?$")]]
    source_reference: str
    admitted: bool
    admitted_by: str | None
    admitted_at: str | None
    admission_receipt: str | None
    card_digest: Digest

    @model_validator(mode="after")
    def admission(self) -> DatedRateCard:
        from datetime import datetime

        if not all(value.strip() for value in (self.rate_card_id, self.resolved_model, self.source_reference)):
            raise ValueError("rate identity/model/source reference required")
        first = datetime.fromisoformat(self.valid_from.replace("Z", "+00:00"))
        last = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
        if first.tzinfo is None or last.tzinfo is None or first >= last:
            raise ValueError("rate validity must be a nonempty aware interval")
        if self.admitted:
            if not (self.admitted_by or "").strip() or not (self.admission_receipt or "").strip() or self.admitted_at is None:
                raise ValueError("admitted rates require actual owner/date/receipt references")
            if datetime.fromisoformat(self.admitted_at.replace("Z", "+00:00")).tzinfo is None:
                raise ValueError("rate admission date must be timezone aware")
        elif any(value is not None for value in (self.admitted_by, self.admitted_at, self.admission_receipt)):
            raise ValueError("unadmitted card must not invent owner admission")
        return self


class CostResult(WireModel):
    status: Literal["derived", "unknown"]
    purpose: Literal["usage", "liability"]
    provider: Literal["openai_compatible", "anthropic"]
    resolved_model: str | None
    rate_card_id: str | None
    rate_card_digest: Digest | None
    usage_digest: Digest
    priced_at: str
    service_tier: str | None
    currency: Literal["USD"] | None
    input_tokens: int | None = Field(ge=0)
    output_tokens: int | None = Field(ge=0)
    categories: dict[str, int]
    amount_decimal: str | None
    amount_usd: float | None = Field(ge=0)
    method: Literal["decimal64-ceil-usd-1e-12/1"]
    error: str | None

    @model_validator(mode="after")
    def known_cost(self) -> CostResult:
        from datetime import datetime

        if datetime.fromisoformat(self.priced_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("pricing time must be timezone aware")
        if any(value < 0 for value in self.categories.values()):
            raise ValueError("negative token categories")
        values = (self.resolved_model, self.rate_card_id, self.rate_card_digest, self.currency,
                  self.input_tokens, self.output_tokens, self.amount_decimal, self.amount_usd)
        if self.status == "derived" and (any(value is None for value in values) or self.error is not None):
            raise ValueError("derived cost requires complete explicit observations and rate identity")
        if self.status == "unknown" and (self.amount_decimal is not None or self.amount_usd is not None or self.error is None):
            raise ValueError("unknown cost must stay null with an explicit reason")
        return self


class SettlementContext(WireModel):
    authorization_id: str
    reservation_id: str
    attempt_id: str
    request_digest: Digest
    payload_digest: Digest
    response_digest: Digest
    provider: Literal["openai_compatible", "anthropic"]
    requested_model: str
    resolved_model: str | None
    response_id: str | None
    origin: Literal["provider_reported", "fixture"]
    raw_usage: object
    service_tier: str | None
    requested_at: str
    pricing: CostResult


class SettlementObservation(WireModel):
    context_digest: Digest
    provider: Literal["openai_compatible", "anthropic"]
    resolved_model: str
    response_id: str
    rate_card_digest: Digest
    usage_digest: Digest
    basis: Literal["rate_card_derived", "provider_bill"]
    amount_decimal: Annotated[str, Field(pattern=r"^[0-9]{1,12}(?:\.[0-9]{1,12})?$")]
    cost_usd: float = Field(ge=0)
    receipt_kind: Literal["derived_calculation", "provider_bill"]
    receipt_reference: str
    observer_id: str
    observed_at: str

    @model_validator(mode="after")
    def attribution(self) -> SettlementObservation:
        from datetime import datetime

        if not all(value.strip() for value in (self.resolved_model, self.response_id, self.receipt_reference, self.observer_id)):
            raise ValueError("actual response/observer/provenance identities required")
        if self.receipt_kind != ("derived_calculation" if self.basis == "rate_card_derived" else "provider_bill"):
            raise ValueError("derived calculation must never impersonate a provider bill")
        if datetime.fromisoformat(self.observed_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("settlement observation date must be timezone aware")
        return self


class LiveUsage(WireModel):
    origin: Literal["provider_reported", "fixture"]
    resolved_model: str | None
    response_id: str | None
    input_tokens: int | None = Field(ge=0)
    output_tokens: int | None = Field(ge=0)
    cost_usd: float | None = Field(ge=0)
    cost_receipt: str | None
    elapsed_seconds: float | None = Field(ge=0)
    raw_usage: object
    cost_basis: Literal["unknown", "rate_card_derived", "provider_bill", "fixture"]
    reported_bill_usd: float | None = Field(ge=0)
    pricing: CostResult | None
    settlement_context: SettlementContext | None
    settlement_observation: SettlementObservation | None
    cost_error: str | None


class ReservationReconciliation(WireModel):
    reconciliation_id: str
    reservation_id: str
    budget_state_digest: Digest
    usage: LiveUsage
    usage_receipt: str
    pricing_receipt: str
    usage_receipt_digest: Digest
    pricing_receipt_digest: Digest
    owner_id: str
    recorded_at: str
    rationale: str

    @model_validator(mode="after")
    def explicit_owner_action(self) -> ReservationReconciliation:
        from datetime import datetime

        if not all(value.strip() for value in (self.reconciliation_id, self.reservation_id, self.usage_receipt,
                                               self.pricing_receipt, self.owner_id, self.rationale)):
            raise ValueError("explicit owner reconciliation identity/actual receipt references required")
        if datetime.fromisoformat(self.recorded_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("owner reconciliation date must be timezone aware")
        return self


class ProviderBillReceipt(WireModel):
    basis: Literal["owner_supplied_provider_bill"]
    provider: Literal["openai_compatible", "anthropic"]
    resolved_model: str
    response_id: str
    currency: Literal["USD"]
    amount_decimal: Annotated[str, Field(pattern=r"^[0-9]{1,12}(?:\.[0-9]{1,12})?$")]
    receipt_reference: str
    issued_at: str
    source_reference: str

    @model_validator(mode="after")
    def explicit_bill_capture(self) -> ProviderBillReceipt:
        from datetime import datetime

        if not all(value.strip() for value in (self.resolved_model, self.response_id, self.receipt_reference, self.source_reference)):
            raise ValueError("actual supplied bill identities/source references required")
        if datetime.fromisoformat(self.issued_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("bill issue time must be timezone aware")
        return self


class LiveBudgetAdmission(WireModel):
    admission_id: str
    owner_id: str
    admitted_at: str
    protocol_digest: Digest
    packet_digest: Digest
    ledger_root_identity: Digest
    caps_digest: Digest
    authorization_ids: dict[str, str]
    liability_scope: Literal["per_role_equal_caps"]
    receipt_reference: str

    @model_validator(mode="after")
    def actor(self) -> LiveBudgetAdmission:
        from datetime import datetime

        if not all(value.strip() for value in (self.admission_id, self.owner_id, self.receipt_reference)):
            raise ValueError("explicit actual owner budget admission references required")
        if set(self.authorization_ids) != {"extraction", "single_pass"} or any(not value.strip() for value in self.authorization_ids.values()):
            raise ValueError("both authorization bindings required for durable root admission")
        if datetime.fromisoformat(self.admitted_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("budget admission date must be timezone aware")
        return self


class LiveProviderResponse(WireModel):
    request_digest: Digest
    payload_digest: Digest
    authorization_id: str
    status: Literal["proposed", "abstention_screened", "invalid_output", "execution_failure", "incomplete"]
    proposals: list[ProviderProposal]
    attempts: list[Attempt]
    usage: list[LiveUsage]
    error: str | None
    mode: Literal["live", "fake"]
    comparative_complete: Literal[False]


class ManualAnnotation(WireModel):
    """Manual source inventory; service reopens bytes and confirms real actions."""

    annotation_id: str
    source_manifest_digest: Digest
    family_id: str
    inventory: Inventory
    parent_spans: list[Span]
    annotator_type: Literal["agent", "human"]
    annotator_id: str
    recorded_at: str
    action_id: str | None
    supersedes_annotation_id: str | None

    @model_validator(mode="after")
    def attribution(self) -> ManualAnnotation:
        from datetime import datetime

        if not all(value.strip() for value in (self.annotation_id, self.family_id, self.annotator_id)):
            raise ValueError("manual annotation and annotator identities must be explicit")
        if datetime.fromisoformat(self.recorded_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("manual annotation timestamp must be timezone aware")
        if self.annotator_type == "agent" and self.action_id is not None:
            raise ValueError("agent annotation cannot carry a human action")
        if self.annotator_type == "human" and not (self.action_id or "").strip():
            raise ValueError("human annotation requires explicit actual-action identity")
        if self.supersedes_annotation_id == self.annotation_id:
            raise ValueError("annotation cannot supersede itself")
        return self


class ManualExportConfig(WireModel):
    """Explicit operator selections; never labels, consensus or action evidence."""

    evidence_files: dict[str, str]
    ruling_ids: dict[str, str]
    operator_id: str | None
    action_id: str | None
    recorded_at: str | None
    adjudication_rationale: str | None

    @model_validator(mode="after")
    def selections(self) -> ManualExportConfig:
        from datetime import datetime

        if not self.ruling_ids or any(not key.strip() or not value.strip() for key, value in self.ruling_ids.items()):
            raise ValueError("explicit nonempty claim-to-ruling selections required")
        if any(not key.strip() for key in self.evidence_files):
            raise ValueError("evidence must be keyed by exact claim identity")
        for path in self.evidence_files.values():
            validate_relative_path(path)
        values = (self.operator_id, self.action_id, self.recorded_at, self.adjudication_rationale)
        if any(value is not None for value in values):
            if any(value is None or not value.strip() for value in values):
                raise ValueError("human export action fields must all be explicit or all null for proposals")
            assert self.recorded_at is not None
            if datetime.fromisoformat(self.recorded_at.replace("Z", "+00:00")).tzinfo is None:
                raise ValueError("export action timestamp must be timezone aware")
        return self


class LiveExperimentConfig(WireModel):
    """Nonsecret future owner configuration; does not itself activate anything."""

    caps: ProviderCaps
    system_prompts: dict[str, str]
    models: dict[str, str]
    authorizations: dict[str, LiveAuthorization]
    allowed_endpoints: dict[str, list[str]]
    rate_cards: dict[str, DatedRateCard]

    @model_validator(mode="after")
    def paired_roles(self) -> LiveExperimentConfig:
        roles = {"extraction", "single_pass"}
        for value in (self.system_prompts, self.models, self.authorizations, self.allowed_endpoints, self.rate_cards):
            if set(value) != roles:
                raise ValueError("exact extraction and single_pass owner configuration required")
        for role in roles:
            authorization = self.authorizations[role]
            if not self.models[role].strip() or not self.system_prompts[role].strip():
                raise ValueError("explicit model and trusted system prompt required")
            if len(self.system_prompts[role].encode("utf-8")) > 32 * 1024:
                raise ValueError("trusted prompt exceeds bounded configuration cap")
            endpoints = self.allowed_endpoints[role]
            if not endpoints or len(endpoints) != len(set(endpoints)) or authorization.endpoint not in endpoints:
                raise ValueError("authorization endpoint must be explicitly owner-allowlisted")
        return self


class DatasetCase(WireModel):
    case_id: str
    family_id: str
    ancestry_id: str
    snapshot_root: str
    snapshot_id: str
    snapshot_manifest_digest: Digest
    source_content_digest: Digest
    run_root: str
    run_manifest_digest: Digest
    gold_path: str
    gold_digest: Digest
    protocol_digest: Digest | None
    source_rights_receipt: str | None
    custody_receipt: str | None

    @model_validator(mode="after")
    def identities(self) -> DatasetCase:
        if not all(value.strip() for value in (self.case_id, self.family_id, self.ancestry_id,
                                               self.snapshot_root, self.snapshot_id, self.run_root, self.gold_path)):
            raise ValueError("dataset case/source/family/ancestry paths and identities must be explicit")
        if any(value is not None and not value.strip() for value in (self.source_rights_receipt, self.custody_receipt)):
            raise ValueError("optional dataset receipts must be explicit nonblank references or null")
        return self


class DatasetManifest(WireModel):
    dataset_id: str
    mode: Literal["dev_descriptive", "locked_evaluation"]
    admitted: bool
    admitted_by: str | None
    admitted_at: str | None
    protocol_id: str
    taxonomy_version: str
    matcher_version: str
    packet_version: str
    runner_version: str
    packet_fact_version: str
    parser_version: str
    code_digest: Digest
    required_arms: list[str]
    provider_models: dict[str, str]
    prompt_digests: dict[str, Digest]
    caps: ProviderCaps
    human_review_receipt: str | None
    cases: list[DatasetCase]

    @model_validator(mode="after")
    def identities(self) -> DatasetManifest:
        from datetime import datetime

        if not all(value.strip() for value in (self.dataset_id, self.protocol_id, self.taxonomy_version,
                                               self.matcher_version, self.packet_version, self.runner_version,
                                               self.packet_fact_version, self.parser_version)):
            raise ValueError("dataset identity and version fields must be explicit")
        if self.admitted:
            if not (self.admitted_by or "").strip() or self.admitted_at is None:
                raise ValueError("admitted dataset requires actual actor and aware date")
            if datetime.fromisoformat(self.admitted_at.replace("Z", "+00:00")).tzinfo is None:
                raise ValueError("dataset admission date must be timezone aware")
        elif self.admitted_by is not None or self.admitted_at is not None:
            raise ValueError("unadmitted dataset must not invent admission actor/date")
        if (not self.required_arms or len(self.required_arms) != len(set(self.required_arms))
                or any(not value.strip() for value in self.required_arms)):
            raise ValueError("dataset arms must be explicit, nonempty and unique")
        if any(not key.strip() or not value.strip() for key, value in self.provider_models.items()):
            raise ValueError("dataset provider model identities must be explicit")
        if any(not key.strip() for key in self.prompt_digests):
            raise ValueError("dataset prompt identities must be explicit")
        if not self.cases or len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("dataset case identities must be nonempty and unique")
        if self.human_review_receipt is not None and not self.human_review_receipt.strip():
            raise ValueError("human receipt must be an explicit reference or null")
        return self
