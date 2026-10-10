"""Closed data-only Assurance contracts; no policy or authority is loaded here.

Only the existing schema validator's supported Draft 2020-12 vocabulary is
used. The checked-in and packaged schema copies must equal these definitions.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

MAX_BYTES = 1_048_576
MAX_DEPTH = 12
MAX_ITEMS = 256
MAX_TEXT = 4096


def text(maximum: int = MAX_TEXT, *, pattern: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "string",
        "minLength": 1,
        "maxLength": maximum,
        "pattern": pattern or r"^[^\x00-\x1f\x7f]+$",
    }
    return result


ID = text(128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")
DIGEST = text(64, pattern=r"^[a-f0-9]{64}$")
REVISION = text(128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")
BOOLEAN = {"type": "boolean"}
PROBABILITY = {"type": "number", "minimum": 0, "maximum": 1}
COUNT = {"type": "integer", "minimum": 0, "maximum": 1_000_000_000}
TIMESTAMP = {"type": "integer", "minimum": 0, "maximum": 2**53 - 1}
MILLISECONDS = {"type": "number", "minimum": 0, "maximum": 86_400_000}


def choice(*values: str) -> dict[str, Any]:
    return {"type": "string", "enum": list(values)}


def nullable(shape: dict[str, Any]) -> dict[str, Any]:
    return {"anyOf": [deepcopy(shape), {"type": "null"}]}


def array(shape: dict[str, Any], maximum: int = MAX_ITEMS) -> dict[str, Any]:
    return {"type": "array", "maxItems": maximum, "items": deepcopy(shape)}


def obj(**properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "required": list(properties),
        "properties": deepcopy(properties),
        "additionalProperties": False,
        "maxProperties": len(properties),
    }


def artifact(name: str, **properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://latentops.space/ordin/schemas/{name.replace('_', '-')}.v1.schema.json",
        "title": f"Ordin {name.replace('_', ' ')} v1",
        **obj(schema_version={"const": f"ordin.{name}.v1", "type": "string"}, **properties),
    }


SOURCE = obj(
    path=text(
        1024,
        pattern=r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))(?!.*(?:^|/)\.(?:/|$))"
        r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$",
    ),
    line={"type": "integer", "minimum": 1, "maximum": 10_000_000},
    revision=REVISION,
    content_digest=DIGEST,
    symbol=nullable(ID),
)
REPOSITORY = obj(id=ID, revision=REVISION)
ASSET = obj(
    id=ID,
    kind=choice("path", "tool", "credential", "endpoint", "policy"),
    value=text(),
    match=choice("exact", "prefix"),
)
BOUNDARY = obj(id=ID, source=ID, sink=ID)
EVIDENCE = obj(
    evidence_id=ID,
    origin=choice(
        "caller_asserted",
        "static_evidence",
        "imported_claim",
        "model_hypothesis",
        "deterministically_derived",
        "policy_verified",
        "runtime_backend_observed",
        "host_authenticated_source",
    ),
    source=nullable(SOURCE),
    action_digest=nullable(DIGEST),
    contract_id=nullable(ID),
    session_digest=nullable(DIGEST),
    proof_gaps=array(text(), 32),
)
SELECTORS = obj(
    kinds=array(ID, 32), effects=array(ID, 64), resource_ref=nullable(ID), principal=nullable(ID)
)
INVARIANT_FIELDS = dict(
    invariant_id=ID,
    kind=choice(
        "require_approval",
        "forbid_effect",
        "resource_subset",
        "network_request_subset",
        "credential_binding",
        "delegated_authority_subset",
        "source_flow_guard",
        "temporal_action_guard",
        "protected_policy_mutation",
    ),
    selectors=SELECTORS,
    on_violation=choice("escalate", "block"),
    severity=choice("low", "medium", "high", "critical"),
    mandatory=BOOLEAN,
    authority_ref=nullable(ID),
    provenance=array(EVIDENCE, 32),
)
INVARIANT = artifact("assurance_invariant", **INVARIANT_FIELDS)
PROFILE_FIELDS = dict(
    profile_id=ID,
    version=ID,
    repository=REPOSITORY,
    protected_assets=array(ASSET),
    trust_boundaries=array(BOUNDARY),
    invariants=array(INVARIANT),
    support_flags=array(ID, 32),
)
PROFILE = artifact("assurance_security_profile", **PROFILE_FIELDS)
DRAFT = artifact(
    "assurance_security_profile_draft",
    draft_id=ID,
    repository=REPOSITORY,
    generator=ID,
    protected_assets=array(ASSET),
    trust_boundaries=array(BOUNDARY),
    entry_points=array(SOURCE),
    risk_hypotheses=array(text()),
    source_evidence=array(SOURCE),
    unresolved_facts=array(text()),
    invariant_suggestions=array(INVARIANT),
    scan_digest=nullable(DIGEST),
    completeness=choice("complete", "partial", "unknown"),
    authoritative={"type": "boolean", "const": False},
)
EVALUATION = artifact(
    "assurance_invariant_evaluation",
    invariant_id=ID,
    status=choice("satisfied", "violated", "inconclusive", "unsupported"),
    reason_code=ID,
    matched_facts=array(ID, 64),
    unknowns=array(text(), 32),
    policy_digest=DIGEST,
    action_digest=DIGEST,
    contract_id=nullable(ID),
)
NODE = obj(
    node_id=ID,
    kind=choice(
        "principal",
        "source",
        "action",
        "tool_or_server",
        "resource",
        "capability",
        "boundary",
        "observation",
        "sink",
        "control",
    ),
    category=ID,
    value_digest=nullable(DIGEST),
)
EDGE = obj(
    edge_id=ID,
    source_id=ID,
    target_id=ID,
    kind=choice(
        "proposed_by",
        "originated_from",
        "read_from",
        "wrote_to",
        "sent_to",
        "delegated_to",
        "requires_capability",
        "crosses_boundary",
        "enforced_by",
        "correlates_to",
        "temporally_precedes",
        "hypothesized_influence",
    ),
    evidence=EVIDENCE,
    confidence=nullable(PROBABILITY),
    evidence_kind=choice(
        "host_observed",
        "deterministic_inference",
        "caller_asserted",
        "model_hypothesis",
        "imported_claim",
    ),
    correlation_id=nullable(ID),
    proof_gaps=array(text(), 32),
)
ATTACK_PATH = artifact(
    "assurance_attack_path",
    path_id=ID,
    repository=REPOSITORY,
    session_digest=nullable(DIGEST),
    nodes=array(NODE),
    edges=array(EDGE, 512),
    supporting_evidence=array(EVIDENCE),
    counterevidence=array(EVIDENCE),
    proof_gaps=array(text()),
    exposure=choice("established", "hypothesis", "unknown"),
    reachability=choice("established", "hypothesis", "blocked", "unknown"),
    possible_impact=array(ID, 32),
    permissions=choice("within_boundary", "exceeds_boundary", "unsupported", "unknown"),
    root_cause_digest=nullable(DIGEST),
    boundary_digest=nullable(DIGEST),
    occurrence_ids=array(ID, 128),
    max_depth={"type": "integer", "minimum": 1, "maximum": 64},
    session_digests=array(DIGEST, 32),
)
FINDING = artifact(
    "assurance_finding",
    finding_id=ID,
    issue_class=ID,
    repository=REPOSITORY,
    affected_sources=array(SOURCE),
    affected_operations=array(ID, 64),
    attacker_control=array(ID, 64),
    invariant_id=nullable(ID),
    requested_privilege=array(ID, 64),
    actual_privilege=array(ID, 64),
    evidence=array(EVIDENCE),
    counterevidence=array(EVIDENCE),
    preconditions=array(text(), 64),
    confidence=nullable(PROBABILITY),
    status=choice("imported", "hypothesis", "confirmed", "refuted", "inconclusive"),
    verification_method=choice("none", "static", "replay", "sandboxed_test", "host_observation"),
    proof_gaps=array(text()),
    safe_reproducer_ref=nullable(ID),
    dedupe_key=DIGEST,
    occurrence_ids=array(ID),
    origin=choice("caller_asserted", "static_evidence", "imported_claim"),
)
CASE_RESULT = obj(
    case_id=ID,
    action_digest=DIGEST,
    baseline_core=choice("execute", "escalate", "deny"),
    candidate_core=choice("execute", "escalate", "deny"),
    baseline_final=choice("execute", "escalate", "deny"),
    candidate_final=choice("execute", "escalate", "deny"),
    change=choice(
        "newly_denied", "newly_escalated", "newly_executable", "unchanged", "unassessable"
    ),
    reason_codes=array(ID, 64),
    authority_delta=choice("unchanged", "narrowed", "widened", "unsupported", "unknown"),
    label=choice("benign", "adversarial", "unknown"),
    baseline_ms=MILLISECONDS,
    candidate_ms=MILLISECONDS,
    baseline_core_ms=MILLISECONDS,
    candidate_core_ms=MILLISECONDS,
    baseline_wrapper_ms=MILLISECONDS,
    candidate_wrapper_ms=MILLISECONDS,
    expected=choice("execute", "escalate", "deny"),
    critical=BOOLEAN,
    action_kind=ID,
    assessable=BOOLEAN,
    baseline_effects=array(ID, 128),
    candidate_effects=array(ID, 128),
    baseline_temporal=array(ID, 32),
    candidate_temporal=array(ID, 32),
    baseline_capability_digest=nullable(DIGEST),
    candidate_capability_digest=nullable(DIGEST),
)
LATENCY = obj(p50_ms=MILLISECONDS, p95_ms=MILLISECONDS, p99_ms=MILLISECONDS, samples=COUNT)
KIND_COVERAGE = obj(action_kind=ID, total=COUNT, assessable=COUNT, unresolved=COUNT)
SIMULATION = artifact(
    "assurance_simulation",
    report_id=ID,
    corpus_digest=DIGEST,
    baseline_revision=REVISION,
    candidate_revision=REVISION,
    old_policy_digest=DIGEST,
    new_policy_digest=DIGEST,
    old_profile_digest=nullable(DIGEST),
    new_profile_digest=nullable(DIGEST),
    old_profile_selection_digest=nullable(DIGEST),
    new_profile_selection_digest=nullable(DIGEST),
    cases=array(CASE_RESULT, 4096),
    critical_misses=COUNT,
    critical_caught=COUNT,
    benign_false_escalations=COUNT,
    benign_false_denials=COUNT,
    baseline_latency=LATENCY,
    candidate_latency=LATENCY,
    coverage=choice("complete", "partial", "unknown"),
    activation_safe=BOOLEAN,
    environment=text(),
    limitations=array(text()),
    newly_denied=array(ID, 4096),
    newly_escalated=array(ID, 4096),
    newly_executable=array(ID, 4096),
    unassessable=array(ID, 4096),
    missing_required_cases=array(ID, 4096),
    policy_authority_delta=choice("unchanged", "narrowed", "widened", "unsupported", "unknown"),
    source_permissions=choice("synthetic_fixture", "authorized_sanitized_replay", "unknown"),
    coverage_by_kind=array(KIND_COVERAGE, 64),
)
COUNTEREXAMPLE = artifact(
    "assurance_counterexample",
    record_id=ID,
    claimed_property=ID,
    seed={"type": "integer", "minimum": 0, "maximum": 2**63 - 1},
    generator_version=ID,
    mutation=ID,
    initial_input=text(),
    minimized_input=text(),
    initial_digest=DIGEST,
    minimized_digest=DIGEST,
    baseline_result=ID,
    candidate_result=ID,
    replay_outcome=choice("verified_failure", "not_reproduced", "inconclusive"),
    revision=REVISION,
    environment=text(),
    provenance_kind=choice("synthetic_fixture", "sanitized_replay"),
    safe_fixture_only={"type": "boolean", "const": True},
    proof_gaps=array(text(), 32),
)
DELEGATION = artifact(
    "assurance_delegation",
    grant_id=ID,
    parent_principal=ID,
    child_principal=ID,
    parent_grant_id=nullable(ID),
    issuer_identity=ID,
    authorization_channel=ID,
    session_digest=DIGEST,
    epoch=COUNT,
    issued_at=TIMESTAMP,
    expires_at=TIMESTAMP,
    revoked_at=nullable(TIMESTAMP),
    parent_policy_digest=DIGEST,
    profile_digest=DIGEST,
    contract_digest=DIGEST,
    capability_refs=array(DIGEST, 128),
    maximum_delegation_depth={"type": "integer", "minimum": 0, "maximum": 16},
    depth={"type": "integer", "minimum": 0, "maximum": 16},
    status=choice("proposal", "issued", "revoked"),
)
CHALLENGE_RUN = artifact(
    "assurance_challenge_run",
    seed={"type": "integer", "minimum": 0, "maximum": 2**63 - 1},
    revision=REVISION,
    variant=choice("actual", "seeded_prefix_bug", "seeded_unsafe_checker"),
    requested_trials=COUNT,
    generated=COUNT,
    evaluated=COUNT,
    unresolved=COUNT,
    failures=COUNT,
    benign_controls=COUNT,
    counterexamples=array(COUNTEREXAMPLE, 256),
    input_manifest_digest=DIGEST,
    elapsed_ms=MILLISECONDS,
    status=choice("passed", "failing", "inconclusive"),
    property_id=choice(
        "authority_subset",
        "monotonicity",
        "exact_request_commitment",
        "protocol_separation",
        "tool_identity",
        "history_observations",
        "delegation_subset",
        "trust_origin",
        "optional_failure_mode",
        "review_to_use_binding",
    ),
    generator_version=choice("authority-paths-v1", "security-properties-v1"),
    host_boundary_exercised={"type": "boolean", "const": False},
    limitations=array(text(), 32),
    missing_scenarios=array(ID, 64),
    samples=array(
        obj(
            case_id=ID,
            scenario=ID,
            input_digest=DIGEST,
            action_digest=DIGEST,
            policy_digest=DIGEST,
            expected=choice("accepted", "rejected", "unsupported"),
            actual=choice("accepted", "rejected", "unsupported"),
            assessable=BOOLEAN,
            reason_code=ID,
            relation=choice(
                "equivalent", "expected_difference", "non_decreasing", "control", "unsupported"
            ),
            benign=BOOLEAN,
            comparison=choice(
                "none", "expected_policy_difference", "not_comparable", "confirmed_bug"
            ),
            legacy_actual=nullable(choice("accepted", "rejected")),
        ),
        256,
    ),
)
CHALLENGE_SUITE = artifact(
    "assurance_challenge_suite",
    seed={"type": "integer", "minimum": 0, "maximum": 2**63 - 1},
    revision=REVISION,
    runs=array(CHALLENGE_RUN, 10),
    status=choice("passed", "failing", "inconclusive"),
    elapsed_ms=MILLISECONDS,
    required_properties=array(ID, 10),
    missing_properties=array(ID, 10),
    unresolved_properties=array(ID, 10),
    failures=COUNT,
    host_boundary_exercised={"type": "boolean", "const": False},
)
MODEL_ANSWER = obj(question_id=ID, p_yes=PROBABILITY)
MODEL = artifact(
    "assurance_model_evidence",
    evidence_id=ID,
    provider=ID,
    model_version=ID,
    question_set_id=ID,
    question_set_digest=DIGEST,
    redaction_policy_id=ID,
    input_digest=DIGEST,
    answers=array(MODEL_ANSWER, 32),
    supportedness=choice("supported", "unsupported", "inconclusive"),
    latency_ms=MILLISECONDS,
    error_class=choice(
        "none",
        "timeout",
        "unavailable",
        "malformed",
        "refused",
        "version_mismatch",
        "transport",
        "question_mismatch",
        "canceled",
        "privacy",
        "budget",
    ),
    calibration_ref=nullable(ID),
    consent_ref=nullable(ID),
)

INVENTORY_FILE = obj(
    path=SOURCE["properties"]["path"],
    content_digest=DIGEST,
    bytes={"type": "integer", "minimum": 0, "maximum": MAX_BYTES},
    lines=COUNT,
    language=choice("python", "javascript", "configuration", "text"),
)
INVENTORY_FACT = obj(
    fact_id=ID,
    kind=choice("entrypoint", "sink", "control", "transformation", "instruction_data", "asset"),
    category=ID,
    source=SOURCE,
    enclosing_symbol=nullable(ID),
)
INVENTORY_ISSUE = obj(code=ID, path_digest=nullable(DIGEST))
INVENTORY_LIMITS = obj(
    max_files={"type": "integer", "minimum": 1, "maximum": 256},
    max_total_bytes={"type": "integer", "minimum": 1, "maximum": 16_777_216},
    max_depth={"type": "integer", "minimum": 0, "maximum": 16},
)
INVENTORY = artifact(
    "assurance_repository_inventory",
    repository=REPOSITORY,
    snapshot_digest=DIGEST,
    root_identity_digest=DIGEST,
    files=array(INVENTORY_FILE),
    facts=array(INVENTORY_FACT),
    assets=array(ASSET),
    issues=array(INVENTORY_ISSUE),
    limits=INVENTORY_LIMITS,
    completeness=choice("complete", "partial", "unknown"),
    generator={"type": "string", "const": "ordin.static_inventory.v1"},
)
ROUTE = obj(
    hypothesis_id=ID,
    actor=ID,
    entrypoint_ref=nullable(ID),
    sink_ref=ID,
    transformation_refs=array(ID, 32),
    control_refs=array(ID, 32),
    boundary_id=ID,
    status={"type": "string", "const": "hypothesis"},
    proof_gaps=array(text(), 32),
)
THREAT_MODEL = artifact(
    "assurance_repository_threat_model",
    model_id=ID,
    inventory=INVENTORY,
    draft=DRAFT,
    actors=array(ID, 32),
    routes=array(ROUTE),
    counterevidence_refs=array(ID),
    assumptions=array(text(), 32),
    open_questions=array(text(), 32),
)
RULE_COMPILATION = obj(
    invariant_id=ID,
    status=choice("compiled", "wrapper_required", "unsupported"),
    rule_id=nullable(ID),
    reason_code=ID,
)
PROFILE_COMPILATION = artifact(
    "assurance_profile_compilation",
    repository=REPOSITORY,
    profile_id=ID,
    version=ID,
    profile_digest=DIGEST,
    selection_digest=DIGEST,
    compiled_policy_digest=DIGEST,
    rules=array(RULE_COMPILATION),
    source_references=array(SOURCE),
    limitations=array(text(), 32),
)

HOST_SCOPE = obj(
    principal=ID,
    repository=REPOSITORY,
    session_digest=DIGEST,
    epoch=COUNT,
    runtime_policy_digest=DIGEST,
    selection_digest=DIGEST,
)
HOST_APPROVAL = artifact(
    "assurance_host_approval",
    receipt_id=ID,
    source_key=DIGEST,
    action_digest=DIGEST,
    profile_digest=DIGEST,
    contract_id=nullable(ID),
)
HOST_ASSESSMENT = artifact(
    "assurance_host_assessment",
    assessment_id=ID,
    source_key=DIGEST,
    action_digest=DIGEST,
    profile_digest=DIGEST,
    invariant_id=ID,
    kind=choice(
        "source_flow_guard",
        "delegated_authority_subset",
        "scanner_isolation",
        "semantic_hosted_scope",
        "semantic_local_scope",
    ),
    status=choice("satisfied", "violated", "unsupported", "inconclusive"),
    contract_id=nullable(ID),
    proof_gaps=array(text(), 32),
    origin={"type": "string", "const": "host_authenticated_assessment"},
)
CREDENTIAL_USE = artifact(
    "assurance_host_credential_use",
    receipt_id=ID,
    source_key=DIGEST,
    action_digest=DIGEST,
    profile_digest=DIGEST,
    binding=ID,
    host=text(256),
    port={"type": "integer", "minimum": 1, "maximum": 65535},
)
AUTHORITY_REF = obj(authority_id=ID, boundary_digest=DIGEST)
HOST_CONTEXT = artifact(
    "assurance_host_context",
    scope=HOST_SCOPE,
    source_key=DIGEST,
    capability_authorities=array(AUTHORITY_REF, 128),
    request_authorities=array(AUTHORITY_REF, 128),
    approval_digests=array(DIGEST, 128),
    assessment_digests=array(DIGEST, 128),
    credential_use_digests=array(DIGEST, 128),
    history_digest=nullable(DIGEST),
)
BASELINE_SUMMARY = obj(
    disposition=choice("execute", "escalate", "deny"),
    decision=choice("allow", "warn", "ask", "block"),
    risk=choice("unknown", "low", "medium", "high", "critical"),
    effects=array(ID, 64),
    omitted_effects=COUNT,
)
ASSURANCE_DECISION = artifact(
    "assurance_decision",
    baseline=BASELINE_SUMMARY,
    disposition=choice("execute", "escalate", "deny"),
    action_digest=DIGEST,
    contract_id=nullable(ID),
    profile_digest=nullable(DIGEST),
    baseline_configuration_digest=DIGEST,
    assurance_configuration_digest=DIGEST,
    host_context_digest=nullable(DIGEST),
    history_digest=nullable(DIGEST),
    invariant_evaluations=array(EVALUATION),
    model_evidence=array(MODEL, 32),
    reason_codes=array(ID, 256),
    evidence_digest=DIGEST,
)
INSTRUCTION_ORIGIN = artifact(
    "assurance_instruction_origin",
    origin_id=ID,
    source_key=DIGEST,
    principal=ID,
    repository=REPOSITORY,
    session_digest=DIGEST,
    epoch=COUNT,
    kind=choice(
        "authorized_user",
        "repository_file",
        "mcp_result",
        "web_content",
        "model_reasoning",
        "unknown_origin",
    ),
    classification=choice("public", "internal", "sensitive", "unknown"),
    content_digest=DIGEST,
    span_digest=DIGEST,
    span_start=COUNT,
    span_end=COUNT,
    source=nullable(SOURCE),
    parent_action_digest=nullable(DIGEST),
)
SOURCE_USE = artifact(
    "assurance_source_use",
    use_id=ID,
    source_key=DIGEST,
    origin_digest=DIGEST,
    action_digest=DIGEST,
    argument_path=array(ID, 8),
    value_digest=DIGEST,
    usage=choice("data_argument", "instruction_context"),
)
SOURCE_PROVENANCE = artifact(
    "assurance_source_provenance",
    source_key=DIGEST,
    action_digest=DIGEST,
    origin_digests=array(DIGEST, 128),
    use_digests=array(DIGEST, 128),
    completeness=choice("complete", "partial", "unknown"),
)
DELEGATION_VERIFICATION = artifact(
    "assurance_delegation_verification",
    result=choice("within_boundary", "exceeds_boundary", "unsupported", "inconclusive"),
    reason_codes=array(ID, 64),
    child_authority_digest=DIGEST,
    parent_authority_digest=DIGEST,
    operator_authority_digest=DIGEST,
    task_authority_digest=DIGEST,
    coverage=obj(
        filesystem=BOOLEAN,
        network=BOOLEAN,
        tools=BOOLEAN,
        process=BOOLEAN,
        privilege=BOOLEAN,
        credentials=BOOLEAN,
        requests=BOOLEAN,
        approval=BOOLEAN,
    ),
    proof_gaps=array(text(), 32),
)
DELEGATED_DECISION = artifact(
    "assurance_delegated_decision",
    disposition=choice("execute", "escalate", "deny"),
    baseline_disposition=choice("execute", "escalate", "deny"),
    assurance_digest=DIGEST,
    grant_digest=DIGEST,
    action_digest=DIGEST,
    contract_digest=nullable(DIGEST),
    issuer_generation=COUNT,
    verification=nullable(DELEGATION_VERIFICATION),
    reason_codes=array(ID, 64),
)
IMPORTED_LOCATION = obj(
    path=text(1024),
    start_line={"type": "integer", "minimum": 1, "maximum": 1_000_000_000},
    end_line=nullable({"type": "integer", "minimum": 1, "maximum": 1_000_000_000}),
    role=nullable(text(128)),
    status=choice("reported", "verified", "missing", "revision_mismatch"),
    source=nullable(SOURCE),
)
IMPORTED_FINDING = artifact(
    "assurance_imported_finding",
    record_id=ID,
    finding=FINDING,
    vendor_finding_id=text(256),
    occurrence_id=text(256),
    rule_id=text(256),
    reported_severity=choice("critical", "high", "medium", "low", "informational", "unknown"),
    reported_confidence=choice("high", "medium", "low", "unknown"),
    reported_score=nullable({"type": "number", "minimum": 0, "maximum": 10}),
    locations=array(IMPORTED_LOCATION, 128),
    reported_payload_parts=array(text(), 256),
    payload_digest=DIGEST,
    duplicate_index=COUNT,
)
SCAN_IMPORT = artifact(
    "assurance_scan_import",
    report_id=ID,
    repository=REPOSITORY,
    artifact_digest=DIGEST,
    format=choice("codex_json", "sarif_2_1_0"),
    adapter_revision=REVISION,
    scanner_name=nullable(text(128)),
    scanner_version=nullable(text(128)),
    scan_id=nullable(text(256)),
    scan_status=choice("completed", "failed", "canceled", "interrupted", "unknown"),
    reported_completeness=choice("complete", "partial", "unknown"),
    completeness=choice("complete", "partial", "unknown"),
    integrity=choice("matched", "missing", "not_available"),
    scope_match=choice("matched", "mismatch", "unknown"),
    included_paths=array(text(1024), 256),
    excluded_paths=array(text(1024), 256),
    findings=array(IMPORTED_FINDING, 256),
    metadata_parts=array(text(), 256),
    metadata_digest=DIGEST,
    threat_model_digest=nullable(DIGEST),
    proof_gaps=array(text(), 64),
    origin=choice("imported_claim"),
)
SEMANTIC_QUESTION_IDS = choice(
    "material_intent_mismatch",
    "possible_secret_egress",
    "suspicious_permission_expansion",
    "untrusted_instruction_following",
    "suspicious_delegation",
)
SEMANTIC_QUESTIONS = artifact(
    "assurance_security_questions",
    question_ids={**array(SEMANTIC_QUESTION_IDS, 5), "minItems": 1},
    question_set_id={"type": "string", "const": "ordin.security_questions.v1"},
    interpretation=text(),
)
SEMANTIC_SNIPPET = obj(
    text=text(2048),
    origin_kind=ID,
    classification=choice("public", "internal", "sensitive", "secret", "unknown"),
    content_digest=DIGEST,
)
SEMANTIC_STATE = artifact(
    "assurance_semantic_state",
    action_digest=DIGEST,
    baseline_evidence_digest=DIGEST,
    gate_configuration_digest=DIGEST,
    host_context_digest=nullable(DIGEST),
    task_context_digest=nullable(DIGEST),
    host_source_key=nullable(DIGEST),
    action_kind=choice("shell", "tool", "mcp", "http", "filesystem", "process", "unknown"),
    risk=choice("unknown", "low", "medium", "high", "critical"),
    effects=array(ID, 64),
    authorized_task=nullable(text(2048)),
    snippets=array(SEMANTIC_SNIPPET, 4),
    signals=array(
        choice(
            "sensitive_content_redacted",
            "untrusted_content_present",
            "untrusted_instruction_context",
            "sensitive_source_present",
            "network_effect",
            "authority_change_candidate",
            "delegation_candidate",
            "task_alignment_question",
            "ambiguous_task_alignment",
            "unclear_effect",
            "near_trust_boundary",
            "cross_agent_flow",
        ),
        12,
    ),
    remote_eligible=BOOLEAN,
    omitted_fields=COUNT,
    redaction_policy_id={"type": "string", "const": "ordin.semantic_privacy.v1"},
)

SEMANTIC_POLICY = artifact(
    "assurance_semantic_policy",
    mode=choice("disabled", "shadow", "enforced-escalation"),
    enabled_question_ids=array(SEMANTIC_QUESTION_IDS, 5),
    mandatory_action_kinds=array(SEMANTIC_STATE["properties"]["action_kind"], 7),
    mandatory_effects=array(ID, 64),
    required_question_ids=array(SEMANTIC_QUESTION_IDS, 5),
    escalation_threshold=PROBABILITY,
    uncertainty_margin={"type": "number", "minimum": 0, "maximum": 0.49},
    deadline_ms={"type": "integer", "minimum": 1, "maximum": 30000},
    max_total_calls={"type": "integer", "minimum": 0, "maximum": 4096},
    max_concurrency={"type": "integer", "minimum": 1, "maximum": 16},
    max_input_bytes={"type": "integer", "minimum": 1024, "maximum": 12288},
)
SEMANTIC_INSPECTION = artifact(
    "assurance_semantic_inspection",
    source_key=DIGEST,
    action_digest=DIGEST,
    reasons={
        **array(
            choice(
                "ambiguous_task_alignment",
                "unclear_effect",
                "near_trust_boundary",
                "cross_agent_flow",
            ),
            4,
        ),
        "minItems": 1,
    },
)
SEMANTIC_DECISION = artifact(
    "assurance_semantic_decision",
    decision_id=ID,
    mode=SEMANTIC_POLICY["properties"]["mode"],
    disposition=choice("execute", "escalate", "deny"),
    baseline_disposition=choice("execute", "escalate", "deny"),
    baseline_evidence_digest=DIGEST,
    router_configuration_digest=DIGEST,
    state_digest=nullable(DIGEST),
    question_set_digest=nullable(DIGEST),
    model_evidence=nullable(MODEL),
    model_invoked=BOOLEAN,
    mandatory=BOOLEAN,
    uncertain_question_ids=array(SEMANTIC_QUESTION_IDS, 5),
    reason_codes=array(ID, 32),
    elapsed_ms=MILLISECONDS,
    advisory_only={"type": "boolean", "const": True},
)

DIFF_FILE = obj(
    path_digest=DIGEST,
    change=choice("added", "modified", "deleted"),
    before_digest=nullable(DIGEST),
    after_digest=nullable(DIGEST),
    categories=array(
        choice(
            "documentation_only",
            "protected_surface",
            "new_subprocess_sink",
            "new_network_sink",
            "new_tool_surface",
            "enforcement_modified",
            "mcp_schema_modified",
            "dependency_modified",
            "host_boundary_modified",
            "source_modified",
        ),
        16,
    ),
    sources=array(SOURCE, 16),
)
DIFF_TRIAGE = artifact(
    "assurance_diff_triage",
    repository_before=REPOSITORY,
    repository_after=REPOSITORY,
    baseline_snapshot_digest=DIGEST,
    candidate_snapshot_digest=DIGEST,
    baseline_policy_digest=nullable(DIGEST),
    candidate_policy_digest=nullable(DIGEST),
    policy_authority_delta=choice(
        "unchanged", "narrowed", "widened", "unknown", "unsupported", "not_supplied"
    ),
    profile_changed=BOOLEAN,
    changes=array(DIFF_FILE, 512),
    review_required=BOOLEAN,
    completeness=choice("complete", "partial"),
    gaps=array(text(), 64),
    limitations=array(text(), 32),
    advisory_only={"type": "boolean", "const": True},
)
SCANNER_RUN = artifact(
    "assurance_scanner_run",
    run_id=ID,
    operation=choice("inspect", "dry_run", "scan", "export", "mock"),
    status=choice(
        "completed",
        "severity_violation",
        "incomplete",
        "unavailable",
        "version_mismatch",
        "timeout",
        "canceled",
        "output_limit",
        "error",
    ),
    exit_code=nullable({"type": "integer", "minimum": -2147483648, "maximum": 4294967295}),
    executable_digest=nullable(DIGEST),
    entrypoint_digest=nullable(DIGEST),
    invocation_digest=DIGEST,
    repository_digest=nullable(DIGEST),
    stdout_digest=DIGEST,
    stderr_digest=DIGEST,
    stdout_bytes=COUNT,
    stderr_bytes=COUNT,
    expected_cli_version=text(128),
    observed_cli_version=nullable(text(128)),
    elapsed_ms=MILLISECONDS,
    imported_report_digest=nullable(DIGEST),
    completeness=choice("complete", "partial", "unknown"),
    model_or_network_enabled=BOOLEAN,
    limitations=array(text(), 32),
)

SCHEMAS = {
    "assurance_semantic_inspection": SEMANTIC_INSPECTION,
    "assurance_semantic_policy": SEMANTIC_POLICY,
    "assurance_semantic_decision": SEMANTIC_DECISION,
    "assurance_security_questions": SEMANTIC_QUESTIONS,
    "assurance_semantic_state": SEMANTIC_STATE,
    "assurance_diff_triage": DIFF_TRIAGE,
    "assurance_scanner_run": SCANNER_RUN,
    "assurance_imported_finding": IMPORTED_FINDING,
    "assurance_scan_import": SCAN_IMPORT,
    "assurance_delegated_decision": DELEGATED_DECISION,
    "assurance_delegation_verification": DELEGATION_VERIFICATION,
    "assurance_source_provenance": SOURCE_PROVENANCE,
    "assurance_instruction_origin": INSTRUCTION_ORIGIN,
    "assurance_source_use": SOURCE_USE,
    "assurance_challenge_suite": CHALLENGE_SUITE,
    "assurance_challenge_run": CHALLENGE_RUN,
    "assurance_host_credential_use": CREDENTIAL_USE,
    "assurance_host_approval": HOST_APPROVAL,
    "assurance_host_assessment": HOST_ASSESSMENT,
    "assurance_host_context": HOST_CONTEXT,
    "assurance_decision": ASSURANCE_DECISION,
    "assurance_repository_inventory": INVENTORY,
    "assurance_repository_threat_model": THREAT_MODEL,
    "assurance_profile_compilation": PROFILE_COMPILATION,
    "assurance_security_profile": PROFILE,
    "assurance_security_profile_draft": DRAFT,
    "assurance_invariant": INVARIANT,
    "assurance_invariant_evaluation": EVALUATION,
    "assurance_finding": FINDING,
    "assurance_attack_path": ATTACK_PATH,
    "assurance_simulation": SIMULATION,
    "assurance_counterexample": COUNTEREXAMPLE,
    "assurance_delegation": DELEGATION,
    "assurance_model_evidence": MODEL,
}
SHAPES = {
    "diff_file": DIFF_FILE,
    "imported_location": IMPORTED_LOCATION,
    "assurance_host_scope": HOST_SCOPE,
    "assurance_authority_ref": AUTHORITY_REF,
    "inventory_file": INVENTORY_FILE,
    "inventory_fact": INVENTORY_FACT,
    "inventory_issue": INVENTORY_ISSUE,
    "inventory_limits": INVENTORY_LIMITS,
    "route_hypothesis": ROUTE,
    "invariant_compilation": RULE_COMPILATION,
    "source_reference": SOURCE,
    "repository_scope": REPOSITORY,
    "protected_asset": ASSET,
    "trust_boundary": BOUNDARY,
    "evidence_link": EVIDENCE,
    "invariant_selectors": SELECTORS,
    "attack_node": NODE,
    "attack_edge": EDGE,
    "simulation_case": CASE_RESULT,
    "action_kind_coverage": KIND_COVERAGE,
    "latency_distribution": LATENCY,
    "model_answer": MODEL_ANSWER,
}
