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
    status=choice("hypothesis", "confirmed", "refuted", "inconclusive"),
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
)
LATENCY = obj(p50_ms=MILLISECONDS, p95_ms=MILLISECONDS, p99_ms=MILLISECONDS, samples=COUNT)
SIMULATION = artifact(
    "assurance_simulation",
    report_id=ID,
    corpus_digest=DIGEST,
    baseline_revision=REVISION,
    candidate_revision=REVISION,
    old_policy_digest=DIGEST,
    new_policy_digest=DIGEST,
    cases=array(CASE_RESULT, 4096),
    critical_misses=COUNT,
    benign_false_escalations=COUNT,
    benign_false_denials=COUNT,
    baseline_latency=LATENCY,
    candidate_latency=LATENCY,
    coverage=choice("complete", "partial", "unknown"),
    activation_safe=BOOLEAN,
    environment=text(),
    limitations=array(text()),
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
    ),
    calibration_ref=nullable(ID),
    consent_ref=nullable(ID),
)

SCHEMAS = {
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
    "source_reference": SOURCE,
    "repository_scope": REPOSITORY,
    "protected_asset": ASSET,
    "trust_boundary": BOUNDARY,
    "evidence_link": EVIDENCE,
    "invariant_selectors": SELECTORS,
    "attack_node": NODE,
    "attack_edge": EDGE,
    "simulation_case": CASE_RESULT,
    "latency_distribution": LATENCY,
    "model_answer": MODEL_ANSWER,
}
