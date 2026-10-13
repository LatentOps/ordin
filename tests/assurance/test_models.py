"""Common contracts: hostile decoding, privacy-safe errors, immutable proposals."""

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from ordin.assurance import (
    ApprovedSecurityProfile,
    AttackEdge,
    AttackNode,
    AttackPathEvidence,
    CounterexampleRecord,
    DelegationGrant,
    EvidenceLink,
    InvariantEvaluation,
    InvariantSelectors,
    LatencyDistribution,
    ModelAnswer,
    ModelRiskEvidence,
    PolicySimulationReport,
    ProtectedAsset,
    RepositoryScope,
    SecurityFinding,
    SecurityInvariant,
    SecurityProfile,
    SecurityProfileDraft,
    SimulationCase,
    SourceReference,
    TrustBoundary,
)
from ordin.assurance._json import canonical_json, digest, loads

HASH = "a" * 64
REPO = RepositoryScope("fixture/payment", "abc123")
SOURCE = SourceReference("src/payment.py", 7, "abc123", HASH, "authorize")
LINK = EvidenceLink(
    "source-1",
    "static_evidence",
    SOURCE,
    proof_gaps=("Static reference does not prove execution.",),
)
RULE = SecurityInvariant(
    "deploy-approval",
    "require_approval",
    InvariantSelectors(effects=("filesystem.write",), resource_ref="deploy"),
    provenance=(LINK,),
)
PROFILE = SecurityProfile(
    "payment",
    "1",
    REPO,
    (ProtectedAsset("deploy", "path", "/fixture/.github/workflows/deploy.yml"),),
    (TrustBoundary("deploy-boundary", "agent", "deployment"),),
    (RULE,),
)


def examples():
    latency = LatencyDistribution(1, 2, 3, 4)
    case = SimulationCase(
        "case",
        HASH,
        "execute",
        "execute",
        "execute",
        "escalate",
        "newly_escalated",
        authority_delta="narrowed",
        label="adversarial",
    )
    return [
        PROFILE,
        SecurityProfileDraft(
            "draft",
            REPO,
            "static",
            source_evidence=(SOURCE,),
            unresolved_facts=("Runtime host unknown.",),
        ),
        RULE,
        InvariantEvaluation("deploy-approval", "inconclusive", "missing_host_approval", HASH, HASH),
        SecurityFinding(
            "candidate",
            "policy_mutation",
            REPO,
            HASH,
            evidence=(LINK,),
            proof_gaps=("No reproduction.",),
            origin="imported_claim",
        ),
        AttackPathEvidence(
            "path",
            REPO,
            nodes=(
                AttackNode("input", "source", "repository"),
                AttackNode("write", "action", "filesystem.write"),
            ),
            edges=(AttackEdge("edge", "input", "write", "hypothesized_influence", LINK),),
        ),
        PolicySimulationReport(
            "simulation",
            HASH,
            "abc123",
            "def456",
            HASH,
            HASH,
            latency,
            latency,
            "synthetic",
            cases=(case,),
        ),
        CounterexampleRecord(
            "counterexample",
            "monotonicity",
            42,
            "1",
            "replace_resource",
            "original",
            "minimal",
            digest("counterexample_input", "original"),
            digest("counterexample_input", "minimal"),
            "deny",
            "execute",
            "inconclusive",
            "abc123",
            "synthetic",
        ),
        DelegationGrant(
            "grant",
            "parent",
            "child",
            "fixture-host",
            "protected",
            HASH,
            0,
            1,
            10,
            HASH,
            HASH,
            HASH,
        ),
        ModelRiskEvidence(
            "model",
            "mock",
            "1",
            "questions",
            HASH,
            "redact-v1",
            HASH,
            (ModelAnswer("possible_secret_egress", 0.5),),
            "supported",
        ),
    ]


@pytest.mark.parametrize("record", examples(), ids=lambda record: record.SCHEMA)
def test_roundtrip_is_detached_canonical_and_immutable(record):
    payload = record.as_dict()
    rebuilt = type(record).from_json(json.dumps(payload))
    assert rebuilt == record
    assert rebuilt.digest == record.digest
    assert canonical_json(payload) == canonical_json(rebuilt.as_dict())
    payload["schema_version"] = "forged"
    assert rebuilt.as_dict()["schema_version"] != "forged"
    with pytest.raises(FrozenInstanceError):
        record.untrusted = True


def test_collections_are_copied_and_cannot_be_modified():
    flags = ["source_inventory"]
    profile = replace(PROFILE, support_flags=flags)
    flags.append("allow_everything")
    assert profile.support_flags == ("source_inventory",)
    serialized = profile.as_dict()
    serialized["invariants"][0]["on_violation"] = "block"
    assert profile.invariants[0].on_violation == "escalate"


@pytest.mark.parametrize(
    "payload",
    [
        '{"approved":false,"approved":true}',
        '{"\\u0061":1,"a":2}',
        '{"x":NaN}',
        '{"x":Infinity}',
        '{"x":-Infinity}',
        '{"x":1e999}',
        '{"x":"\\ud800"}',
        "[1]",
        '{"x":' + "[" * 14 + "0" + "]" * 14 + "}",
    ],
)
def test_hostile_json_is_rejected_without_echoing_values(payload):
    with pytest.raises(ValueError) as caught:
        loads(payload)
    assert payload not in str(caught.value)


def test_json_boundary_limits_and_safe_duplicate_error():
    assert loads('{"x":"' + "a" * 4096 + '"}')["x"] == "a" * 4096
    with pytest.raises(ValueError):
        loads('{"x":"' + "a" * 4097 + '"}')
    assert len(loads(json.dumps({"x": list(range(4096))}))["x"]) == 4096
    with pytest.raises(ValueError):
        loads(json.dumps({"x": list(range(4097))}))
    with pytest.raises(ValueError):
        loads(" " * 1_048_577)
    private = "fixture-secret-value"
    with pytest.raises(ValueError) as caught:
        loads(json.dumps({private: 1})[:-1] + ',"' + private + '":2}')
    assert private not in str(caught.value)


@pytest.mark.parametrize("record", examples(), ids=lambda record: record.SCHEMA)
def test_unknown_fields_versions_and_missing_fields_rejected(record):
    for key, value in [("trusted", True), ("approved", True), ("execute", "python")]:
        payload = record.as_dict()
        payload[key] = value
        with pytest.raises(ValueError):
            type(record).from_dict(payload)
    payload = record.as_dict()
    payload["schema_version"] = "ordin.forged.v99"
    with pytest.raises(ValueError):
        type(record).from_dict(payload)
    payload = record.as_dict()
    del payload["schema_version"]
    with pytest.raises(ValueError):
        type(record).from_dict(payload)


@pytest.mark.parametrize(
    "origin", ["policy_verified", "runtime_backend_observed", "deterministically_derived"]
)
def test_strong_provenance_cannot_be_claimed_from_json_or_constructor(origin):
    with pytest.raises(ValueError, match="host source"):
        EvidenceLink("spoof", origin)
    payload = LINK.as_dict()
    payload["origin"] = origin
    with pytest.raises(ValueError, match="host source"):
        EvidenceLink.from_dict(payload)


def test_draft_cannot_activate_or_claim_approval():
    with pytest.raises(ValueError):
        replace(SecurityProfileDraft("draft", REPO, "static"), authoritative=True)
    with pytest.raises(ValueError, match="cannot activate"):
        ApprovedSecurityProfile.from_dict(PROFILE.as_dict())
    with pytest.raises(ValueError, match="protected host"):
        ApprovedSecurityProfile(PROFILE, "operator", HASH, object())


@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        "/etc/passwd",
        "C:/secret",
        "src/../secret",
        "src/./secret",
        "src//secret",
        "src\\secret",
        "https://fixture.invalid",
    ],
)
def test_source_references_have_no_external_or_ambiguous_path_authority(path):
    with pytest.raises(ValueError):
        replace(SOURCE, path=path)


def test_profile_and_graph_reject_ambiguous_references():
    with pytest.raises(ValueError, match="unique"):
        replace(PROFILE, protected_assets=PROFILE.protected_assets * 2)
    with pytest.raises(ValueError, match="undefined asset"):
        replace(PROFILE, protected_assets=())
    path = examples()[5]
    with pytest.raises(ValueError, match="undefined node"):
        replace(path, nodes=())
    with pytest.raises(ValueError, match="session mismatch"):
        replace(path, edges=(replace(path.edges[0], evidence=replace(LINK, session_digest=HASH)),))


def test_unverified_findings_and_partial_simulations_cannot_claim_success():
    finding = examples()[4]
    with pytest.raises(ValueError, match="imported claims"):
        replace(finding, status="confirmed", verification_method="replay")
    with pytest.raises(ValueError, match="host validation"):
        replace(
            finding,
            origin="caller_asserted",
            status="confirmed",
            verification_method="replay",
            proof_gaps=(),
        )
    simulation = examples()[6]
    with pytest.raises(ValueError, match="incomplete"):
        replace(simulation, activation_safe=True)


def test_counterexample_changes_invalidate_binding():
    with pytest.raises(ValueError, match="digest mismatch"):
        replace(examples()[7], minimized_input="different-property")
    with pytest.raises(ValueError):
        replace(examples()[7], safe_fixture_only=False)


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -0.1, 1.1, True])
def test_model_scores_are_finite_bounded_numbers(score):
    with pytest.raises(ValueError):
        ModelAnswer("risk", score)


def test_model_outages_duplicate_answers_and_missing_answers_remain_visible():
    model = examples()[9]
    with pytest.raises(ValueError, match="failed"):
        replace(model, error_class="timeout")
    with pytest.raises(ValueError, match="unique"):
        replace(model, answers=model.answers * 2)
    with pytest.raises(ValueError, match="requires answers"):
        replace(model, answers=())
    assert (
        replace(model, supportedness="inconclusive", error_class="timeout", answers=()).answers
        == ()
    )


def test_grant_metadata_alone_is_a_proposal_and_lifetimes_are_bounded():
    grant = examples()[8]
    assert grant.status == "proposal"
    assert DelegationGrant.from_dict(grant.as_dict()).status == "proposal"
    for changes in (
        {"expires_at": 1},
        {"child_principal": "parent"},
        {"depth": 1},
        {"parent_grant_id": "grant"},
        {"revoked_at": 0},
    ):
        with pytest.raises(ValueError):
            replace(grant, **changes)


def test_digest_is_domain_separated():
    assert digest("profile", {"x": 1}) != digest("finding", {"x": 1})
    assert digest("profile", {"a": 1, "b": 2}) == digest("profile", {"b": 2, "a": 1})


@pytest.mark.parametrize(
    "endpoint",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://@fixture.invalid/path",
        "https://fixture.invalid/a?token=x",
        "https://fixture.invalid/a#fragment",
        "https://fixture.invalid/a%2fb",
    ],
)
def test_endpoint_assets_reuse_existing_strict_request_parser(endpoint):
    with pytest.raises(ValueError):
        ProtectedAsset("endpoint", "endpoint", endpoint)


def test_supported_assets_do_not_expand_uri_or_path_authority():
    assert ProtectedAsset("endpoint", "endpoint", "https://fixture.invalid/docs").match == "exact"
    assert ProtectedAsset("build", "path", "/fixture/build", "prefix").match == "prefix"
    with pytest.raises(ValueError):
        ProtectedAsset("endpoint", "endpoint", "https://fixture.invalid/docs", "prefix")
    with pytest.raises(ValueError):
        ProtectedAsset("credential", "credential", "fixture secret value")
    assert (
        replace(examples()[8], issued_at=1_791_590_000, expires_at=1_791_590_010).expires_at
        == 1_791_590_010
    )
