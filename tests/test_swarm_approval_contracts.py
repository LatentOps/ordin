"""Installed governance data and CLI cannot reconstruct authenticated approval."""

import json

import pytest

from ordin.schema import validate_named_schema
from ordin.swarm.approval import SwarmApprovalPolicy, SwarmApprovalReceipt, SwarmRecoveryApproval
from ordin.swarm.approval_cli import main


def test_explicit_policy_round_trip_is_bounded_and_defaults_to_no_break_glass(tmp_path, capsys):
    policy = SwarmApprovalPolicy("human")
    assert not policy.break_glass
    assert SwarmApprovalPolicy.from_dict(policy.as_dict()) == policy
    assert not validate_named_schema("swarm_approval_policy", policy.as_dict())
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(policy.as_dict()))
    assert main(["validate", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == policy.as_dict()
    for fields in (
        {"maximum_lifetime": 301},
        {"required_roles": ["*"]},
        {"break_glass_quorum": 1},
        {"lifetime": True},
        {"execution_authority": True},
        {"unknown_authorizer": "approved"},
    ):
        with pytest.raises(ValueError):
            SwarmApprovalPolicy.from_dict(policy.as_dict() | fields)


def test_json_and_plain_cli_flags_never_authenticate_a_human_or_recovery(tmp_path, capsys):
    for cls in (SwarmApprovalReceipt, SwarmRecoveryApproval):
        with pytest.raises(ValueError):
            cls.from_dict({"approved": True, "operator": "alice", "roles": ["recover"]})
    for command in ("approve", "deny", "cancel", "expire", "resume"):
        args = [command, "a" * 32]
        if command != "resume":
            args += ["--idempotency-key", "owned-test"]
        assert main(args) == 2
    assert "original current bounded authority required" in capsys.readouterr().out


def test_governance_resolution_schema_rejects_authority_claims():
    packet = {
        "schema_version": "ordin.swarm_approval_resolution.v1",
        "request_id": "a" * 32,
        "status": "approved",
        "votes": 2,
        "quorum": 2,
        "execution_authority": False,
    }
    assert not validate_named_schema("swarm_approval_resolution", packet)
    assert validate_named_schema(
        "swarm_approval_resolution", packet | {"receipt": {"approved": True}}
    )
    assert validate_named_schema(
        "swarm_approval_resolution", packet | {"execution_authority": True}
    )
