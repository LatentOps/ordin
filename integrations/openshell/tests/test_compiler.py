import copy
import json
from dataclasses import replace

import pytest

from ordin import ActionEnvelope, Ordin
from ordin.runtime_contract import (
    FilesystemCapability,
    NetworkCapability,
    ProcessCapability,
    ToolCapability,
    CredentialBinding,
    derive_runtime_capability_contract,
)
from ordin_openshell.compiler import OpenShellBackend, compile_openshell_policy
from ordin_openshell.model import PUBLIC_IPV4_RANGES, policy_errors, serialize_policy


def supported_contract():
    original = derive_runtime_capability_contract(
        Ordin().review_action(
            ActionEnvelope.shell(
                "/usr/bin/curl --disable --request GET https://api.github.com/repos/LatentOps/ordin/issues/37",
                action_id="issue-read",
            )
        )
    )
    return replace(
        original,
        contract_id="",
        decision="allow",
        risk="low",
        unknowns=(),
        filesystem=(
            FilesystemCapability("read", "/usr", "prefix"),
            FilesystemCapability("execute", "/usr", "prefix"),
        ),
        network=(
            NetworkCapability(
                "api.github.com",
                443,
                "rest",
                "read",
                ("GET",),
                ("/repos/LatentOps/ordin/issues/37",),
            ),
        ),
        process=ProcessCapability(True, ("/usr/bin/curl",), True),
    )


def compile(contract=None, **kwargs):
    return compile_openshell_policy(
        contract or supported_contract(), process_identity=(1000, 1000), **kwargs
    )


def test_golden_structured_policy_preserves_exact_request_and_binary():
    contract = supported_contract()
    result = compile(contract)
    assert result.status == "success" and result.enforceable
    policy = result.plan.as_dict()["policy"]
    endpoint = {
        "host": "api.github.com",
        "port": 443,
        "protocol": "rest",
        "enforcement": "enforce",
        "allowed_ips": list(PUBLIC_IPV4_RANGES),
        "rules": [{"allow": {"method": "GET", "path": "/repos/LatentOps/ordin/issues/37"}}],
    }
    assert policy == {
        "version": 1,
        "filesystem_policy": {"include_workdir": False, "read_only": ["/usr"], "read_write": []},
        "landlock": {"compatibility": "hard_requirement"},
        "process": {"run_as_user": "1000", "run_as_group": "1000"},
        "network_policies": {
            f"ordin_action_{contract.action_digest[:12]}_0": {
                "endpoints": [endpoint],
                "binaries": [{"path": "/usr/bin/curl"}],
            }
        },
    }
    assert policy_errors(policy) == ()
    assert compile(contract).plan.policy_digest == result.plan.policy_digest
    assert result.plan.contract == contract
    assert result.plan.metadata["semantic_effects"] == contract.source["effects"]


@pytest.mark.parametrize("protocol", ["unknown", "tcp", "graphql", "mcp", "json-rpc", "websocket"])
def test_high_level_or_unknown_protocol_never_falls_back_to_tcp(protocol):
    contract = supported_contract()
    changed = replace(
        contract, contract_id="", network=(replace(contract.network[0], protocol=protocol),)
    )
    result = compile(changed)
    assert result.status == "unsupported" and result.plan is None
    assert "network.protocol" in result.unsupported_fields


def test_missing_binary_process_identity_and_child_restriction_fail_closed():
    contract = supported_contract()
    assert (
        compile(replace(contract, contract_id="", process=ProcessCapability(True, (), True))).status
        == "unsupported"
    )
    assert compile_openshell_policy(contract).status == "unsupported"
    assert (
        compile(
            replace(
                contract, contract_id="", process=replace(contract.process, spawn_children=False)
            )
        ).status
        == "unsupported"
    )


@pytest.mark.parametrize(
    "filesystem",
    [
        (),
        (FilesystemCapability("read", "/usr", "prefix"),),
        (FilesystemCapability("write", "/repo", "prefix"),),
        (FilesystemCapability("delete", "/repo", "prefix"),),
        (
            FilesystemCapability("read", "/repo/file", "exact"),
            FilesystemCapability("execute", "/repo/file", "exact"),
        ),
    ],
)
def test_unrepresentable_or_widening_filesystem_scopes_return_no_plan(filesystem):
    result = compile(replace(supported_contract(), contract_id="", filesystem=filesystem))
    assert result.status == "unsupported" and result.plan is None
    assert any(field.startswith("filesystem") for field in result.unsupported_fields)


def test_explicit_exact_file_kind_and_full_write_primitive_are_supported():
    contract = replace(
        supported_contract(),
        contract_id="",
        filesystem=tuple(
            FilesystemCapability(access, "/repo/file", "exact")
            for access in ("read", "write", "delete", "execute")
        ),
    )
    result = compile(contract, resource_kinds={"/repo/file": "file"})
    assert result.status == "success"
    assert result.plan.policy["filesystem_policy"]["read_write"] == ("/repo/file",)


@pytest.mark.parametrize(
    "host,path",
    [
        ("127.0.0.1", "/a"),
        ("169.254.169.254", "/a"),
        ("localhost", "/a"),
        ("api.github.com", "/repos/**"),
        ("api.github.com", "/a%2Fb"),
    ],
)
def test_private_destination_and_wildcard_or_encoded_path_expansion_are_unsupported(host, path):
    contract = supported_contract()
    result = compile(
        replace(
            contract,
            contract_id="",
            network=(replace(contract.network[0], host=host, paths=(path,)),),
        )
    )
    assert result.status == "unsupported" and not result.enforceable


def test_credential_reference_needs_independent_explicit_endpoint_mapping():
    contract = replace(
        supported_contract(),
        contract_id="",
        credentials=(CredentialBinding("github.read", "api.github.com", 443),),
    )
    assert compile(contract).status == "unsupported"
    providers = {
        "github.read": {
            "provider": "operator-github",
            "host": "api.github.com",
            "port": 443,
            "methods": ["GET"],
            "paths": ["/repos/LatentOps/ordin/issues/37"],
        }
    }
    result = compile(contract, credential_providers=providers)
    assert result.status == "success"
    endpoint = next(iter(result.plan.policy["network_policies"].values()))["endpoints"][0]
    assert endpoint["credential_binding"] == {"provider": "operator-github"}
    assert "token" not in json.dumps(result.plan.as_dict())
    providers["github.read"]["token"] = "NEVER_RECORD_ME"
    rejected = compile(contract, credential_providers=providers)
    assert rejected.status == "unsupported" and "NEVER_RECORD_ME" not in json.dumps(
        rejected.as_dict()
    )


def test_tools_and_broader_base_policy_cannot_introduce_extra_authority():
    contract = supported_contract()
    assert (
        compile(
            replace(contract, contract_id="", tools=(ToolCapability("mcp", "github", "get_issue"),))
        ).status
        == "unsupported"
    )
    original = compile().plan.as_dict()["policy"]
    assert compile(base_policy=original).status == "success"
    original["filesystem_policy"]["read_write"] = ["/"]
    assert compile(base_policy=original).status == "unsupported"


def test_block_and_ask_requirements_cannot_disappear():
    assert (
        compile(replace(supported_contract(), contract_id="", decision="block")).status
        == "unsupported"
    )
    result = compile(replace(supported_contract(), contract_id="", decision="ask"))
    assert result.status == "success" and result.plan.requires_human_approval
    assert compile(mode="shadow").plan.mode == "shadow"


def test_policy_validation_rejects_drift_and_unsupported_fields():
    backend = OpenShellBackend(process_identity=(1000, 1000))
    plan = backend.compile(supported_contract()).plan
    assert backend.validate(plan).ok
    modified = copy.deepcopy(plan.as_dict()["policy"])
    next(iter(modified["network_policies"].values()))["endpoints"][0]["rules"][0]["allow"][
        "method"
    ] = "POST"
    assert not backend.validate(replace(plan, policy=modified)).ok
    modified["extra_unmodeled_permission"] = True
    assert policy_errors(modified)


def test_json_and_optional_yaml_round_trip_use_structured_serializer():
    plan = compile().plan
    assert json.loads(serialize_policy(plan.policy)) == plan.as_dict()["policy"]
    yaml = pytest.importorskip("yaml")
    assert yaml.safe_load(serialize_policy(plan.policy, format="yaml")) == plan.as_dict()["policy"]


def test_compiler_has_no_io_or_subprocess_effects(monkeypatch):
    import builtins
    import subprocess
    import socket

    contract = supported_contract()

    def forbidden(*args, **kwargs):
        raise AssertionError("compiler performed I/O or execution")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    assert compile(contract).status == "success"


def test_operator_metadata_cannot_smuggle_secret_values_into_a_successful_plan():
    secret = "NEVER_PERSIST_OPERATOR_SECRET"
    result = compile(resource_kinds={"/repo/file": "file", "token": secret})
    assert result.status == "unsupported" and result.plan is None
    assert secret not in json.dumps(result.as_dict())
    result = compile(resource_kinds={"/repo/file": secret})
    assert result.status == "unsupported" and result.plan is None
    providers = {
        "unused-binding": {
            "provider": "operator",
            "host": "api.github.com",
            "port": 443,
            "methods": None,
            "paths": ["/a"],
        }
    }
    result = compile(credential_providers=providers)
    assert result.status == "unsupported" and result.plan is None


@pytest.mark.parametrize("identity", [(0, 1000), (True, 1000), (2**32 - 1, 1000), (2**64, 1000)])
def test_process_identity_must_be_representable_by_the_actual_runtime(identity):
    result = compile_openshell_policy(supported_contract(), process_identity=identity)
    assert result.status == "unsupported" and result.plan is None
