import builtins
import json
import socket
import subprocess
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from ordin import (
    ActionEnvelope,
    ActionResource,
    ActionReview,
    MCPAdapter,
    Ordin,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
)
from ordin.audit import action_digest
from ordin.runtime_contract import (
    CapabilityUnknown,
    CredentialBinding,
    FilesystemCapability,
    NetworkCapability,
    ProcessCapability,
    RuntimeCapabilityContract,
    derive_runtime_capability_contract,
)
from ordin.schema import load_schema, resource_parity_errors, validate_named_schema
from ordin._runtime_schemas import SCHEMAS


def reviewed(*effects, resources=(), decision="allow", kind="shell", parameters=None):
    return ActionReview(
        action=ActionEnvelope(
            kind=kind,
            operation="execute" if kind == "shell" else "call",
            action_id="step-1",
            parameters=parameters or {"command": "/usr/bin/demo"},
        ),
        decision=decision,
        risk="low",
        reasons=[],
        safer_next_step=None,
        effects=list(effects),
        resources=list(resources),
        adapter="shell" if kind == "shell" else "trusted-test",
    )


def test_action_digest_and_contract_identity_are_canonical_and_deterministic():
    a = reviewed("filesystem.read", resources=(ActionResource("path", "/repo/README.md"),))
    b = replace(a, action=ActionEnvelope.from_dict(json.loads(json.dumps(a.action.as_dict()))))
    first = derive_runtime_capability_contract(a)
    second = derive_runtime_capability_contract(b)
    assert first == second
    assert first.action_digest == action_digest(a)
    assert first.contract_id.startswith("rc:")
    changed = replace(a, action=replace(a.action, intent="other intent"))
    assert derive_runtime_capability_contract(changed).action_digest != first.action_digest
    assert derive_runtime_capability_contract(changed).contract_id != first.contract_id
    assert replace(first, contract_id="", decision="block").contract_id != first.contract_id


@pytest.mark.parametrize(
    "effect,access",
    [
        ("filesystem.read", "read"),
        ("filesystem.write", "write"),
        ("filesystem.metadata_read", "metadata"),
        ("filesystem.delete", "delete"),
        ("filesystem.execute", "execute"),
    ],
)
def test_filesystem_access_preserves_semantics(effect, access):
    c = derive_runtime_capability_contract(
        reviewed(effect, resources=(ActionResource("path", "/repo/a"),))
    )
    assert c.filesystem == (FilesystemCapability(access, "/repo/a", "exact"),)
    assert not c.unknowns


def test_recursive_delete_uses_corresponding_subtree_scope():
    c = derive_runtime_capability_contract(
        reviewed(
            "filesystem.recursive_delete", resources=(ActionResource("directory", "/repo/build"),)
        )
    )
    assert c.filesystem == (FilesystemCapability("delete", "/repo/build", "prefix"),)


@pytest.mark.parametrize(
    "effect,access",
    [("network.download", "read"), ("network.connect", "read"), ("network.upload", "write")],
)
def test_network_access_does_not_invent_protocol_or_method(effect, access):
    c = derive_runtime_capability_contract(
        reviewed(effect, resources=(ActionResource("url", "https://api.example.com/files"),))
    )
    assert c.network == (NetworkCapability("api.example.com", 443, access=access),)
    assert c.network[0].methods == ()
    assert c.network[0].paths == ()
    assert c.unknowns and c.grant_state == "diagnostic"


@pytest.mark.parametrize(
    "url,valid",
    [
        ("https://api.example.com/a", True),
        ("http://api.example.com/a", True),
        ("https://user@api.example.com/a", False),
        ("https://user:pass@api.example.com/a", False),
        ("https://@api.example.com/a", False),
        ("https://:@api.example.com/a", False),
        ("https://api.example.com/a?x=1", False),
        ("https://api.example.com/a#fragment", False),
        ("https://api.example.com:443/a", True),
        ("https://api.example.com:99999/a", False),
        ("https://api.example.com:0/a", False),
    ],
)
def test_url_authority_consistency_preserves_diagnostic_derivation(url, valid):
    from ordin.runtime_requests import request_endpoint

    contract = derive_runtime_capability_contract(
        Ordin().review_action(ActionEnvelope.shell("curl --disable --request GET " + url))
    )
    assert (request_endpoint(url) is not None) is valid
    if valid:
        assert contract.network[0].host == "api.example.com"
        assert contract.network[0].port == (80 if url.startswith("http:") else 443)
        assert contract.network[0].protocol == "rest"
    else:
        assert all(n.host is None and n.port is None for n in contract.network)
        assert contract.grant_state == "diagnostic"
        assert any(
            u.reason_code == "runtime_contract_malformed_resource" for u in contract.unknowns
        )
        assert url not in json.dumps(contract.as_dict())


def test_process_execution_without_arbitrary_child_permission():
    c = derive_runtime_capability_contract(reviewed("code.execute"))
    assert c.process.execution is True
    assert c.process.executables == ("/usr/bin/demo",)
    assert c.process.spawn_children is None
    generic = derive_runtime_capability_contract(reviewed("process.spawn", kind="file"))
    assert generic.process.execution is True


@pytest.mark.parametrize("command", ["sudo id", "/usr/bin/sudo id", "doas id", "su root"])
def test_explicit_privilege_wrapper_is_preserved_even_without_effect(command):
    c = derive_runtime_capability_contract(reviewed(parameters={"command": command}))
    assert c.privilege.escalation is True
    assert c.privilege.required_euid is None


def test_privilege_effect_is_not_an_invented_uid():
    c = derive_runtime_capability_contract(reviewed("privilege.escalate"))
    assert c.privilege.escalation is True
    assert c.privilege.required_euid is None


def test_mcp_exact_identity_requires_actual_registered_semantics():
    registry = ToolSemanticsRegistry(
        "runtime-contract-tests",
        "1",
        (
            ToolSemanticRule(
                "read",
                "mcp",
                "read_file",
                ("filesystem.read",),
                server="files",
                resources=(ToolResourceBinding(argument="path", type="path"),),
            ),
        ),
    )
    ordin = Ordin(tool_semantics=registry)
    good = MCPAdapter("files").adapt("read_file", {"path": "/repo/a"}, action_id="a")
    c = derive_runtime_capability_contract(ordin.review_action(good))
    assert c.tools[0].as_dict() == {
        "runtime": "mcp",
        "server": "files",
        "tool": "read_file",
        "operation": "call",
    }
    assert not c.unknowns
    for server, tool in [("files-other", "read_file"), ("files", "safe_read_file")]:
        unknown = MCPAdapter(server).adapt(tool, {"path": "/repo/a"}, action_id="u")
        c = derive_runtime_capability_contract(ordin.review_action(unknown))
        assert c.tools == () and c.unknowns


def test_unknown_generic_tool_never_becomes_an_allowlist():
    action = ToolCallAdapter("agent").adapt("safe_read_file", {"path": "/repo/a"})
    c = derive_runtime_capability_contract(Ordin().review_action(action))
    assert c.tools == ()
    assert c.process.execution is None
    assert c.grant_state == "diagnostic"


@pytest.mark.parametrize(
    "effect,domain", [("filesystem.read", "filesystem"), ("network.upload", "network")]
)
def test_missing_resource_is_explicit(effect, domain):
    c = derive_runtime_capability_contract(reviewed(effect))
    assert any(
        u.domain == domain and u.reason_code == "runtime_contract_missing_resource"
        for u in c.unknowns
    )


@pytest.mark.parametrize(
    "path", ["relative", "/repo/../secret", "/repo/*", "/repo/$HOME", "//server/path", "a\\b"]
)
def test_ambiguous_paths_do_not_turn_into_wildcards(path):
    c = derive_runtime_capability_contract(
        reviewed("filesystem.read", resources=(ActionResource("path", path),))
    )
    assert c.filesystem[0].path is None and c.filesystem[0].scope == "unknown"
    assert c.unknowns


@pytest.mark.parametrize(
    "url",
    [
        "https://user:NEVER_RECORD_ME@api.example.com/a",
        "https://api.example.com/a?token=NEVER_RECORD_ME",
        "https://api.example.com/a#NEVER_RECORD_ME",
        "https://api.example.com:invalid/a",
    ],
)
def test_sensitive_and_malformed_urls_never_leak(url):
    c = derive_runtime_capability_contract(
        reviewed("network.upload", resources=(ActionResource("url", url),))
    )
    assert "NEVER_RECORD_ME" not in json.dumps(c.as_dict())
    assert c.network[0].host is None and c.unknowns
    assert c.credentials == ()


def test_raw_action_arguments_and_caller_credential_claims_are_not_copied():
    c = derive_runtime_capability_contract(
        reviewed(
            parameters={
                "command": "/usr/bin/demo NEVER_RECORD_ME",
                "credential_binding": "NEVER_RECORD_ME",
            }
        )
    )
    assert "NEVER_RECORD_ME" not in json.dumps(c.as_dict())
    assert c.credentials == ()


def test_schemas_round_trip_and_identity_tampering():
    c = derive_runtime_capability_contract(
        reviewed("filesystem.read", resources=(ActionResource("path", "/repo/a"),))
    )
    payload = c.as_dict()
    assert validate_named_schema("runtime_capability", payload) == []
    assert RuntimeCapabilityContract.from_dict(json.loads(json.dumps(payload))) == c
    payload["action_digest"] = "0" * 64
    with pytest.raises(ValueError, match="identity"):
        RuntimeCapabilityContract.from_dict(payload)
    assert resource_parity_errors() == []
    assert load_schema("runtime_capability") == SCHEMAS["runtime_capability"]


def test_nested_immutability_and_detached_serialization():
    c = derive_runtime_capability_contract(
        reviewed("filesystem.read", resources=(ActionResource("path", "/repo/a"),))
    )
    with pytest.raises(FrozenInstanceError):
        c.decision = "allow"
    with pytest.raises(TypeError):
        c.source["adapter"] = "other"
    with pytest.raises(FrozenInstanceError):
        c.filesystem[0].access = "write"
    payload = c.as_dict()
    payload["source"]["effects"].append("filesystem.write")
    assert "filesystem.write" not in c.source["effects"]
    p = ProcessCapability(True, ["/usr/bin/demo"], None)
    assert p.executables == ("/usr/bin/demo",)


def test_size_collection_and_strict_type_bounds():
    c = derive_runtime_capability_contract(reviewed())
    for kwargs in [
        {"filesystem": (FilesystemCapability("read", "/a"),) * 129},
        {"process": ProcessCapability(True, ("/a",) * 128), "source": {"x": "y"}},
        {"source": {"x": "z" * 4097}},
    ]:
        with pytest.raises(ValueError):
            replace(c, contract_id="", **kwargs)
    for make in [
        lambda: NetworkCapability("api.example.com", True),
        lambda: ProcessCapability(1),
        lambda: ProcessCapability(True, "demo"),
        lambda: NetworkCapability("api.example.com", 443, methods="GET"),
        lambda: FilesystemCapability("admin", "/a"),
        lambda: CredentialBinding("x", "api.example.com", 65536),
        lambda: CapabilityUnknown("invented", "x", "reason"),
    ]:
        with pytest.raises(ValueError):
            make()


@pytest.mark.parametrize(
    "decision,expected",
    [
        ("allow", "eligible"),
        ("warn", "requires_approval"),
        ("ask", "requires_approval"),
        ("block", "diagnostic"),
    ],
)
def test_grant_state_preserves_review_requirement(decision, expected):
    c = derive_runtime_capability_contract(reviewed(decision=decision))
    assert c.grant_state == expected


def test_derivation_performs_no_io_or_execution(monkeypatch):
    review = reviewed("filesystem.read", resources=(ActionResource("path", "/repo/a"),))

    def forbidden(*args, **kwargs):
        raise AssertionError("derivation crossed an I/O boundary")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert derive_runtime_capability_contract(review).filesystem


def test_existing_capability_profile_and_review_v1_remain_unchanged():
    review = Ordin().review_action(ActionEnvelope.shell("git status --short", action_id="one"))
    before = review.as_dict()
    derive_runtime_capability_contract(review)
    assert review.as_dict() == before
    assert before["schema_version"] == "ordin.action_review.v1"
    assert before["capabilities"]["schema_version"] == "ordin.execution_capabilities.v1"


def test_canonical_digest_handles_unicode_and_parameter_order():
    a = reviewed(parameters={"command": "/usr/bin/demo", "label": "résumé", "count": 3})
    b = replace(
        a,
        action=replace(
            a.action, parameters={"count": 3, "label": "résumé", "command": "/usr/bin/demo"}
        ),
    )
    assert derive_runtime_capability_contract(a) == derive_runtime_capability_contract(b)
    assert derive_runtime_capability_contract(a).action_digest == action_digest(a)


def test_ambiguous_effect_resource_association_is_explicit():
    c = derive_runtime_capability_contract(
        reviewed(
            "filesystem.read",
            "filesystem.write",
            resources=(
                ActionResource("path", "/repo/input"),
                ActionResource("path", "/repo/output"),
            ),
        )
    )
    assert any(u.reason_code == "runtime_contract_ambiguous_resource" for u in c.unknowns)
    assert c.grant_state == "diagnostic"


@pytest.mark.parametrize(
    "command",
    [
        "/usr/bin/demo && /usr/bin/other",
        "/usr/bin/demo | /usr/bin/other",
        "/usr/bin/demo > /tmp/out",
        "/usr/bin/demo $(/usr/bin/other)",
    ],
)
def test_compound_execution_never_becomes_a_single_program_permission(command):
    c = derive_runtime_capability_contract(reviewed(parameters={"command": command}))
    assert any(u.domain == "process" for u in c.unknowns)
    assert c.grant_state == "diagnostic"


def test_schema_and_model_reject_unrecognized_authority_fields():
    c = derive_runtime_capability_contract(reviewed())
    payload = c.as_dict()
    payload["credentials"] = [
        {
            "binding": "repo-write",
            "host": "api.example.com",
            "port": 443,
            "token": "NEVER_RECORD_ME",
        }
    ]
    with pytest.raises(ValueError):
        RuntimeCapabilityContract.from_dict(payload)
    payload = c.as_dict()
    payload["allow_all_network"] = True
    with pytest.raises(ValueError):
        RuntimeCapabilityContract.from_dict(payload)


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com:0/a",
        "https://api.example.com:65536/a",
        "https://api.example.com\n/a",
        "https://api_example.com/a",
    ],
)
def test_invalid_endpoints_keep_an_explicit_unknown(url):
    c = derive_runtime_capability_contract(
        reviewed("network.connect", resources=(ActionResource("url", url),))
    )
    assert c.network[0].host is None and c.network[0].port is None and c.unknowns
