import builtins
import json
import socket
from dataclasses import replace
from pathlib import Path

import pytest

from ordin import ActionEnvelope, Ordin
from ordin.runtime_contract import (
    CapabilityUnknown,
    CredentialBinding,
    FilesystemCapability,
    NetworkCapability,
    PrivilegeCapability,
    ProcessCapability,
    ToolCapability,
    derive_runtime_capability_contract,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from ordin.schema import load_schema, resource_parity_errors, validate_named_schema
from ordin._runtime_schemas import SCHEMAS


def candidate(**kwargs):
    original = derive_runtime_capability_contract(
        Ordin().review_action(ActionEnvelope.shell("/usr/bin/git status", action_id="one"))
    )
    return replace(original, contract_id="", process=ProcessCapability(False), **kwargs)


def test_empty_contract_within_empty_boundary_has_complete_coverage():
    result = verify_runtime_capability(candidate(), RuntimeCapabilityBoundary("empty"))
    assert result.ok and result.result == "within_boundary"
    assert all(result.coverage.values()) and not result.unsupported_fields
    assert result.contract_digest == candidate().digest


@pytest.mark.parametrize("access", ["read", "write", "delete", "metadata", "execute"])
def test_exact_filesystem_access_and_resource_match(access):
    contract = candidate(filesystem=(FilesystemCapability(access, "/repo/file"),))
    boundary = RuntimeCapabilityBoundary(
        "files", filesystem=(FilesystemCapability(access, "/repo/file"),)
    )
    assert verify_runtime_capability(contract, boundary).ok
    other = replace(boundary, filesystem=(FilesystemCapability(access, "/repo/other"),))
    assert verify_runtime_capability(contract, other).result == "exceeds_boundary"


def test_access_lattice_does_not_equate_write_delete_or_execute():
    contract = candidate(filesystem=(FilesystemCapability("read", "/repo/file"),))
    write = RuntimeCapabilityBoundary(
        "write", filesystem=(FilesystemCapability("write", "/repo/file"),)
    )
    assert verify_runtime_capability(contract, write).result == "exceeds_boundary"
    metadata = candidate(filesystem=(FilesystemCapability("metadata", "/repo/file"),))
    read = RuntimeCapabilityBoundary(
        "read", filesystem=(FilesystemCapability("read", "/repo/file"),)
    )
    assert verify_runtime_capability(metadata, read).ok


def test_nested_filesystem_prefix_needs_explicit_semantics_and_runtime_guarantee():
    contract = candidate(filesystem=(FilesystemCapability("read", "/repo/src/file"),))
    boundary = RuntimeCapabilityBoundary(
        "repo", filesystem=(FilesystemCapability("read", "/repo", "prefix"),)
    )
    assert verify_runtime_capability(contract, boundary).result == "unsupported"
    lexical = replace(boundary, filesystem_semantics="lexical_prefix")
    assert verify_runtime_capability(contract, lexical).result == "unsupported"
    affirmed = replace(lexical, runtime_filesystem_guarantees=True)
    assert verify_runtime_capability(contract, affirmed).ok
    sibling = candidate(filesystem=(FilesystemCapability("read", "/repo-other/file"),))
    assert verify_runtime_capability(sibling, affirmed).result == "exceeds_boundary"


def test_unknown_scope_never_counts_as_proven_permission():
    contract = candidate(filesystem=(FilesystemCapability("read", "/repo/file"),))
    boundary = RuntimeCapabilityBoundary(
        "unknown", filesystem=(FilesystemCapability("read", "/repo/file", "unknown"),)
    )
    result = verify_runtime_capability(contract, boundary)
    assert result.result == "unsupported" and not result.coverage["filesystem"]


def network(method="GET", path="/repos/org/repo/issues/37", protocol="rest", access="read"):
    return NetworkCapability("api.example.com", 443, protocol, access, (method,), (path,))


def test_network_exact_endpoint_method_path_and_prefix_boundary():
    contract = candidate(network=(network(),))
    boundary = RuntimeCapabilityBoundary("api", network=(network(path="/repos/org/repo/**"),))
    assert verify_runtime_capability(contract, boundary).ok
    for modified in [
        network(method="DELETE", access="write"),
        network(path="/repos/other/repo/issues/37"),
        replace(network(), port=80),
        replace(network(), host="other.example.com"),
    ]:
        assert (
            verify_runtime_capability(candidate(network=(modified,)), boundary).result
            == "exceeds_boundary"
        )


def test_request_permissions_are_compared_as_method_path_pairs_across_rules():
    contract = candidate(network=(replace(network(), methods=("GET", "HEAD")),))
    boundary = RuntimeCapabilityBoundary("api", network=(network("GET"), network("HEAD")))
    assert verify_runtime_capability(contract, boundary).ok
    wrong_pairs = RuntimeCapabilityBoundary(
        "api", network=(network("GET", "/a"), network("POST", "/b", access="write"))
    )
    request = replace(network(), methods=("GET", "POST"), paths=("/a", "/b"), access="write")
    assert (
        verify_runtime_capability(candidate(network=(request,)), wrong_pairs).result
        == "exceeds_boundary"
    )


@pytest.mark.parametrize(
    "path", ["/a/%2F/private", "/a/../private", "/a//private", "/a?token=x", "/a/*"]
)
def test_encoded_ambiguous_and_wildcard_candidate_paths_fail_closed(path):
    result = verify_runtime_capability(
        candidate(network=(network(path=path),)),
        RuntimeCapabilityBoundary("api", network=(network(path="/**"),)),
    )
    assert result.result == "unsupported" and not result.ok


def test_rest_cannot_be_satisfied_by_protocol_downgrade_in_candidate():
    rest = RuntimeCapabilityBoundary("api", network=(network(),))
    tcp = NetworkCapability("api.example.com", 443, "tcp", "read")
    assert verify_runtime_capability(candidate(network=(tcp,)), rest).result == "exceeds_boundary"
    malformed = replace(tcp, methods=("GET",), paths=("/a",))
    assert verify_runtime_capability(candidate(network=(malformed,)), rest).result == "unsupported"


@pytest.mark.parametrize("protocol", ["mcp", "graphql", "json-rpc", "websocket"])
def test_unmodeled_protocols_preserve_unsupported_coverage(protocol):
    contract = candidate(network=(replace(network(), protocol=protocol),))
    boundary = RuntimeCapabilityBoundary("api", network=(network(),))
    result = verify_runtime_capability(contract, boundary)
    assert result.result == "unsupported" and result.unsupported_fields
    assert result.coverage["network"] is False


def test_unknown_contract_fields_are_explicit_non_success_even_with_other_covered_domains():
    contract = candidate(
        unknowns=(CapabilityUnknown("network", "unknown_protocol", "protocol unknown"),)
    )
    result = verify_runtime_capability(contract, RuntimeCapabilityBoundary("empty"))
    assert not result.ok and result.result == "unsupported"
    assert result.coverage["network"] is False
    assert result.coverage["filesystem"] is True


def test_credentials_require_independent_exact_binding_host_and_port():
    contract = candidate(
        network=(network(),), credentials=(CredentialBinding("repo-read", "api.example.com", 443),)
    )
    boundary = RuntimeCapabilityBoundary("api", network=(network(),))
    result = verify_runtime_capability(contract, boundary)
    assert result.result == "exceeds_boundary"
    assert result.reason_code == "credential_binding_exceeds_boundary"
    authorized = replace(boundary, credentials=contract.credentials)
    assert verify_runtime_capability(contract, authorized).ok
    expanded = replace(
        contract,
        contract_id="",
        credentials=(CredentialBinding("repo-write", "api.example.com", 443),),
    )
    assert verify_runtime_capability(expanded, authorized).result == "exceeds_boundary"


def test_exact_tool_identity_is_separate_from_network_access():
    contract = candidate(tools=(ToolCapability("mcp", "github", "get_issue"),))
    boundary = RuntimeCapabilityBoundary("tools", tools=contract.tools)
    assert verify_runtime_capability(contract, boundary).ok
    renamed = candidate(tools=(ToolCapability("mcp", "github-other", "get_issue"),))
    assert verify_runtime_capability(renamed, boundary).result == "exceeds_boundary"


def test_process_identity_child_scope_and_privilege_are_independent():
    base = candidate()
    contract = replace(
        base, contract_id="", process=ProcessCapability(True, ("/usr/bin/git",), False)
    )
    boundary = RuntimeCapabilityBoundary(
        "process", process=ProcessCapability(True, ("/usr/bin/git",), False)
    )
    assert verify_runtime_capability(contract, boundary).ok
    uncertain = replace(
        contract, contract_id="", process=ProcessCapability(True, ("/usr/bin/git",), None)
    )
    assert verify_runtime_capability(uncertain, boundary).result == "inconclusive"
    child = replace(
        contract, contract_id="", process=ProcessCapability(True, ("/usr/bin/git",), True)
    )
    assert verify_runtime_capability(child, boundary).result == "exceeds_boundary"
    privileged = replace(contract, contract_id="", privilege=PrivilegeCapability(True))
    assert verify_runtime_capability(privileged, boundary).result == "exceeds_boundary"


def test_blocked_decision_never_verifies_as_grantable():
    assert (
        verify_runtime_capability(
            candidate(decision="block"), RuntimeCapabilityBoundary("empty")
        ).result
        == "exceeds_boundary"
    )


def test_boundaries_are_immutable_round_trip_and_schema_parity_checked():
    boundary = RuntimeCapabilityBoundary("api", network=(network(),))
    assert (
        RuntimeCapabilityBoundary.from_dict(json.loads(json.dumps(boundary.as_dict()))) == boundary
    )
    assert validate_named_schema("runtime_capability_boundary", boundary.as_dict()) == []
    assert load_schema("runtime_capability_boundary") == SCHEMAS["runtime_capability_boundary"]
    assert resource_parity_errors() == []


def test_boundary_verification_performs_no_host_io_or_dns(monkeypatch):
    contract = candidate(network=(network(),))
    boundary = RuntimeCapabilityBoundary("api", network=(network(),))

    def forbidden(*args, **kwargs):
        raise AssertionError("boundary verification performed host I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    assert verify_runtime_capability(contract, boundary).ok
