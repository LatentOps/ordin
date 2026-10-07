from dataclasses import replace

import pytest

from ordin import ActionEnvelope, Ordin
from ordin.runtime_contract import FilesystemCapability, ProcessCapability, NetworkCapability
from ordin.runtime_requests_v2 import derive_runtime_request_contract_v2
from ordin_openshell.compiler import OpenShellBackend, compile_openshell_policy
from ordin_openshell.model import policy_errors
from ordin_openshell.address_scope import validate_network_scopes


def supported_request(operation, body, url="https://api.example.com/rpc"):
    review = Ordin().review_action(
        ActionEnvelope(
            kind="network",
            operation=operation,
            action_id="request-fixture",
            parameters={"url": url, "body": body},
        )
    )
    request = derive_runtime_request_contract_v2(review)
    capability = replace(
        request.capability,
        contract_id="",
        filesystem=(
            FilesystemCapability("read", "/usr", "prefix"),
            FilesystemCapability("execute", "/usr", "prefix"),
        ),
        process=ProcessCapability(True, ("/usr/bin/curl",), True),
    )
    return replace(request, capability=capability, request_contract_id="")


@pytest.mark.parametrize(
    "operation,body",
    [
        (
            "graphql.request",
            {
                "query": "query Q($id:ID!){ user(id:$id){ name } }",
                "variables": {"id": "secret-test-value"},
            },
        ),
        (
            "graphql.request",
            [{"query": "{ user { name } }"}, {"query": "subscription S { updates { id } }"}],
        ),
        (
            "jsonrpc.request",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "items/update",
                "params": {"key": "secret-test-value"},
            },
        ),
    ],
)
def test_compiler_intersects_protocol_scope_with_full_request_commitment(operation, body):
    request = supported_request(operation, body)
    backend = OpenShellBackend((1000, 1000), request_contract=request)
    result = backend.compile(request.capability)
    assert result.enforceable, result.unsupported_fields
    assert backend.validate(result.plan).ok
    assert policy_errors(result.plan.policy) == ()
    endpoint = next(iter(result.plan.policy["network_policies"].values()))["endpoints"][0]
    assert endpoint["request_integrity"]["commitments"] == (request.requests[0].commitment,)
    assert "secret-test-value" not in str(result.plan.as_dict())
    assert result.plan.metadata["runtime_extension"] == "ordin.request-authority.v1"


def test_host_approved_private_ranges_and_wildcards_expand_to_exact_action_endpoint():
    request = supported_request(
        "jsonrpc.request",
        {"jsonrpc": "2.0", "id": 1, "method": "lookup", "params": {}},
        "https://tools.corp.internal/rpc",
    )
    assert not compile_openshell_policy(
        request.capability, process_identity=(1000, 1000), request_contract=request
    ).enforceable
    scope = {
        "host": "*.corp.internal",
        "port": 443,
        "protocols": ["json-rpc"],
        "allowed_ips": ["10.50.0.0/24"],
    }
    result = compile_openshell_policy(
        request.capability,
        process_identity=(1000, 1000),
        request_contract=request,
        network_scopes=(scope,),
    )
    assert result.enforceable, result.unsupported_fields
    endpoint = next(iter(result.plan.policy["network_policies"].values()))["endpoints"][0]
    assert endpoint["host"] == "tools.corp.internal"
    assert endpoint["allowed_ips"] == ("10.50.0.0/24",)
    conflict = {**scope, "allowed_ips": ["10.51.0.0/24"]}
    assert not compile_openshell_policy(
        request.capability,
        process_identity=(1000, 1000),
        request_contract=request,
        network_scopes=(scope, conflict),
    ).enforceable


@pytest.mark.parametrize(
    "network",
    ["127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/0", "::1/128", "fe80::/10", "::ffff:0:0/96"],
)
def test_private_approval_cannot_include_protected_destinations(network):
    with pytest.raises(ValueError, match="openshell_network_scope_invalid"):
        validate_network_scopes(
            [
                {
                    "host": "*.corp.internal",
                    "port": 443,
                    "protocols": ["mcp"],
                    "allowed_ips": [network],
                }
            ]
        )


def test_tcp_compilation_only_grants_connection_authority():
    request = supported_request("jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "lookup"})
    capability = replace(
        request.capability,
        contract_id="",
        network=(NetworkCapability("db.example.com", 5432, "tcp", "write"),),
    )
    result = compile_openshell_policy(capability, process_identity=(1000, 1000))
    assert result.enforceable, result.unsupported_fields
    endpoint = next(iter(result.plan.policy["network_policies"].values()))["endpoints"][0]
    assert set(endpoint) == {"host", "port", "protocol", "allowed_ips"}


def test_literal_tcp_is_exact_and_requires_confirmed_runtime_support():
    request = supported_request("jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "lookup"})
    capability = replace(
        request.capability,
        contract_id="",
        network=(NetworkCapability("8.8.8.8", 853, "tcp", "write"),),
    )
    result = compile_openshell_policy(capability, process_identity=(1000, 1000))
    assert result.enforceable, result.unsupported_fields
    assert result.plan.metadata["runtime_extension"] == "ordin.request-authority.v1"
    endpoint = next(iter(result.plan.policy["network_policies"].values()))["endpoints"][0]
    assert endpoint["host"] == "8.8.8.8" and endpoint["port"] == 853


def test_generic_rpc_read_downgrade_is_not_enforceable():
    request = supported_request(
        "jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "items/delete"}
    )
    capability = replace(
        request.capability,
        contract_id="",
        network=tuple(replace(n, access="read") for n in request.capability.network),
    )
    request = replace(request, request_contract_id="", capability=capability)
    result = OpenShellBackend((1000, 1000), request_contract=request).compile(capability)
    assert not result.enforceable
    assert "requests.jsonrpc_access_mismatch" in result.unsupported_fields


@pytest.mark.parametrize(
    "alias", ["host.openshell.internal", "host.containers.internal", "host.docker.internal"]
)
def test_driver_aliases_cannot_bypass_operator_address_ranges(alias):
    with pytest.raises(ValueError):
        validate_network_scopes(
            [
                {
                    "host": alias,
                    "port": 443,
                    "protocols": ["json-rpc"],
                    "allowed_ips": ["10.50.0.0/24"],
                }
            ]
        )
