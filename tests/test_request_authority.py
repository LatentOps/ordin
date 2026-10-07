from dataclasses import replace

import pytest

from ordin import ActionEnvelope, Ordin
from ordin._graphql_authority import graphql_authorities
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_requests_v2 import (
    NetworkAuthorityGrant,
    RequestAuthority,
    RuntimeRequestBoundaryV2,
    RuntimeRequestContractV2,
    derive_runtime_request_contract_v2,
    verify_runtime_request_authority,
)


@pytest.mark.parametrize(
    "body,kind,fields",
    [
        ({"query": "{ viewer { id name } }"}, "query", ["viewer", "viewer.id", "viewer.name"]),
        (
            {
                "query": "query Q($id: ID!, $show: Boolean = true) { x:user(id:$id) @include(if:$show) { ...F } } fragment F on User { id }",
                "variables": {"id": "a"},
            },
            "query",
            ["user", "user.id"],
        ),
        (
            {"query": "query A { one } mutation B { set(id:1) { ok } }", "operationName": "B"},
            "mutation",
            ["set", "set.ok"],
        ),
        ({"query": "subscription S { updates { id } }"}, "subscription", ["updates", "updates.id"]),
    ],
)
def test_full_graphql_operation_selection(body, kind, fields):
    authority = RequestAuthority.from_body("graphql", "https://api.example.com/graphql", body)
    assert authority.operations[0]["operation_type"] == kind
    assert list(authority.operations[0]["fields"]) == fields
    assert "query" not in authority.as_dict()


@pytest.mark.parametrize(
    "body",
    [
        {"query": "query A { one } query B { two }"},
        {"query": "query A { one }", "operationName": "B"},
        {"query": "{ ...Missing }"},
        {"query": "{ ...F } fragment F on Query { ...F }"},
        {"query": "{ user(id:1,id:2) }"},
        {"query": "{ user }", "extensions": {"unknown": True}},
        {"query": "{ user }", "variables": [1]},
        {"query": "query Q { user(id:$undefined) }"},
        {"query": "query Q { ...F } fragment F on Query { user(id:$undefined) }"},
        {
            "query": "query Q($id:ID) { ...F } query Other { ...F } fragment F on Query { user(id:$id) }",
            "operationName": "Q",
        },
    ],
)
def test_ambiguous_or_unmodeled_graphql_fails_closed(body):
    with pytest.raises(ValueError):
        RequestAuthority.from_body("graphql", "https://api.example.com/graphql", body)


def test_whole_batch_order_multiplicity_variables_and_directives_are_bound():
    a, b = {"query": "{ one }"}, {"query": "{ two }"}

    def authority(body):
        return RequestAuthority.from_body("graphql", "https://api.example.com/graphql", body)

    assert authority([a, b]).commitment != authority([b, a]).commitment
    assert authority([a]).commitment != authority([a, a]).commitment
    assert authority(a).commitment != authority({**a, "variables": None}).commitment
    assert authority(a).commitment != authority({"query": "{ one @skip(if:true) }"}).commitment


def test_derived_request_v2_is_action_bound_and_protocol_isolated():
    review = Ordin().review_action(
        ActionEnvelope(
            kind="network",
            operation="graphql.request",
            parameters={
                "url": "https://api.example.com/graphql",
                "query": "query Q($id:ID!) { user(id:$id) { name } }",
                "variables": {"id": "a"},
            },
        )
    )
    contract = derive_runtime_request_contract_v2(review)
    assert contract.requests and contract.capability.network[0].protocol == "graphql"
    assert RuntimeRequestContractV2.from_dict(contract.as_dict()) == contract
    maximum = RuntimeCapabilityBoundary("max", network=contract.capability.network)
    boundary = RuntimeRequestBoundaryV2(maximum, contract.requests)
    assert verify_runtime_request_authority(contract, boundary).ok
    changed = replace(contract.requests[0], commitment="0" * 64)
    assert (
        verify_runtime_request_authority(
            replace(contract, request_contract_id="", requests=(changed,)), boundary
        ).result
        == "exceeds_boundary"
    )
    other_protocol = replace(
        maximum, network=tuple(replace(n, protocol="rest") for n in maximum.network)
    )
    assert not verify_runtime_request_authority(
        contract, replace(boundary, boundary=other_protocol)
    ).ok


def test_generic_rpc_derives_exact_argument_and_batch_authority():
    body = [
        {"jsonrpc": "2.0", "id": 1, "method": "items/update", "params": {"id": "a"}},
        {"jsonrpc": "2.0", "method": "events/ack", "params": [3]},
    ]
    review = Ordin().review_action(
        ActionEnvelope(
            kind="network",
            operation="jsonrpc.request",
            parameters={"url": "https://api.example.com/rpc", "body": body},
        )
    )
    contract = derive_runtime_request_contract_v2(review)
    assert contract.requests[0].protocol == "json-rpc"
    assert len(contract.requests[0].calls) == 2
    assert contract.capability.network[0].access == "write"
    assert "items/update" in str(contract.as_dict()) and "params" not in str(contract.as_dict())


def test_generic_rpc_cannot_downgrade_unknown_effects_to_read():
    review = Ordin().review_action(
        ActionEnvelope(
            kind="network",
            operation="jsonrpc.request",
            parameters={
                "url": "https://api.example.com/rpc",
                "body": {"jsonrpc": "2.0", "id": 1, "method": "items/delete"},
            },
        )
    )
    request = derive_runtime_request_contract_v2(review)
    read_capability = replace(
        request.capability,
        contract_id="",
        network=tuple(replace(n, access="read") for n in request.capability.network),
    )
    downgraded = replace(request, request_contract_id="", capability=read_capability)
    maximum = RuntimeRequestBoundaryV2(
        RuntimeCapabilityBoundary("read-only", network=read_capability.network), request.requests
    )
    result = verify_runtime_request_authority(downgraded, maximum)
    assert result.result == "unsupported"
    assert "requests.jsonrpc_access_mismatch" in result.unsupported_fields


def test_opaque_sibling_cannot_borrow_another_requests_restrictions():
    review = Ordin().review_action(
        ActionEnvelope(
            kind="network",
            operation="graphql.request",
            parameters={"url": "https://api.example.com/graphql", "query": "{ user { id } }"},
        )
    )
    contract = derive_runtime_request_contract_v2(review)
    changed = replace(
        contract.capability,
        contract_id="",
        network=(
            *contract.capability.network,
            replace(contract.capability.network[0], tool_identity="opaque"),
        ),
    )
    maximum = RuntimeCapabilityBoundary("max", network=changed.network)
    result = verify_runtime_request_authority(
        replace(contract, request_contract_id="", capability=changed),
        RuntimeRequestBoundaryV2(maximum, contract.requests),
    )
    assert result.result == "unsupported"
    assert "requests.network_scope_unrepresentable" in result.unsupported_fields


def test_wildcard_network_grants_keep_protocol_and_port_boundaries():
    review = Ordin().review_action(
        ActionEnvelope(
            kind="network",
            operation="jsonrpc.request",
            parameters={
                "url": "https://api.corp.example/rpc",
                "body": {"jsonrpc": "2.0", "id": 1, "method": "lookup"},
            },
        )
    )
    contract = derive_runtime_request_contract_v2(review)
    grant = NetworkAuthorityGrant("*.corp.example", 443, "json-rpc", "write", ("POST",), ("/rpc",))
    maximum = RuntimeRequestBoundaryV2(
        RuntimeCapabilityBoundary("max"), contract.requests, (grant,)
    )
    assert verify_runtime_request_authority(contract, maximum).ok
    assert RuntimeRequestBoundaryV2.from_dict(maximum.as_dict()) == maximum
    assert not verify_runtime_request_authority(
        contract, replace(maximum, network_grants=(replace(grant, port=444),))
    ).ok
    assert not verify_runtime_request_authority(
        contract, replace(maximum, network_grants=(replace(grant, protocol="rest"),))
    ).ok


def test_more_than_128_nested_fields_follow_the_declared_v2_budget():
    fields = " ".join(f"f{i} {{ id }}" for i in range(70))
    authority = RequestAuthority.from_body(
        "graphql", "https://api.example.com/graphql", {"query": "{ " + fields + " }"}
    )
    assert len(authority.operations[0]["fields"]) == 140


@pytest.mark.parametrize(
    "query",
    [
        "{ user(ids:[01]) }",
        "{ user(ids:[1e2foo]) }",
        '{ user(value:[""""]) }',
        "{\u00a0user }",
        "{\vuser }",
        '{ user(value:"\\uD800") }',
        '{ user(value:"\\uD83D\\uDE42") }',
        '{ user(value:"\\u{1F642}") }',
    ],
)
def test_ambiguous_lexemes_and_unmodeled_pinned_escapes_fail_closed(query):
    with pytest.raises(ValueError):
        graphql_authorities({"query": query})


def test_pinned_scalar_escapes_and_literal_unicode_remain_supported():
    assert graphql_authorities({"query": '{ user(value:"\\u00e9🙂") { id } }'})
    assert graphql_authorities({"query": '{ user(value:"a\tb") { id } }'})


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com/rpc?",
        "https://api.example.com/rpc?&&",
        "https://api.example.com/rpc#",
    ],
)
def test_wire_query_or_fragment_delimiters_are_not_authorized(url):
    with pytest.raises(ValueError):
        RequestAuthority.from_body("json-rpc", url, {"jsonrpc": "2.0", "id": 1, "method": "lookup"})
