import copy
import json
import os
import shutil
from dataclasses import replace

import pytest

from ordin import ActionEnvelope, AgentGate, IntegrationSession, Ordin, SessionIdentity
from ordin.runtime_contract import FilesystemCapability, NetworkCapability
from ordin.runtime_requirements import RuntimeRequirementProfile
from ordin.runtime_requests import (
    ProtocolRequestCapability,
    RuntimeRequestContract,
    RuntimeRequestBoundary,
    derive_runtime_request_contract,
    verify_runtime_request_capability,
    graphql_operation,
    request_endpoint,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.tool_calls import ToolSemanticRule, ToolSemanticsRegistry
from ordin_openshell.compiler import OpenShellBackend
from ordin_openshell.model import policy_errors, serialize_policy
from ordin_openshell.apply import (
    prepare_openshell_apply,
    apply_openshell_policy,
    canonical_runtime_policy,
)
from ordin_openshell.prover import verify_with_openshell_prover
from test_apply import FakeCLI
from ordin_openshell.shadow import ShadowCase, build_shadow_report, policy_request_match
from ordin.runtime_observation import RuntimeEvidenceSource


def profile(mcp=False):
    return RuntimeRequirementProfile(
        "request-client",
        (
            FilesystemCapability("read", "/usr", "prefix"),
            FilesystemCapability("execute", "/usr", "prefix"),
        ),
        spawn_children=True,
        client_executables=("/usr/bin/curl",),
        mcp_endpoints={"monitor": "https://api.example.com/mcp"} if mcp else {},
    )


def graphql_contract(query="query InspectStatus { status version }"):
    review = Ordin(runtime_requirements=profile()).review_action(
        ActionEnvelope(
            "network",
            "graphql.request",
            {"url": "https://api.example.com/graphql", "query": query},
            action_id="graphql",
        )
    )
    return review, derive_runtime_request_contract(review)


def mcp_contract(arguments=None, *, version=None, declared=None):
    rules = ToolSemanticsRegistry(
        "request-test",
        "1",
        (
            ToolSemanticRule(
                "read-status", "mcp", "read_status", ("network.download",), server="monitor"
            ),
        ),
    )
    action = ActionEnvelope(
        "mcp",
        "call",
        {
            "server": "monitor",
            "tool": "read_status",
            "arguments": arguments or {},
            **({"protocol_version": version} if version is not None else {}),
        },
        action_id="mcp",
    )
    deployment = profile(True)
    if declared is not None:
        deployment = replace(deployment, mcp_versions={"monitor": declared})
    review = Ordin(tool_semantics=rules, runtime_requirements=deployment).review_action(action)
    return review, derive_runtime_request_contract(review)


def request_boundary(contract):
    base = contract.capability
    return RuntimeRequestBoundary(
        RuntimeCapabilityBoundary(
            "maximum",
            filesystem=base.filesystem,
            network=base.network,
            tools=base.tools,
            process=base.process,
            privilege=base.privilege,
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        ),
        contract.requests,
    )


@pytest.mark.parametrize("factory", [graphql_contract, mcp_contract])
def test_derived_protocol_contract_preserves_action_decision_and_exact_source(factory):
    review, request = factory()
    base = request.capability
    assert (
        base.unknowns == ()
        and base.decision == review.decision
        and base.source["provenance_digest"] == review.provenance.digest
    )
    assert base.process.executables == ("/usr/bin/curl",) and base.process.execution is True
    assert RuntimeRequestContract.from_dict(request.as_dict()) == request
    assert RuntimeRequestBoundary.from_dict(
        request_boundary(request).as_dict()
    ) == request_boundary(request)
    assert verify_runtime_request_capability(request, request_boundary(request)).ok
    assert OpenShellBackend((1000, 1000)).compile(base).status == "unsupported"


@pytest.mark.parametrize(
    "query",
    [
        "query Q($id: ID!){ status(id:$id) }",
        "query Q { a::status }",
        "query Q { ...F }",
        "query Q { status }; mutation X { delete }",
    ],
)
def test_unmodeled_graphql_input_remains_diagnostic_without_erasing_semantics(query):
    review, contract = graphql_contract(query)
    assert review.decision == "ask" and contract.capability.grant_state == "diagnostic"
    assert (
        OpenShellBackend((1000, 1000), request_contract=contract)
        .compile(contract.capability)
        .status
        == "unsupported"
    )


def test_graphql_golden_and_independent_field_operation_boundary():
    review, request = graphql_contract()
    backend = OpenShellBackend((1000, 1000), request_contract=request)
    result = backend.compile(request.capability)
    assert result.status == "success", result.as_dict()
    endpoint = next(iter(result.plan.policy["network_policies"].values()))["endpoints"][0]
    assert endpoint["protocol"] == "graphql" and endpoint["path"] == "/graphql"
    assert endpoint["rules"][0]["allow"] == {
        "operation_type": "query",
        "operation_name": "InspectStatus",
        "fields": ("status", "version"),
    }
    assert result.plan.metadata["request_contract_digest"] == request.digest
    assert backend.validate(result.plan).ok
    for changed in (
        replace(request.requests[0], fields=("secret",)),
        replace(request.requests[0], operation_name="Another"),
    ):
        bad = replace(request, requests=(changed,), request_contract_id="")
        assert (
            verify_runtime_request_capability(bad, request_boundary(request)).result
            == "exceeds_boundary"
        )
    mutation_review, mutation = graphql_contract("mutation DeleteStatus { deleteStatus }")
    assert "network.upload" in mutation_review.effects and mutation_review.decision == "warn"
    assert not verify_runtime_request_capability(mutation, request_boundary(request)).ok
    forged = result.plan.as_dict()["policy"]
    next(iter(forged["network_policies"].values()))["endpoints"][0]["rules"][0]["allow"][
        "fields"
    ].append("secret")
    assert not backend.validate(replace(result.plan, policy=forged)).ok


def test_mcp_golden_exact_tool_version_and_method_default():
    _, request = mcp_contract()
    backend = OpenShellBackend((1000, 1000), request_contract=request)
    result = backend.compile(request.capability)
    assert result.status == "success", result.as_dict()
    endpoint = next(iter(result.plan.policy["network_policies"].values()))["endpoints"][0]
    assert endpoint["mcp"] == {
        "strict_tool_names": True,
        "allow_all_known_mcp_methods": False,
        "versions": ("2025-11-25",),
    }
    assert endpoint["rules"][0]["allow"] == {
        "method": "tools/call",
        "params": {"name": {"any": ("read_status",)}},
    }
    assert (
        canonical_runtime_policy(result.plan.as_dict()["policy"]) == result.plan.as_dict()["policy"]
    )
    native_alias = result.plan.as_dict()["policy"]
    native_allow = next(iter(native_alias["network_policies"].values()))["endpoints"][0]["rules"][
        0
    ]["allow"]
    native_allow["tool"] = native_allow.pop("params")["name"]
    assert canonical_runtime_policy(native_alias) == result.plan.as_dict()["policy"]
    wider = replace(request.requests[0], versions=("2025-06-18", "2025-11-25"))
    assert (
        verify_runtime_request_capability(
            replace(request, requests=(wider,), request_contract_id=""), request_boundary(request)
        ).result
        == "exceeds_boundary"
    )
    _, with_args = mcp_contract({"path": "/etc/passwd"})
    rejected = OpenShellBackend((1000, 1000), request_contract=with_args).compile(
        with_args.capability
    )
    assert (
        rejected.status == "unsupported"
        and "requests.argument_constraints_unrepresentable" in rejected.unsupported_fields
    )


def test_mcp_without_trusted_transport_or_semantic_binding_cannot_gain_authority():
    action = ActionEnvelope(
        "mcp",
        "call",
        {"server": "monitor", "tool": "read_status", "arguments": {}},
        action_id="unknown",
    )
    unknown = Ordin(runtime_requirements=profile(True)).review_action(action)
    assert derive_runtime_request_contract(unknown).capability.grant_state == "diagnostic"
    known, request = mcp_contract()
    spoofed = replace(
        request,
        requests=(replace(request.requests[0], server="another-server"),),
        request_contract_id="",
    )
    assert (
        OpenShellBackend((1000, 1000), request_contract=spoofed).compile(spoofed.capability).status
        == "unsupported"
    )


def test_protocol_apply_requires_request_boundary_and_exact_request_approval():
    _, request = graphql_contract()
    backend = OpenShellBackend((1000, 1000), request_contract=request)
    plan = backend.compile(request.capability).plan
    cli = FakeCLI(plan)
    assert (
        prepare_openshell_apply(plan, backend=backend, sandbox="demo", cli=cli).reason_code
        == "runtime_request_boundary_required"
    )
    prepared = prepare_openshell_apply(
        plan, backend=backend, sandbox="demo", cli=cli, request_boundary=request_boundary(request)
    )
    assert prepared.status == "requires_approval", prepared.as_dict()
    result = apply_openshell_policy(
        plan,
        backend=backend,
        sandbox="demo",
        cli=cli,
        request_boundary=request_boundary(request),
        approval_request_id=prepared.request_id,
    )
    assert result.status == "applied" and cli.set_calls == 1
    empty = replace(request_boundary(request), requests=())
    assert (
        prepare_openshell_apply(
            plan, backend=backend, sandbox="demo", cli=cli, request_boundary=empty
        ).status
        == "exceeds_boundary"
    )


@pytest.mark.parametrize("factory", [graphql_contract, mcp_contract])
def test_real_prover_explicitly_refuses_unmodeled_protocol_coverage(factory, tmp_path):
    executable = os.environ.get("ORDIN_OPENSHELL_PROVER", "openshell-prover")
    if shutil.which(executable) is None:
        pytest.skip("standalone OpenShell prover unavailable")
    _, request = factory()
    plan = OpenShellBackend((1000, 1000), request_contract=request).compile(request.capability).plan
    candidate = tmp_path / "candidate.json"
    candidate.write_text(serialize_policy(plan.policy))
    proof = verify_with_openshell_prover(candidate, candidate, executable=executable)
    assert proof.result == "unsupported" and not proof.ok, proof.as_dict()


def test_immutable_request_fields_and_digest_replay_fail_closed():
    _, request = graphql_contract()
    data = request.as_dict()
    data["requests"][0]["fields"].append("secret")
    with pytest.raises(ValueError):
        RuntimeRequestContract.from_dict(data)
    assert request.requests[0].fields == ("status", "version")
    with pytest.raises(ValueError):
        replace(request.requests[0], fields=("*",))
    with pytest.raises(ValueError):
        replace(mcp_contract()[1].requests[0], versions=("latest",))


def test_protocol_shadow_uses_request_boundary_without_claiming_missing_event_fields():
    _, request = graphql_contract()
    maximum = request_boundary(request)
    backend = OpenShellBackend((1000, 1000), mode="shadow", request_contract=request)
    report = build_shadow_report(
        (
            ShadowCase(
                request.capability, maximum.boundary, backend=backend, request_boundary=maximum
            ),
        )
    )
    assert report.metrics["contracts_fully_representable"] == 1
    assert report.boundary_outcomes["within_boundary"] == 1
    assert report.as_dict()["mode"] == "shadow"
    source = RuntimeEvidenceSource("openshell", "a" * 64, "sandbox", "b" * 64)
    observation = source.observe(
        request.capability,
        observation_id="http-only",
        trust="backend_observed",
        enforcement_point="network",
        outcome="allowed",
        operation="http.request",
        metadata={
            "host": "api.example.com",
            "port": 443,
            "path": "/graphql",
            "method": "POST",
            "binary": "/usr/bin/curl",
        },
    )
    assert (
        policy_request_match(backend.compile(request.capability).plan, observation)
        == "inconclusive"
    )


def test_mismatched_boundary_protocol_and_opaque_identity_fail_closed():
    _, request = graphql_contract()
    maximum = request_boundary(request)
    wrong_network = tuple(replace(n, protocol="mcp") for n in maximum.boundary.network)
    wrong = replace(maximum, boundary=replace(maximum.boundary, network=wrong_network))
    assert verify_runtime_request_capability(request, wrong).result == "unsupported"
    opaque = replace(
        request.capability,
        contract_id="",
        network=tuple(replace(n, tool_identity="opaque") for n in request.capability.network),
    )
    altered = replace(request, capability=opaque, request_contract_id="")
    assert (
        OpenShellBackend((1000, 1000), request_contract=altered).compile(opaque).status
        == "unsupported"
    )


@pytest.mark.parametrize(
    "factory",
    [
        graphql_contract,
        mcp_contract,
        pytest.param(
            lambda: graphql_contract("mutation DeleteStatus { deleteStatus }"),
            id="graphql_mutation",
        ),
    ],
)
def test_raw_http_cannot_borrow_protocol_request_authority(factory):
    _, request = factory()
    raw = RuntimeRequestContract(
        replace(
            request.capability,
            contract_id="",
            tools=(),
            network=tuple(replace(n, protocol="rest") for n in request.capability.network),
        ),
        (),
    )
    if raw.capability.network[0].access == "write":
        assert OpenShellBackend((1000, 1000)).compile(raw.capability).status == "success"
    assert (
        verify_runtime_request_capability(raw, request_boundary(request)).result
        == "exceeds_boundary"
    )
    # Explicit HTTP authority remains usable, including beside protocol restrictions.
    maximum = request_boundary(request)
    explicit = replace(
        maximum,
        boundary=replace(
            maximum.boundary, network=maximum.boundary.network + raw.capability.network
        ),
    )
    assert verify_runtime_request_capability(raw, explicit).ok
    mixed = replace(
        request,
        capability=replace(
            request.capability,
            contract_id="",
            network=request.capability.network + raw.capability.network,
        ),
        request_contract_id="",
    )
    assert verify_runtime_request_capability(mixed, maximum).result == "exceeds_boundary"


@pytest.mark.parametrize("factory", [graphql_contract, mcp_contract])
def test_opaque_boundary_tool_identity_is_never_discarded(factory):
    _, request = factory()
    maximum = request_boundary(request)
    restricted = replace(
        maximum,
        boundary=replace(
            maximum.boundary,
            network=tuple(replace(n, tool_identity="opaque") for n in maximum.boundary.network),
        ),
    )
    result = verify_runtime_request_capability(request, restricted)
    assert result.result == "unsupported" and not result.ok


@pytest.mark.parametrize("authority", ["@api.example.com", ":@api.example.com"])
def test_request_endpoints_reject_even_empty_userinfo(authority):
    assert request_endpoint("https://" + authority + "/graphql") is None


@pytest.mark.parametrize("protocol", [[], {}, ["rest"]])
def test_malformed_policy_protocol_is_a_validation_error(protocol):
    _, request = graphql_contract()
    plan = OpenShellBackend((1000, 1000), request_contract=request).compile(request.capability).plan
    policy = plan.as_dict()["policy"]
    endpoint = next(iter(policy["network_policies"].values()))["endpoints"][0]
    endpoint["protocol"] = protocol
    assert "network_policies.request_inspection" in policy_errors(policy)


@pytest.mark.parametrize(
    "entry",
    [None, [], {"allow": None}, {"allow": []}, {"allow": {"params": None}}],
)
def test_malformed_mcp_readback_returns_unsupported_before_apply(entry):
    _, request = mcp_contract()
    backend = OpenShellBackend((1000, 1000), request_contract=request)
    plan = backend.compile(request.capability).plan
    policy = plan.as_dict()["policy"]
    next(iter(policy["network_policies"].values()))["endpoints"][0]["rules"] = [entry]
    with pytest.raises(ValueError, match="openshell_policy"):
        canonical_runtime_policy(policy)
    cli = FakeCLI(plan)
    cli.policy = policy
    result = prepare_openshell_apply(
        plan, backend=backend, sandbox="demo", cli=cli, request_boundary=request_boundary(request)
    )
    assert result.status == "unsupported" and cli.set_calls == 0


@pytest.mark.parametrize(
    "query",
    [
        "query InspectStatus { current:status version }",
        "# comment\nquery InspectStatus { status, version # another comment\n}",
        "query InspectStatus { ...Status } fragment Status on Query { current:status version }",
        "fragment Status on Query { status version } query InspectStatus { ...Status }",
        "query InspectStatus { ... on Query { status version } }",
        "query InspectStatus { ...A } fragment A on Query { status ...B } fragment B on Query { version }",
    ],
)
def test_equivalent_graphql_syntax_preserves_exact_backend_field_authority(query):
    _, original = graphql_contract()
    review, request = graphql_contract(query)
    assert review.decision == "allow" and request.requests == original.requests
    assert request.capability.action_digest != original.capability.action_digest
    result = OpenShellBackend((1000, 1000), request_contract=request).compile(request.capability)
    assert result.status == "success"
    endpoint = next(iter(result.plan.policy["network_policies"].values()))["endpoints"][0]
    assert endpoint["rules"][0]["allow"]["fields"] == ("status", "version")
    assert verify_runtime_request_capability(request, request_boundary(original)).ok


@pytest.mark.parametrize(
    "query",
    [
        "query InspectStatus { status:secret version }",
        "query InspectStatus { ...Fields } fragment Fields on Query { secret version }",
    ],
)
def test_aliases_and_fragments_cannot_disguise_field_expansion(query):
    _, original = graphql_contract()
    _, expanded = graphql_contract(query)
    assert expanded.requests[0].fields == ("secret", "version")
    assert (
        verify_runtime_request_capability(expanded, request_boundary(original)).result
        == "exceeds_boundary"
    )


@pytest.mark.parametrize(
    "query",
    [
        "query Q { a:status a:secret }",
        "query Q { ...A } fragment A on Query { ...A }",
        "query Q { ...A } fragment A on Query { ...B } fragment B on Query { ...A }",
        "query Q { status } fragment Unused on Query { secret }",
        "query Q { ...Missing }",
        "query Q { ...A } fragment A on Query { status } fragment A on Query { secret }",
        "query Q { status } query Other { secret }",
    ],
)
def test_ambiguous_or_unenforceable_graphql_documents_stay_diagnostic(query):
    review, request = graphql_contract(query)
    assert review.decision == "ask" and not request.requests
    assert (
        OpenShellBackend((1000, 1000), request_contract=request).compile(request.capability).status
        == "unsupported"
    )


def protocol_contract(method="tools/list", version="2025-11-25", declared=None, params=None):
    deployment = profile(True)
    if declared is not None:
        deployment = replace(deployment, mcp_versions={"monitor": declared})
    action = ActionEnvelope(
        "mcp",
        "protocol.request",
        {
            "server": "monitor",
            "method": method,
            "protocol_version": version,
            "params": {} if params is None else params,
        },
        action_id="protocol",
    )
    review = Ordin(runtime_requirements=deployment).review_action(action)
    return review, derive_runtime_request_contract(review)


@pytest.mark.parametrize("method", ["ping", "tools/list", "notifications/initialized"])
def test_known_mcp_control_methods_require_exact_transport_method_and_version(method):
    review, request = protocol_contract(method)
    assert review.adapter == "mcp.protocol" and request.capability.unknowns == ()
    assert request.capability.tools == ()
    assert request.requests[0].method == method and request.requests[0].tool is None
    assert verify_runtime_request_capability(request, request_boundary(request)).ok
    plan = OpenShellBackend((1000, 1000), request_contract=request).compile(request.capability).plan
    assert plan is not None
    endpoint = next(iter(plan.policy["network_policies"].values()))["endpoints"][0]
    assert endpoint["rules"][0]["allow"] == {"method": method}
    changed = replace(
        request,
        requests=(
            replace(request.requests[0], method="tools/list" if method == "ping" else "ping"),
        ),
        request_contract_id="",
    )
    assert (
        verify_runtime_request_capability(changed, request_boundary(request)).result
        == "exceeds_boundary"
    )


@pytest.mark.parametrize("version", ["2025-03-26", "2025-06-18"])
def test_older_mcp_versions_need_explicit_host_approval(version):
    _, denied = protocol_contract(version=version)
    assert denied.capability.grant_state == "diagnostic" and not denied.requests
    assert any(
        u.reason_code == "runtime_contract_mcp_version_unapproved"
        for u in denied.capability.unknowns
    )
    _, approved = protocol_contract(version=version, declared=(version,))
    assert approved.requests[0].versions == (version,) and approved.capability.unknowns == ()
    result = OpenShellBackend((1000, 1000), request_contract=approved).compile(approved.capability)
    assert result.status == "success"
    endpoint = next(iter(result.plan.policy["network_policies"].values()))["endpoints"][0]
    assert endpoint["mcp"]["versions"] == (version,)
    _, latest = protocol_contract()
    assert (
        verify_runtime_request_capability(approved, request_boundary(latest)).result
        == "exceeds_boundary"
    )


@pytest.mark.parametrize(
    "method,params",
    [
        ("tools/call", {}),
        ("tools/delete", {}),
        ("initialize", {}),
        ("ping", []),
    ],
)
def test_unknown_or_parameterized_mcp_control_actions_cannot_gain_authority(method, params):
    review, request = protocol_contract(method, params=params)
    assert review.decision == "ask" and request.capability.grant_state == "diagnostic"
    assert (
        OpenShellBackend((1000, 1000), request_contract=request).compile(request.capability).status
        == "unsupported"
    )


def test_control_method_names_do_not_establish_transport_authority():
    action = ActionEnvelope(
        "mcp", "protocol.request", {"server": "monitor", "method": "ping"}, action_id="unbound"
    )
    request = derive_runtime_request_contract(Ordin().review_action(action))
    assert not request.requests and request.capability.grant_state == "diagnostic"


@pytest.mark.parametrize("version", ["latest", True])
def test_unknown_control_protocol_versions_remain_unknown_actions(version):
    review, request = protocol_contract(version=version)
    assert review.decision == "ask" and request.capability.grant_state == "diagnostic"


@pytest.mark.parametrize("version", ["2025-03-26", "2025-06-18"])
def test_exact_mcp_tools_can_use_only_host_approved_older_versions(version):
    _, unapproved = mcp_contract(version=version)
    assert unapproved.capability.grant_state == "diagnostic" and not unapproved.requests
    _, approved = mcp_contract(version=version, declared=(version,))
    assert approved.capability.unknowns == () and approved.requests[0].versions == (version,)
    assert (
        OpenShellBackend((1000, 1000), request_contract=approved)
        .compile(approved.capability)
        .status
        == "success"
    )
    _, with_args = mcp_contract(
        {"secret": "REJECTED_ARGUMENT_VALUE"}, version=version, declared=(version,)
    )
    rejected = OpenShellBackend((1000, 1000), request_contract=with_args).compile(
        with_args.capability
    )
    assert rejected.status == "unsupported" and "REJECTED_ARGUMENT_VALUE" not in json.dumps(
        rejected.as_dict()
    )


@pytest.mark.parametrize("versions", [(), ("latest",), ("2025-06-18", "2025-06-18"), (True,)])
def test_host_version_profile_is_bounded_and_exact(versions):
    with pytest.raises(ValueError, match="runtime_requirement_mcp_versions_invalid"):
        replace(profile(True), mcp_versions={"monitor": versions})


def test_conflicting_host_version_declarations_do_not_union_authority():
    review, _ = protocol_contract(version="2025-06-18", declared=("2025-06-18",))
    stricter = replace(profile(True), mcp_versions={"monitor": ("2025-11-25",)})
    request = derive_runtime_request_contract(stricter.declare(review))
    assert request.capability.grant_state == "diagnostic" and not request.requests


def test_graphql_parser_work_is_bounded_and_performs_no_io(monkeypatch):
    import builtins
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("GraphQL scope parsing crossed an I/O boundary")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert graphql_operation("query Q { ...F } fragment F on Query { a:status }") == (
        "query",
        "Q",
        ("status",),
    )
    assert graphql_operation("query Q { " + "status " * 1000 + "}") is None
    chain = (
        "query Q { ...F0 } "
        + " ".join(
            "fragment F" + str(i) + " on Query { ...F" + str(i + 1) + " }" for i in range(20)
        )
        + " fragment F20 on Query { status }"
    )
    assert graphql_operation(chain) is None
