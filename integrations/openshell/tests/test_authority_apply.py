from test_apply import FakeCLI, boundary_for
from dataclasses import replace
import json
from ordin.runtime_contract import NetworkCapability
from test_authority_compiler import supported_request
from ordin.runtime_requests_v2 import RuntimeRequestBoundaryV2
from ordin_openshell import extension
from ordin_openshell.apply import apply_openshell_policy, prepare_openshell_apply
from ordin_openshell.compiler import OpenShellBackend
from ordin_openshell.apply_audit import PolicyApplyAudit


def test_post_mutation_runtime_identity_failure_records_an_inconclusive_receipt(
    monkeypatch, tmp_path
):
    request = supported_request("jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "lookup"})
    backend = OpenShellBackend((1000, 1000), request_contract=request)
    plan = backend.compile(request.capability).plan
    boundary = RuntimeRequestBoundaryV2(boundary_for(request.capability), request.requests)
    cli = FakeCLI(plan)
    monkeypatch.setattr(extension, "expected_runtime_identity", lambda: {"source_digest": "a" * 64})
    original = cli.json

    def attested(arguments, **kwargs):
        value = original(arguments, **kwargs)
        if arguments[:2] == ("sandbox", "get"):
            value["configuration_admission"].update(
                runtime_extension_id=extension.EXTENSION_ID,
                runtime_source_digest=("b" if cli.set_calls else "a") * 64,
                gateway_source_digest="a" * 64,
                cli_source_digest="a" * 64,
            )
        return value

    cli.json = attested
    options = dict(backend=backend, sandbox="demo", cli=cli, request_boundary=boundary)
    prepared = prepare_openshell_apply(plan, **options)
    assert prepared.status == "requires_approval"
    audit = PolicyApplyAudit(tmp_path / "apply.jsonl")
    result = apply_openshell_policy(
        plan, approval_request_id=prepared.request_id, audit=audit, **options
    )
    assert result.status == "inconclusive" and result.mutation_attempted
    assert cli.set_calls == 1
    assert audit.verify()["events"] == 2
    assert [json.loads(line)["outcome"] for line in audit.path.read_text().splitlines()] == [
        "attempted",
        "inconclusive",
    ]


def test_extended_apply_requires_actual_cli_gateway_and_supervisor_build_identity(monkeypatch):
    request = supported_request("jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "lookup"})
    backend = OpenShellBackend((1000, 1000), request_contract=request)
    plan = backend.compile(request.capability).plan
    boundary = RuntimeRequestBoundaryV2(boundary_for(request.capability), request.requests)
    cli = FakeCLI(plan)
    monkeypatch.setattr(extension, "expected_runtime_identity", lambda: {"source_digest": "a" * 64})
    prepared = prepare_openshell_apply(
        plan,
        backend=backend,
        sandbox="demo",
        cli=cli,
        request_boundary=boundary,
        capability_boundary=boundary.boundary,
    )
    assert (
        prepared.status == "unsupported"
        and prepared.reason_code == "openshell_runtime_extension_mismatch"
    )
    assert cli.set_calls == 0
    original = cli.json
    identity = {
        "runtime_extension_id": extension.EXTENSION_ID,
        "runtime_source_digest": "a" * 64,
        "gateway_source_digest": "a" * 64,
        "cli_source_digest": "a" * 64,
    }

    def attested(arguments, **kwargs):
        value = original(arguments, **kwargs)
        if arguments[:2] == ("sandbox", "get"):
            value["configuration_admission"].update(identity)
        return value

    cli.json = attested
    too_small = prepare_openshell_apply(
        plan,
        backend=backend,
        sandbox="demo",
        cli=cli,
        request_boundary=boundary,
        capability_boundary=replace(boundary.boundary, network=()),
    )
    assert too_small.status == "exceeds_boundary", too_small.reason_code
    assert cli.set_calls == 0
    prepared = prepare_openshell_apply(
        plan,
        backend=backend,
        sandbox="demo",
        cli=cli,
        request_boundary=boundary,
        capability_boundary=boundary.boundary,
    )
    assert prepared.status == "requires_approval", prepared.reason_code
    result = apply_openshell_policy(
        plan,
        backend=backend,
        sandbox="demo",
        cli=cli,
        request_boundary=boundary,
        capability_boundary=boundary.boundary,
        approval_request_id=prepared.request_id,
    )
    assert result.status == "applied" and cli.set_calls == 1


def test_literal_tcp_needs_authenticated_confirmation_beyond_source_build(monkeypatch):
    from dataclasses import replace
    from ordin.runtime_contract import NetworkCapability

    request = supported_request("jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "lookup"})
    contract = replace(
        request.capability,
        contract_id="",
        network=(NetworkCapability("8.8.8.8", 853, "tcp", "write"),),
    )
    backend = OpenShellBackend((1000, 1000))
    plan = backend.compile(contract).plan
    cli = FakeCLI(plan)
    monkeypatch.setattr(extension, "expected_runtime_identity", lambda: {"source_digest": "a" * 64})
    identity = {
        "runtime_extension_id": extension.EXTENSION_ID,
        "runtime_source_digest": "a" * 64,
        "gateway_source_digest": "a" * 64,
        "cli_source_digest": "a" * 64,
    }
    original = cli.json

    def attested(arguments, **kwargs):
        value = original(arguments, **kwargs)
        if arguments[:2] == ("sandbox", "get"):
            value["configuration_admission"].update(identity)
        return value

    cli.json = attested
    prepared = prepare_openshell_apply(plan, backend=backend, sandbox="demo", cli=cli)
    assert prepared.reason_code == "openshell_staged_tcp_confirmation_required"
    assert cli.set_calls == 0
    identity.update(
        confirmed_backend="openshell-sandbox",
        egress_interception="seccomp-notify",
        request_attribution="seccomp-notify-procfs",
        staged_tcp_confirmed=True,
    )
    assert (
        prepare_openshell_apply(plan, backend=backend, sandbox="demo", cli=cli).status
        == "requires_approval"
    )


def test_pure_tcp_request_boundary_is_verified_and_bound_before_approval():
    request = supported_request("jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "lookup"})
    capability = replace(
        request.capability,
        contract_id="",
        network=(NetworkCapability("db.example.com", 5432, "tcp", "write"),),
    )
    request = replace(request, request_contract_id="", capability=capability, requests=())
    backend = OpenShellBackend((1000, 1000), request_contract=request)
    plan = backend.compile(capability).plan
    cli = FakeCLI(plan)
    maximum = replace(boundary_for(capability), network=())
    boundary = RuntimeRequestBoundaryV2(maximum, ())
    rejected = prepare_openshell_apply(
        plan, backend=backend, sandbox="demo", cli=cli, request_boundary=boundary
    )
    assert rejected.status == "exceeds_boundary", rejected.reason_code
    assert cli.set_calls == 0
    accepted_boundary = RuntimeRequestBoundaryV2(boundary_for(capability), ())
    accepted = prepare_openshell_apply(
        plan, backend=backend, sandbox="demo", cli=cli, request_boundary=accepted_boundary
    )
    assert accepted.verification[-1]["result"] == "within_boundary"
    assert accepted.reason_code == "openshell_runtime_extension_mismatch"
    assert rejected.request_id != accepted.request_id
    assert rejected.verification[-1]["boundary_digest"] == boundary.digest
