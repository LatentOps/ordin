"""OpenShell admission never weakens requirements or fabricates execution."""

from dataclasses import replace
import pytest

from ordin import ActionEnvelope, Ordin
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import (
    FilesystemCapability,
    NetworkCapability,
    ProcessCapability,
    derive_runtime_capability_contract,
)
from ordin.runtime_requests_v2 import RuntimeRequestContractV2


def fixture():
    compiler = pytest.importorskip("ordin_openshell.compiler")
    from ordin_openshell.backend_cli import OpenShellCLI
    from ordin_swarm.openshell_backend import SwarmOpenShellBackend

    original = derive_runtime_capability_contract(
        Ordin().review_action(
            ActionEnvelope.shell(
                "/usr/bin/cat /usr/share/fixture",
                action_id="read",
            )
        )
    )
    contract = replace(
        original,
        contract_id="",
        decision="allow",
        risk="low",
        unknowns=(),
        filesystem=(
            FilesystemCapability("read", "/usr", "prefix"),
            FilesystemCapability("execute", "/usr", "prefix"),
        ),
        network=(),
        process=ProcessCapability(True, ("/usr/bin/cat",), True),
    )
    backend = compiler.OpenShellBackend((1000, 1000))
    compiled = backend.compile(contract)
    assert compiled.enforceable
    boundary = RuntimeCapabilityBoundary(
        "operator",
        filesystem=contract.filesystem,
        network=contract.network,
        process=contract.process,
        privilege=contract.privilege,
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )
    operator = object()
    bridge = SwarmOpenShellBackend(
        backend,
        OpenShellCLI("ordin-nonexistent-openshell-runtime"),
        sandbox="fixture",
        capability_boundary=boundary,
        backend_boundary_policy=compiled.plan.as_dict()["policy"],
        prover_executable="ordin-nonexistent-openshell-prover",
        operator=operator,
    )
    return bridge, contract, operator


def test_missing_native_prover_or_host_runtime_cannot_admit_or_claim_completion():
    bridge, contract, operator = fixture()
    compiled = bridge.compile(contract)
    prepared = bridge.prepare(compiled.plan)
    assert prepared.status not in {"success", "requires_approval"}
    assert not hasattr(bridge, "execute")
    with pytest.raises(ValueError):
        bridge.apply(compiled.plan, approval_request_id="copied-json", operator=object())


def test_request_authority_cannot_be_omitted_swapped_or_projected_into_tcp():
    bridge, contract, _ = fixture()
    complete = RuntimeRequestContractV2(contract, ())
    refused = bridge.compile(complete)
    assert not refused.enforceable and "requests.complete_authority" in refused.unsupported_fields
    refused = bridge.compile(object())
    assert not refused.enforceable
    unknown = replace(
        contract,
        contract_id="",
        network=(NetworkCapability("api.github.com", 443, "graphql", "read"),),
    )
    assert not bridge.compile(unknown).enforceable
    rest = replace(
        contract,
        contract_id="",
        network=(
            NetworkCapability("api.github.com", 443, "rest", "read", ("GET",), ("/fixture",)),
        ),
    )
    assert not bridge.compile(rest).enforceable
    with pytest.raises(ValueError):
        bridge.prepare(bridge.backend.compile(contract).plan)
