from copy import deepcopy
from dataclasses import replace
import json
import os
import shutil

import pytest

from test_authority_compiler import supported_request
from ordin.runtime_contract import NetworkCapability
from ordin_openshell.compiler import OpenShellBackend
from ordin_openshell.authority_prover import check_protocol_containment, project_transport
from ordin_openshell.prover import verify_with_openshell_prover


def compiled():
    request = supported_request(
        "jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "lookup", "params": {"key": "a"}}
    )
    return (
        OpenShellBackend((1000, 1000), request_contract=request)
        .compile(request.capability)
        .plan.as_dict()["policy"]
    )


def test_composition_covers_argument_protocol_method_binary_and_ip_constraints():
    candidate = compiled()
    assert check_protocol_containment(candidate, candidate)[0] == "within_boundary"
    projection = project_transport(candidate)
    endpoint = next(iter(projection["network_policies"].values()))["endpoints"][0]
    assert endpoint["protocol"] == "rest" and endpoint["rules"] == [
        {"allow": {"method": "POST", "path": "/rpc"}}
    ]
    assert "request_integrity" not in endpoint
    for change in ("commitment", "method", "binary", "ips", "protocol"):
        maximum = deepcopy(candidate)
        rule = next(iter(maximum["network_policies"].values()))
        ep = rule["endpoints"][0]
        if change == "commitment":
            ep["request_integrity"]["commitments"] = ["0" * 64]
        elif change == "method":
            ep["rules"][0]["allow"]["method"] = "other"
        elif change == "binary":
            rule["binaries"][0]["path"] = "/usr/bin/other"
        elif change == "ips":
            ep["allowed_ips"] = ["8.8.8.8/32"]
        else:
            ep["protocol"] = "rest"
            ep.pop("request_integrity")
            ep.pop("path")
            ep["rules"] = [{"allow": {"method": "POST", "path": "/rpc"}}]
        assert check_protocol_containment(candidate, maximum)[0] != "within_boundary", change


def test_raw_rest_cannot_borrow_jsonrpc_authority_after_transport_projection():
    maximum = compiled()
    candidate = project_transport(maximum)
    assert check_protocol_containment(candidate, maximum)[0] == "exceeds_boundary"


def test_ambiguous_duplicate_integrity_endpoints_are_not_projected_into_success():
    candidate = compiled()
    rule = next(iter(candidate["network_policies"].values()))
    sibling = deepcopy(rule["endpoints"][0])
    sibling["request_integrity"]["commitments"] = ["0" * 64]
    rule["endpoints"].append(sibling)
    assert check_protocol_containment(candidate, candidate)[0] == "unsupported"


@pytest.mark.parametrize("host", ["8.8.8.8", "2001:4860:4860::8888"])
@pytest.mark.parametrize("mixed", [False, True])
def test_real_prover_literal_tcp_and_mixed_request_authority(tmp_path, host, mixed):
    executable = os.environ.get("ORDIN_OPENSHELL_PROVER", "openshell-prover")
    if shutil.which(executable) is None:
        pytest.skip("standalone OpenShell prover is not installed")
    request = supported_request(
        "jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "items/delete"}
    )
    capability = replace(
        request.capability,
        contract_id="",
        network=((*request.capability.network,) if mixed else ())
        + (NetworkCapability(host, 853, "tcp", "write"),),
    )
    request = replace(
        request,
        request_contract_id="",
        capability=capability,
        requests=request.requests if mixed else (),
    )
    scope = {
        "host": host,
        "port": 853,
        "protocols": ["tcp"],
        "allowed_ips": [host + ("/128" if ":" in host else "/32")],
    }
    result = OpenShellBackend(
        (1000, 1000), request_contract=request, network_scopes=(scope,)
    ).compile(capability)
    assert result.enforceable, result.unsupported_fields
    policy = result.plan.as_dict()["policy"]
    candidate, boundary = tmp_path / "candidate.json", tmp_path / "boundary.json"
    candidate.write_text(json.dumps(policy))
    boundary.write_text(json.dumps(policy))
    within = verify_with_openshell_prover(candidate, boundary, executable=executable)
    assert within.ok, within.as_dict()
    assert "network_tcp_literal" in within.coverage["domains"]
    for change in ("host", "port", "binary", "ips"):
        changed = deepcopy(policy)
        rule = next(
            rule
            for rule in changed["network_policies"].values()
            if any(ep["protocol"] == "tcp" for ep in rule["endpoints"])
        )
        endpoint = next(ep for ep in rule["endpoints"] if ep["protocol"] == "tcp")
        if change == "host":
            endpoint["host"] = "1.1.1.1"
        elif change == "port":
            endpoint["port"] = 854
        elif change == "binary":
            rule["binaries"][0]["path"] = "/usr/bin/other"
        else:
            endpoint["allowed_ips"] = ["1.1.1.1/32"]
        candidate.write_text(json.dumps(changed))
        exceeds = verify_with_openshell_prover(candidate, boundary, executable=executable)
        assert exceeds.result == "exceeds_boundary", (change, exceeds.as_dict())
