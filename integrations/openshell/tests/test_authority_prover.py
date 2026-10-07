from copy import deepcopy

from test_authority_compiler import supported_request
from ordin_openshell.compiler import OpenShellBackend
from ordin_openshell.authority_prover import check_protocol_containment, project_transport


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
