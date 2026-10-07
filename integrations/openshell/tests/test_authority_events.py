from copy import deepcopy

from test_authority_compiler import supported_request
from test_observations import event_fixture, register_event, source_context
from ordin_openshell.correlation import CorrelationStore
from ordin_openshell.observations import ingest_openshell_event, parse_openshell_event
from ordin_openshell.compiler import OpenShellBackend
from ordin_openshell.shadow import policy_request_match


def authority_event(request):
    event = event_fixture("http-audit")
    ep = request.requests[0]
    event["http_request"]["http_method"] = "POST"
    event["http_request"]["url"].update(hostname=ep.host, port=ep.port, path=ep.path)
    event["dst_endpoint"].update(domain=ep.host, port=ep.port)
    event["unmapped"] = {
        "request_authority": {
            "protocol": ep.protocol,
            "algorithm": ep.algorithm,
            "commitment": ep.commitment,
            "enforcement": "enforce",
        },
        "workload_binary": "/usr/bin/curl",
    }
    return event


def test_request_events_need_exact_commitment_and_private_source_binding(tmp_path):
    request = supported_request(
        "jsonrpc.request", {"jsonrpc": "2.0", "id": 1, "method": "lookup", "params": {"key": "a"}}
    )
    source = source_context()
    store = CorrelationStore(tmp_path / "bindings.json")
    event = authority_event(request)
    register_event(store, event, request.capability, source)
    result = ingest_openshell_event(
        event,
        contract=request.capability,
        request_contract=request,
        source=source,
        store=store,
        now_ms=2000,
    )
    assert result.status == "accepted", result.reason_code
    assert result.observation.metadata["request_commitment"] == request.requests[0].commitment
    plan = OpenShellBackend((1000, 1000), request_contract=request).compile(request.capability).plan
    assert policy_request_match(plan, result.observation) == "within_policy"


def test_coarse_allow_and_wrong_payload_never_become_exact_request_evidence(tmp_path):
    request = supported_request("graphql.request", {"query": "{ viewer { id } }"})
    source = source_context()
    for mode in ("missing", "wrong"):
        store = CorrelationStore(tmp_path / (mode + ".json"))
        event = authority_event(request)
        if mode == "missing":
            event.pop("unmapped")
        else:
            event["unmapped"]["request_authority"]["commitment"] = "0" * 64
        register_event(store, event, request.capability, source)
        result = ingest_openshell_event(
            event,
            contract=request.capability,
            request_contract=request,
            source=source,
            store=store,
            now_ms=2000,
        )
        assert (
            result.status == "rejected"
            and result.reason_code == "runtime_request_observation_mismatch"
        )
        assert store.lookup(parse_openshell_event(event).event_id_digest) is not None
