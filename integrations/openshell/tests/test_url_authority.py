import json
import sys

import pytest

from ordin import ActionEnvelope, ActionResource, ActionReview, Ordin, ObservedResource
from ordin.mcp_http import MCPHTTPConfig
from ordin.runtime_contract import derive_runtime_capability_contract
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation
from ordin.runtime_reasoning import current_runtime_signals
from ordin.runtime_requests import request_endpoint
from ordin.setup import TARGETS, plan
from ordin_openshell.backend_cli import OpenShellCLI
from ordin_openshell.correlation import CorrelationStore
from ordin_openshell.observations import ingest_openshell_event
from ordin_openshell.model import exact_request_path
from test_observations import event_fixture, register_event, source_context
from test_compiler import supported_contract

URL_CASES = [
    ("https://api.example.com/a", True),
    ("http://api.example.com/a", True),
    ("https://api.example.com:443/a", True),
    (" https://api.example.com/a", False),
    ("https://api.example.com/a ", False),
    ("\nhttps://api.example.com/a", False),
    ("https://api.example.com/a\n", False),
    ("\thttps://api.example.com/a", False),
    ("https://api.example.com/a\t", False),
    ("https://api.example.com/\x7f", False),
    ("https://@api.example.com/a", False),
    ("https://:@api.example.com/a", False),
    ("https://user@api.example.com/a", False),
    ("https://user:pass@api.example.com/a", False),
    ("https://api.example.com/a?x=1", False),
    ("https://api.example.com/a#frag", False),
    ("https://api.example.com:0/a", False),
    ("https://api.example.com:99999/a", False),
    ("https://api.example.com:PRIVATE_PORT/a", False),
]


def review(url):
    return ActionReview(
        action=ActionEnvelope("network", "http.request", {"url": url}, action_id="url-test"),
        decision="allow",
        risk="low",
        reasons=[],
        safer_next_step=None,
        effects=["network.download"],
        resources=[ActionResource("url", url)],
        adapter="trusted-url-fixture",
    )


@pytest.mark.parametrize("url,valid", URL_CASES)
def test_url_authority_is_consistent_in_derivation_requests_and_retry_keys(url, valid):
    assert (request_endpoint(url) is not None) is valid
    current = review(url)
    contract = derive_runtime_capability_contract(current)
    if valid:
        assert contract.network[0].host == "api.example.com"
    else:
        assert all(n.host is None and n.port is None for n in contract.network)
        assert contract.grant_state == "diagnostic"
        assert any(
            u.reason_code == "runtime_contract_malformed_resource" for u in contract.unknowns
        )
        assert url not in json.dumps(contract.as_dict())
    original = derive_runtime_capability_contract(
        Ordin().review_action(ActionEnvelope.shell("git status", action_id="old"))
    )
    source = RuntimeEvidenceSource("openshell", "a" * 64, "sandbox", "b" * 64)
    port = 80 if url.startswith("http:") else 443
    observations = {
        "old": tuple(
            source.observe(
                original,
                observation_id=str(i),
                trust="backend_enforced",
                enforcement_point="network",
                outcome="denied",
                operation="http.request",
                reason_code="policy_denied",
                metadata={"host": "api.example.com", "port": port, "path": "/a"},
            )
            for i in range(2)
        )
    }
    assert (
        "signal:runtime-boundary-retry" in current_runtime_signals(current, observations)
    ) is valid


@pytest.mark.parametrize("resource_type", ["url", "endpoint"])
@pytest.mark.parametrize("url,valid", URL_CASES)
def test_malformed_resources_are_rejected_with_the_same_error_for_every_trust_label(
    resource_type, url, valid
):
    contract = supported_contract()
    source = source_context()
    resources = (ObservedResource(resource_type, url),)
    constructors = [lambda: RuntimeObservation("weak", contract.action_id, resources=resources)]
    constructors.extend(
        lambda trust=trust: source.observe(
            contract,
            observation_id=trust,
            trust=trust,
            enforcement_point="network",
            outcome="denied",
            operation="http.request",
            resources=resources,
        )
        for trust in ("backend_observed", "backend_enforced")
    )
    for construct in constructors:
        if valid:
            assert construct().resources == resources
        else:
            with pytest.raises(ValueError) as error:
                construct()
            assert str(error.value) == "runtime observation rejects sensitive or ambiguous URLs"
            assert url not in str(error.value)


@pytest.mark.parametrize("url,valid", URL_CASES)
def test_configuration_does_not_normalize_url_or_origin_authority(url, valid, tmp_path):
    origin = url.replace("api.example.com/a", "api.example.com").replace(
        "api.example.com:443/a", "api.example.com:443"
    )
    options = {
        "integration": "mcp-http",
        "config": TARGETS["mcp-http"],
        "python": sys.executable,
        "state": False,
        "audit": False,
        "observations": False,
        "shell": "bash",
        "server_id": "fixture",
        "command": [],
        "upstream": url,
        "port": 8766,
        "semantics": None,
        "inventory": None,
        "contract_lock": None,
    }
    checks = [
        (lambda: OpenShellCLI(gateway_endpoint=origin), valid),
        (lambda: MCPHTTPConfig("fixture", url, allow_insecure_upstream=True), valid),
        (
            lambda: MCPHTTPConfig(
                "fixture", "https://api.example.com/mcp", allowed_origins={origin}
            ),
            valid,
        ),
        (lambda: plan(options, tmp_path.resolve()), valid and not url.startswith("http:")),
    ]
    for construct, allowed in checks:
        if allowed:
            construct()
        else:
            with pytest.raises(ValueError) as error:
                construct()
            assert url not in str(error.value) and "PRIVATE_PORT" not in str(error.value)


@pytest.mark.parametrize(
    "path",
    [
        " /a",
        "/a ",
        "\n/a",
        "/a\n",
        "\t/a",
        "/a\t",
        "/\x7f",
        "/a\x00",
        "https://@api.example.com/a",
        "https://:@api.example.com/a",
    ],
)
def test_unsafe_native_paths_never_enter_protected_correlation(path, tmp_path):
    original = event_fixture()
    event = event_fixture()
    event["http_request"]["url"]["path"] = path
    contract, source = supported_contract(), source_context()
    store = CorrelationStore(tmp_path / "bindings.db")
    register_event(store, original, contract, source)
    result = ingest_openshell_event(
        event, contract=contract, source=source, store=store, now_ms=2000
    )
    assert result.status == "rejected" and result.event is None and result.observation is None
    assert path not in json.dumps(result.as_dict())
    assert (
        ingest_openshell_event(
            original, contract=contract, source=source, store=store, now_ms=2000
        ).status
        == "accepted"
    )


@pytest.mark.parametrize("path", ["/a ", "/a\x7f", "/a\t"])
def test_request_path_authority_is_rejected_without_restricting_filesystem_names(path):
    from dataclasses import replace
    from ordin.runtime_contract import FilesystemCapability, NetworkCapability
    from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability

    assert not exact_request_path(path)
    if any(ord(character) < 32 for character in path):
        with pytest.raises(ValueError):
            NetworkCapability("api.github.com", 443, "rest", "read", ("GET",), (path,))
        return
    contract = supported_contract()
    candidate = replace(
        contract,
        contract_id="",
        network=(NetworkCapability("api.github.com", 443, "rest", "read", ("GET",), (path,)),),
    )
    boundary = RuntimeCapabilityBoundary(
        "path",
        filesystem=contract.filesystem,
        network=candidate.network,
        process=contract.process,
        privilege=contract.privilege,
    )
    result = verify_runtime_capability(candidate, boundary)
    assert result.result == "unsupported" and result.coverage["network"] is False
    assert (
        FilesystemCapability("read", "/repo/file with spaces", "exact").path
        == "/repo/file with spaces"
    )
