"""Actual exact HTTP(S), private credentials, and independent bounded framing."""

from contextlib import contextmanager
import copy
from dataclasses import replace
from dataclasses import replace
import io
import json
import socket
import ssl
from threading import Thread

import pytest

from ordin import ActionEnvelope, Ordin
from ordin.assurance import RestSemantics
from ordin.assurance.rest import derive_rest_request_contract
from ordin.runtime_contract import CredentialBinding
from ordin.runtime_contract import CapabilityUnknown
from ordin.enforcement_backend import EnforcementPlan
from ordin.runtime_observation import RuntimeEvidenceSource
from ordin.swarm._owned_http import OwnedRequestPlan
from ordin.swarm._owned_http_wire import read_response, request_bytes, request_tag
from ordin.swarm.owned_tools import OwnedHTTPRoute
from tests.swarm_owned_tools_samples import configured
from tests.test_swarm_delegation import CERTS
from tests.test_swarm_owned_tools import operator_backend


class BoundedStream:
    def __init__(self, value):
        self.input = io.BytesIO(value)
        self.count = 0

    def recv(self, maximum):
        assert 1 <= maximum <= 4096
        value = self.input.read(maximum)
        self.count += len(value)
        return value


def test_complete_http_wire_headers_and_private_tag_bind_every_byte():
    raw = request_bytes("https://example.com/a", (("X-Mode", "one"),))
    assert (
        raw
        == b"GET /a HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nAccept-Encoding: identity\r\nX-Mode: one\r\n\r\n"
    )
    private = request_bytes("https://example.com/a", (), b"private-token")
    assert b"Authorization: Bearer private-token\r\n" in private
    assert request_tag(b"a" * 32, raw) != request_tag(b"a" * 32, raw + b"x")
    assert request_tag(b"a" * 32, private) != request_tag(b"b" * 32, private)
    for url, headers in (
        ("https://example.com/a?x=1", ()),
        ("https://example.com/a\r\n", ()),
        ("https://user@example.com/a", ()),
        ("https://example.com/π", ()),
        ("https://example.com/a", (("Content-Length", "0"),)),
        ("https://example.com/a", (("x-mode", "one"), ("X-Mode", "two"))),
        ("https://example.com/a", (("X-Mode", "one\r\nInjected: true"),)),
    ):
        with pytest.raises(ValueError):
            request_bytes(url, headers)


def test_full_rest_plan_retains_original_marker_without_generic_grant_projection():
    action = ActionEnvelope(
        "network",
        "http.request",
        {"url": "https://example.com/a", "method": "GET", "headers": {"X-Mode": "one"}},
        action_id="exact-rest",
    )
    complete = derive_rest_request_contract(
        Ordin(rest_semantics=RestSemantics()).review_action(action)
    )
    assert complete.capability.grant_state == "diagnostic"
    with pytest.raises(ValueError, match="uncertain"):
        EnforcementPlan("linux-owned-tools-v1", complete.capability, {})
    plan = OwnedRequestPlan(
        "linux-owned-tools-v1", complete, {"complete_request_digest": complete.digest}
    )
    assert plan.complete is complete and plan.contract is complete.capability
    assert plan.complete.digest != plan.contract.digest
    assert plan.contract.unknowns == complete.capability.unknowns
    extra = replace(
        complete.capability,
        contract_id="",
        unknowns=complete.capability.unknowns
        + (CapabilityUnknown("credential", "unresolved", "Unresolved private use."),),
    )
    with pytest.raises(ValueError, match="unresolved"):
        OwnedRequestPlan("linux-owned-tools-v1", replace(complete, capability=extra), {})


@pytest.mark.parametrize(
    "response,maximum,expected",
    [
        (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", 3, b"abc"),
        (b"HTTP/1.0 200 OK\r\n\r\nabc", 3, b"abc"),
        (b"HTTP/1.1 204 Empty\r\n\r\n", 1, b""),
        (b"HTTP/1.1 401 Private\r\nContent-Length: 0\r\n\r\n", 1, b""),
    ],
)
def test_bounded_http_response_valid_controls(response, maximum, expected):
    assert read_response(BoundedStream(response), maximum) == expected


def test_header_read_ahead_never_spends_the_independent_body_budget():
    header = b"HTTP/1.1 200 OK\r\nX-Mode: one\r\n\r\n"
    incoming = BoundedStream(header + b"x" * 32768)
    with pytest.raises(ValueError, match="body"):
        read_response(incoming, 1)
    assert incoming.count == len(header) + 2  # One permitted byte plus one overflow probe.
    with pytest.raises(ValueError, match="content length"):
        read_response(BoundedStream(header), 1, require_length=True)


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 302 Redirect\r\nLocation: https://other.invalid/\r\n\r\n",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxy",
        b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nFolded: one\r\n two\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 4097,
        b"HTTP/1.1 200 OK\r\nHeader: " + b"x" * 8192,
    ],
)
def test_ambiguous_redirect_encoded_oversized_and_partial_responses_refuse(response):
    incoming = BoundedStream(response)
    with pytest.raises((ValueError, UnicodeError)):
        read_response(incoming, 4096)
    assert incoming.count <= 8192 + 4096 + 1


@contextmanager
def endpoint(*, body=b"bounded endpoint data", tls=False, response=None):
    """Private one-shot loopback fixture, with no external service or DNS."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(5)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    seen, failures = [], []
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(CERTS / "server.pem"), str(CERTS / "server-key.pem"))

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                if context is not None:
                    connection = context.wrap_socket(connection, server_side=True)
                with connection:
                    connection.settimeout(5)
                    request = bytearray()
                    while b"\r\n\r\n" not in request and len(request) < 65536:
                        value = connection.recv(min(4096, 65536 - len(request)))
                        if not value:
                            break
                        request.extend(value)
                    seen.append(bytes(request))
                    connection.sendall(
                        response
                        if response is not None
                        else b"HTTP/1.1 200 OK\r\nContent-Length: "
                        + str(len(body)).encode()
                        + b"\r\n\r\n"
                        + body
                    )
        except (OSError, ssl.SSLError) as exc:
            failures.append(type(exc).__name__)

    thread = Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield (
            f"{'https://localhost' if tls else 'http://127.0.0.1'}:{listener.getsockname()[1]}/docs",
            seen,
            failures,
        )
    finally:
        listener.close()
        thread.join(6)
        assert not thread.is_alive(), "owned one-shot endpoint fixture did not terminate"


def get_action(route, *, action_id="owned-get"):
    return ActionEnvelope("network", "http.request", route.public_parameters(), action_id=action_id)


@pytest.mark.parametrize("tls", [False, True])
def test_actual_http_and_verified_https_preserve_complete_request_authority(
    tmp_path, tls, monkeypatch
):
    # Skip before starting even the private endpoint on unsupported platforms.
    from tests.test_swarm_broker import require_kernel

    require_kernel()
    with endpoint(tls=tls) as (url, seen, failures):
        route = OwnedHTTPRoute(
            "docs",
            url,
            ("127.0.0.1",),
            headers=(("X-Mode", "one"),),
            ca_file=CERTS / "ca.pem" if tls else None,
            allow_private=True,
            allow_http=not tls,
        )
        backend, operator, _, install = operator_backend(tmp_path, http_routes=(route,))
        try:
            monkeypatch.setattr(
                socket, "getaddrinfo", lambda *a, **k: pytest.fail("implicit DNS lookup")
            )
            action = get_action(route)
            complete = derive_rest_request_contract(
                Ordin(rest_semantics=RestSemantics()).review_action(action)
            )
            assert complete.capability.grant_state == "diagnostic"  # Never stripped.
            compiled = backend.compile_action(action, complete)
            assert compiled.enforceable, compiled.as_dict()
            assert type(compiled.plan) is OwnedRequestPlan and compiled.plan.complete is complete
            assert backend.compile_action(action, complete).plan is compiled.plan
            source = RuntimeEvidenceSource(backend.name, "a" * 64, "owned-http-test", "b" * 64)
            result = backend.execute(compiled.plan, action, source, operator=operator)
            assert result.status == "completed", result.as_dict()
            assert result.value == b"bounded endpoint data" and result.physical_enforcement
            assert result.contract_digest == complete.digest and backend.verify_outcome(
                result, compiled.plan
            )
            assert result.observation.contract_id == complete.capability.contract_id
            evidence = backend.evidence_record(result, operator=operator)
            assert (
                evidence["tls_verified"] is tls
                and evidence["network_scope"] == "one_preconnected_destination"
            )
            assert evidence["complete_request_digest"] == complete.digest
            assert all(
                evidence["checks"][key]
                for key in (
                    "preconnected_socket_nonblocking_control",
                    "wrong_socket_ioctl_descriptor_denied",
                    "wrong_socket_ioctl_request_denied",
                    "socket_fcntl_denied",
                    "socket_connect_denied",
                )
            )
            assert not backend.verify_outcome(copy.copy(result), compiled.plan)
            assert not backend.compile_action(action, complete).enforceable
            assert seen == [request_bytes(url, route.headers)] and not failures
        finally:
            backend.close()
            install.cleanup()


def test_actual_broker_credentialed_https_keeps_original_proof_and_private_response(tmp_path):
    from tests.test_swarm_broker import require_kernel

    require_kernel()
    secret = b"private-credential-fixture"
    with endpoint(tls=True, body=b"echo: " + secret) as (url, seen, failures):
        route = OwnedHTTPRoute(
            "private-docs",
            url,
            ("127.0.0.1",),
            ca_file=CERTS / "ca.pem",
            credential_binding=CredentialBinding(
                "fixture-key", "localhost", int(url.split(":")[2].split("/")[0])
            ),
            credential=secret,
            allow_private=True,
        )
        with configured(tmp_path, http_routes=(route,), physical=True) as data:
            action = get_action(route)
            source = data.details["sources"]["child"]
            uses = data.broker.review_credential_uses(source, action)
            assert data.broker.review_credential_uses(source, action) is uses
            prepared = data.broker.prepare(
                data.channel, data.grant, action, idempotency_key="credential-get"
            )
            assert prepared.disposition == "execute", prepared.as_dict()
            scope = data.broker.authorization_scope(prepared.authorization)
            assert scope.delegation_scope.review_context.credential_uses[0] is uses[0]
            result = data.broker.dispatch(prepared.authorization)
            assert result.status == "completed", result.as_dict()
            assert result.value == b'{"completed":true,"credentialed":true}'
            assert (
                data.broker.retained_result(prepared.authorization, operator=data.operator)
                is result
            )
            with pytest.raises(ValueError):
                data.broker.retained_result(prepared.authorization, operator=object())
            with pytest.raises(ValueError, match="consumed"):
                data.broker.review_credential_uses(source, action)
            public = json.dumps(result.as_dict()) + repr(result) + json.dumps(scope.plan.as_dict())
            assert secret.decode() not in public and "echo:" not in public
            assert seen == [request_bytes(url, (), secret)] and not failures


def test_tls_hostname_failure_sends_no_private_credential_and_never_reissues(tmp_path):
    from tests.test_swarm_broker import require_kernel

    require_kernel()
    secret = b"private-credential-fixture"
    with endpoint(tls=True) as (localhost, seen, _):
        port = int(localhost.split(":")[2].split("/")[0])
        route = OwnedHTTPRoute(
            "private-docs",
            f"https://example.com:{port}/docs",
            ("127.0.0.1",),
            ca_file=CERTS / "ca.pem",
            allow_private=True,
            credential=secret,
            credential_binding=CredentialBinding("fixture-key", "example.com", port),
        )
        with configured(tmp_path, http_routes=(route,)) as data:
            action = get_action(route)
            source = data.details["sources"]["child"]
            uses = data.broker.review_credential_uses(source, action)
            prepared = data.broker.prepare(
                data.channel, data.grant, action, idempotency_key="wrong-tls"
            )
            assert prepared.disposition == "execute", prepared.as_dict()
            result = data.broker.dispatch(prepared.authorization)
            assert result.status == "unknown" and result.value is None
            assert data.broker.verify_credential_uses(source, action, uses)
            with pytest.raises(ValueError, match="consumed"):
                data.broker.review_credential_uses(source, action)
            assert not any(secret in value or b"GET " in value for value in seen)


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 302 Redirect\r\nLocation: http://127.0.0.1/elsewhere\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n",
    ],
)
def test_actual_http_ambiguous_and_redirect_responses_never_succeed_or_retry(tmp_path, response):
    from tests.test_swarm_broker import require_kernel

    require_kernel()
    with endpoint(response=response) as (url, seen, _):
        route = OwnedHTTPRoute("docs", url, ("127.0.0.1",), allow_private=True, allow_http=True)
        backend, operator, _, install = operator_backend(tmp_path, http_routes=(route,))
        try:
            action = get_action(route)
            complete = derive_rest_request_contract(
                Ordin(rest_semantics=RestSemantics()).review_action(action)
            )
            compiled = backend.compile_action(action, complete)
            source = RuntimeEvidenceSource(backend.name, "a" * 64, "owned-http-test", "b" * 64)
            result = backend.execute(compiled.plan, action, source, operator=operator)
            assert (
                result.status == "unknown"
                and not result.physical_enforcement
                and result.value is None
            )
            assert len(seen) == 1 and not backend.compile_action(action, complete).enforceable
        finally:
            backend.close()
            install.cleanup()
