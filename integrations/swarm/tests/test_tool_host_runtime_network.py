"""The explicit runtime fixture cannot turn conformance networking back on."""

import socket

import pytest


def test_explicit_runtime_fixture_requires_live_owned_listener_and_rejects_dns(
    owned_runtime_loopback, monkeypatch
):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        address = listener.getsockname()
        with socket.create_connection(address) as client:
            server, _ = listener.accept()
            with server:
                client.sendall(b"owned")
                assert server.recv(5) == b"owned"

        def no_resolver(*args, **kwargs):
            pytest.fail("unowned endpoint reached a resolver")

        monkeypatch.setattr(socket, "getaddrinfo", no_resolver)
        foreign_port = address[1] + 1 if address[1] < 65535 else address[1] - 1
        for foreign in (
            ("localhost", address[1]),
            ("192.0.2.1", address[1]),
            ("127.0.0.2", address[1]),
            ("127.0.0.1", foreign_port),
        ):
            with pytest.raises(AssertionError, match="runtime fixture"):
                socket.create_connection(foreign)
        listener.close()
        with pytest.raises(AssertionError, match="live owned listener"):
            socket.create_connection(address)


def test_default_conformance_network_denial_remains_active():
    with pytest.raises(AssertionError, match="conformance attempted"):
        socket.create_connection(("127.0.0.1", 1))
