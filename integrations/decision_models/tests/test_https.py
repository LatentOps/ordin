"""Actual bounded transport parser over simulated streams; no socket is opened."""

import asyncio
import hashlib
import json

import pytest

from ordin_decision_models.typesafe import AsyncHTTPS, TypeSafeConfiguration


class FakeTLS:
    def __init__(self, *args):
        pass

    def load_verify_locations(self, *, cadata):
        assert cadata == "synthetic-ca"


class Writer:
    def __init__(self):
        self.content = b""
        self.closed = False

    def write(self, content):
        self.content += content

    async def drain(self):
        pass

    def close(self):
        self.closed = True


def transport_fixture(tmp_path, monkeypatch, response):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"synthetic-ca")
    config = TypeSafeConfiguration(
        ca.resolve(), hashlib.sha256(ca.read_bytes()).hexdigest(), max_response_bytes=1024
    )
    writer = Writer()

    async def connect(host, port, **kwargs):
        assert (host, port) == ("api.typesafe.ai", 443)
        assert kwargs["server_hostname"] == "api.typesafe.ai"
        reader = asyncio.StreamReader(limit=8192)
        reader.feed_data(response)
        reader.feed_eof()
        return reader, writer

    monkeypatch.setattr("ssl.SSLContext", FakeTLS)
    monkeypatch.setattr("asyncio.open_connection", connect)
    return AsyncHTTPS(config), writer, ca


def test_fixed_endpoint_auth_and_bounded_json_stream(tmp_path, monkeypatch):
    body = b'{"models":[]}'
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n" + body
    )
    transport, writer, _ = transport_fixture(tmp_path, monkeypatch, response)
    status, packet = asyncio.run(
        transport.request_json(
            "GET", "/v1/models", api_key="synthetic-token", body=None, deadline_ms=250
        )
    )
    assert status == 200 and packet == {"models": []} and writer.closed
    assert writer.content.startswith(b"GET /v1/models HTTP/1.1\r\nHost: api.typesafe.ai\r\n")
    assert b"Authorization: Bearer synthetic-token" in writer.content


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2048\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>bad</script>",
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"key":1,"key":2}',
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"score":NaN}',
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + b"x" * 2048,
    ],
)
def test_unsafe_framing_and_malformed_payloads_refused(tmp_path, monkeypatch, response):
    transport, writer, _ = transport_fixture(tmp_path, monkeypatch, response)
    with pytest.raises(ValueError):
        asyncio.run(
            transport.request_json(
                "GET", "/v1/models", api_key="synthetic", body=None, deadline_ms=250
            )
        )
    assert writer.closed


def test_redirect_does_not_parse_echoed_secrets_or_follow_location(tmp_path, monkeypatch):
    transport, writer, _ = transport_fixture(
        tmp_path,
        monkeypatch,
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.invalid\r\n\r\nsecret=value",
    )
    status, packet = asyncio.run(
        transport.request_json("GET", "/v1/models", api_key="synthetic", body=None, deadline_ms=250)
    )
    assert status == 302 and packet is None and writer.closed
    assert b"evil.invalid" not in writer.content


def test_ca_drift_bad_path_and_header_injection_refused_before_connect(tmp_path, monkeypatch):
    transport, writer, ca = transport_fixture(tmp_path, monkeypatch, b"")
    ca.write_bytes(b"changed")
    for method, path, credential in (
        ("GET", "/v1/models", "synthetic"),
        ("GET", "https://evil.invalid", "synthetic"),
        ("GET", "/v1/models", "token\r\nHost: injected"),
    ):
        with pytest.raises(ValueError):
            asyncio.run(
                transport.request_json(method, path, api_key=credential, body=None, deadline_ms=250)
            )
    assert writer.content == b""
