import builtins
import math
import socket
import subprocess
import json
from decimal import Decimal
from pathlib import Path

import pytest

from ordin._request_commitment import (
    commitment_json,
    request_commitment,
    rpc_authority_commitment,
    rpc_body_commitment,
)


def test_commitment_is_order_independent_but_preserves_argument_and_type_authority():
    assert request_commitment({"a": 1, "b": [None, True]}) == request_commitment(
        {"b": [None, True], "a": 1}
    )
    values = [None, False, True, 0, 0.0, -0.0, 1, 1.0, "1", [1], {"value": 1}]
    assert len({request_commitment(v) for v in values}) == len(values)
    assert request_commitment({"path": "/repo/a"}) != request_commitment({"path": "/etc/shadow"})


def test_unicode_and_control_values_are_committed_without_normalizing_them():
    assert request_commitment("é") != request_commitment("e\u0301")
    assert request_commitment("value") != request_commitment("value\n")
    assert request_commitment(2**200) != request_commitment(2**200 + 1)


def test_raw_decimals_keep_precision_and_duplicates_fail_closed():
    for first, second in [
        (b"9007199254740992.0", b"9007199254740993.0"),
        (b"0.0", b"1e-4000"),
        (b"0.1", b"0.10000000000000000000000000001"),
    ]:
        assert commitment_json(first) != commitment_json(second)
    assert commitment_json(b"1.00") == commitment_json(b"10e-1")
    assert commitment_json(b"-0") == commitment_json(b"0")
    assert commitment_json(b"0.1") == request_commitment(0.1)
    for body in [b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b"1e10001"]:
        with pytest.raises(ValueError, match="^request_commitment_invalid$"):
            commitment_json(body)
    with pytest.raises(ValueError, match="^request_commitment_invalid$"):
        rpc_authority_commitment({"jsonrpc": "2.0", "method": "ping", "extra": True})


def test_rpc_correlation_id_cannot_change_authority_but_params_and_methods_do():
    first = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read", "arguments": {"path": "/a"}},
    }
    second = {**first, "id": "unrelated-transport-id"}
    assert rpc_authority_commitment(first) == rpc_authority_commitment(second)
    notification = {key: value for key, value in first.items() if key != "id"}
    assert rpc_authority_commitment(first) != rpc_authority_commitment(notification)
    missing = {key: value for key, value in first.items() if key != "params"}
    assert rpc_authority_commitment(missing) != rpc_authority_commitment(
        {**missing, "params": None}
    )
    assert rpc_authority_commitment(first) != rpc_authority_commitment(
        {**first, "method": "tools/list"}
    )
    assert rpc_authority_commitment(first) != rpc_authority_commitment(
        {**first, "params": {"name": "read", "arguments": {"path": "/b"}}}
    )


@pytest.mark.parametrize(
    "value",
    [math.nan, math.inf, -math.inf, {1: "value"}, object(), "\ud800", "x" * 65537, [0] * 129],
    ids=[
        "nan",
        "infinity",
        "negative-infinity",
        "bad-key",
        "non-json",
        "surrogate",
        "oversized-text",
        "oversized-array",
    ],
)
def test_malformed_unbounded_or_unportable_values_have_generic_errors(value):
    with pytest.raises(ValueError, match="^request_commitment_invalid$"):
        request_commitment(value)


def test_cycles_and_excessive_depth_are_rejected():
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError):
        request_commitment(cycle)
    nested = None
    for _ in range(40):
        nested = [nested]
    with pytest.raises(ValueError):
        request_commitment(nested)


def test_portable_vectors_match_the_audited_runtime_encoding():
    vectors = json.loads(
        (Path(__file__).parent / "fixtures/request-authority-v1.json").read_text(encoding="utf-8")
    )
    for vector in vectors:
        actual = (
            commitment_json(vector["json"].encode("utf-8"))
            if vector["kind"] == "json"
            else rpc_body_commitment(json.loads(vector["json"], parse_float=Decimal))
        )
        assert actual == vector["digest"]


def test_commitment_performs_no_io_and_does_not_echo_sensitive_values(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("request commitment performed I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    result = request_commitment({"token": "NONSECRET-TEST-VALUE", "arguments": {"count": 3}})
    assert len(result) == 64 and "NONSECRET-TEST-VALUE" not in result
