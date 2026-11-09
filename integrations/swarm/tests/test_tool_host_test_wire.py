"""Consume the real producer byte wire as untrusted data, never as native proof."""

from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from ordin import ActionEnvelope
from ordin.swarm._owned_test_output import bounded_test_value
from ordin_swarm.host_authority import HostDispatch
from ordin_swarm.host_runtime import ManagedToolHost, MAX_DATA_BYTES
from test_tool_host_lineage import host as lineage_host


def payload():
    return {
        "exit_code": 0,
        "output": "1 passed in 0.01s\n",
        "output_truncated": False,
        "output_trust": "untrusted_test_diagnostic",
        "test_correctness_verified": False,
        "snapshot_digest": "a" * 64,
    }


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def action(snapshot="a" * 64):
    return ActionEnvelope(
        "tool",
        "call",
        {
            "runtime": "ordin-owned",
            "tool": "run_tests",
            "arguments": {"test_id": "report"},
            "host_test_snapshot": {"reference": "original-reference", "digest": snapshot},
        },
        action_id="original-test",
    )


def consumer(tmp_path):
    lineage, authority = lineage_host(tmp_path)
    host = object.__new__(ManagedToolHost)
    host._lineage, host.profile = lineage, authority.profile
    return host, lineage


@pytest.mark.parametrize("text", ["1 passed in 0.01s\n", "untrusted π \U0001f600\x00"])
def test_actual_producer_byte_wire_decodes_without_rewriting_original_outcome(tmp_path, text):
    host, lineage = consumer(tmp_path)
    data = {**payload(), "output": text}
    original_wire = bounded_test_value(encode(data), MAX_DATA_BYTES)
    native = SimpleNamespace(value=original_wire, physical_enforcement=True, status="completed")
    original_hash = hashlib.sha256(native.value).hexdigest()
    original_action = action()
    effect = HostDispatch("completed", (), True, True, result=native, action=original_action)
    reservation = lineage.reserve("reader", MAX_DATA_BYTES)
    result = host._completed("reader", "run_tests", {"test_id": "report"}, effect, reservation)
    assert result["status"] == "completed" and result["physical_enforcement"] is True
    assert result["data"]["output"] == text and result["data"]["exit_code"] == 0
    assert result["data"]["test_correctness_verified"] is False
    assert result["data"]["output_trust"] == "untrusted_test_diagnostic"
    assert result["data"]["instruction_authority"] == "data"
    assert set(result["data"]["labels"]) == {"pii", "private_code", "secret"}
    assert lineage.require("reader", result["data"]["resource_ref"]).content == text
    assert lineage.status("reader")["pending_custody_reservations"] == 0
    assert (
        native.value is original_wire and hashlib.sha256(native.value).hexdigest() == original_hash
    )
    assert native.physical_enforcement is True and native.status == "completed"
    assert effect.result is native and effect.action is original_action


BAD_WIRES = [
    b"{",
    b"null",
    b"[]",
    b"\xff",
    b"",
    encode(payload()) + b" " * MAX_DATA_BYTES,
    encode(payload())[:-1] + b',"exit_code":1}',
    encode({**payload(), "exit_code": float("nan")}),
    encode({**payload(), "exit_code": float("inf")}),
    encode({**payload(), "exit_code": float("-inf")}),
    encode(payload()).replace(b'"exit_code":0', b'"exit_code":1e999'),
    json.dumps({**payload(), "output": "\ud800"}, ensure_ascii=True).encode(),
    encode({**payload(), "output": "x" * 8193}),
    encode({**payload(), "output": [0] * 4097}),
    encode({**payload(), "physical_enforcement": True}),
    encode({key: value for key, value in payload().items() if key != "output"}),
]
deep = []
for _ in range(15):
    deep = [deep]
BAD_WIRES.append(encode({**payload(), "output": deep}))


@pytest.mark.parametrize("wire", BAD_WIRES)
def test_malformed_or_unbounded_original_bytes_keep_unknown_custody(tmp_path, wire):
    host, lineage = consumer(tmp_path)
    native = SimpleNamespace(value=wire, physical_enforcement=True)
    reservation = lineage.reserve("reader", MAX_DATA_BYTES)
    effect = HostDispatch("completed", (), True, True, result=native, action=action())
    result = host._completed("reader", "run_tests", {"test_id": "report"}, effect, reservation)
    assert result["status"] == "unknown" and result["forwarded"] is True and result["data"] == {}
    assert lineage.status("reader")["retained_resources"] == 0
    assert lineage.status("reader")["pending_custody_reservations"] == 1
    lineage.uncertain(reservation)  # Existing call/fulfillment finally retains it.
    with pytest.raises(ValueError, match="refunded"):
        lineage.cancel(reservation)
    assert native.value is wire and native.physical_enforcement is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("exit_code", True),
        ("exit_code", None),
        ("exit_code", "0"),
        ("exit_code", 0.0),
        ("output", None),
        ("output", {}),
        ("output_truncated", 0),
        ("output_truncated", "false"),
        ("output_trust", "trusted"),
        ("test_correctness_verified", True),
        ("test_correctness_verified", 0),
        ("snapshot_digest", None),
        ("snapshot_digest", "b" * 64),
        ("snapshot_digest", "g" * 64),
        ("snapshot_digest", "A" * 64),
        ("snapshot_digest", "a" * 63),
    ],
)
def test_decoded_schema_types_and_exact_snapshot_cannot_be_forged(tmp_path, field, value):
    host, lineage = consumer(tmp_path)
    native = SimpleNamespace(value=encode({**payload(), field: value}))
    effect = HostDispatch("completed", (), True, True, result=native, action=action())
    result = host._completed("reader", "run_tests", {"test_id": "report"}, effect)
    assert result["status"] == "unknown" and lineage.status("reader")["retained_resources"] == 0


@pytest.mark.parametrize(
    "value",
    [
        payload(),
        encode(payload()).decode(),
        bytearray(encode(payload())),
        memoryview(encode(payload())),
    ],
)
def test_dict_text_and_other_containers_are_not_original_native_bytes(tmp_path, value):
    host, lineage = consumer(tmp_path)
    effect = HostDispatch(
        "completed", (), True, True, result=SimpleNamespace(value=value), action=action()
    )
    result = host._completed("reader", "run_tests", {"test_id": "report"}, effect)
    assert result["status"] == "unknown" and lineage.status("reader")["retained_resources"] == 0


def test_missing_or_malformed_protected_snapshot_is_not_rebound_to_payload(tmp_path):
    host, lineage = consumer(tmp_path)
    native = SimpleNamespace(value=encode(payload()))
    effect = HostDispatch("completed", (), True, True, result=native, action=action())
    for original in (
        None,
        replace(
            action(),
            parameters={
                "runtime": "ordin-owned",
                "tool": "run_tests",
                "arguments": {"test_id": "report"},
            },
        ),
        action("b" * 64),
    ):
        assert (
            host._completed(
                "reader", "run_tests", {"test_id": "report"}, replace(effect, action=original)
            )["status"]
            == "unknown"
        )
    malformed = {**payload(), "snapshot_digest": "invalid"}
    assert (
        host._completed(
            "reader",
            "run_tests",
            {"test_id": "report"},
            HostDispatch(
                "completed",
                (),
                True,
                True,
                result=SimpleNamespace(value=encode(malformed)),
                action=action("invalid"),
            ),
        )["status"]
        == "unknown"
    )
    assert lineage.status("reader")["retained_resources"] == 0
