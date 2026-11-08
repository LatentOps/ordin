"""Bound the verified runner's untrusted diagnostics before public delivery."""

import json

from ._owned_protocol import wire
from .events import _hex

TEST_PROTOCOL = "ordin.swarm.owned_fixed_tests.v1"


def bounded_test_value(value, maximum):
    if type(value) is not bytes or len(value) > 65536 or type(maximum) is not int or maximum < 8192:
        raise ValueError("bounded original test result required")
    data = json.loads(value)
    if (
        type(data) is not dict
        or set(data)
        != {
            "exit_code",
            "output",
            "output_truncated",
            "output_trust",
            "test_correctness_verified",
            "snapshot_digest",
        }
        or type(data["output"]) is not str
        or len(data["output"]) > 8192
        or type(data["output_truncated"]) is not bool
        or data["output_trust"] != "untrusted_test_diagnostic"
        or data["test_correctness_verified"] is not False
        or data["exit_code"] is not None
        and type(data["exit_code"]) is not int
    ):
        raise ValueError("closed test diagnostic shape required")
    _hex(data["snapshot_digest"], "original test snapshot digest")
    if len(wire(data)) <= maximum:
        return wire(data)
    text = data["output"]
    low, high = 0, len(text)
    data["output_truncated"] = True
    while low < high:
        middle = (low + high + 1) // 2
        data["output"] = text[:middle]
        if len(wire(data)) <= maximum:
            low = middle
        else:
            high = middle - 1
    data["output"] = text[:low]
    result = wire(data)
    if len(result) > maximum:
        raise ValueError("test metadata exceeds delivery bound")
    return result
