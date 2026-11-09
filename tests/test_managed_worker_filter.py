"""Pure classic-BPF semantics of the actual emitter; never install a filter."""

import ast
import ctypes
import errno
import hashlib
import json
from pathlib import Path
import struct
from typing import Any

import pytest


ALLOW, DENY, KILL = 0x7FFF0000, 0x00050000 | errno.EPERM, 0x80000000


@pytest.fixture(scope="module")
def emitted_filter():
    source = Path(__file__).resolve().parents[1] / "ordin/swarm/_managed_worker.py"
    parsed = ast.parse(source.read_text(encoding="utf-8"))
    functions: list[ast.stmt] = [
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name in {"wire", "install_filter"}
    ]
    assert len(functions) == 2
    namespace: dict[str, Any] = {"ctypes": ctypes, "errno": errno, "hashlib": hashlib, "json": json}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), namespace)
    captured: list[tuple[int, int, int, int]] = []

    class Capture:
        def prctl(self, option, mode, pointer, first, second):
            assert (option, mode, first, second) == (22, 2, 0, 0)
            program = pointer._obj
            captured.extend(
                (entry.code, entry.jt, entry.jf, entry.k)
                for entry in program.filters[: program.length]
            )
            return 0

    digest = namespace["install_filter"](Capture())
    assert len(digest) == 64 and captured
    return captured


def evaluate(code, number, arguments=(0, 0, 0, 0, 0, 0), *, arch=0xC000003E):
    """Independent Linux seccomp_data byte layout, including both argument words."""
    data = struct.pack("<IIQ6Q", number & 0xFFFFFFFF, arch, 0, *arguments)
    pc, accumulator = 0, 0
    for _ in range(len(code) * 2):
        operation, yes, no, value = code[pc]
        pc += 1
        if operation == 0x20:
            accumulator = struct.unpack_from("<I", data, value)[0]
        elif operation == 0x15:
            pc += yes if accumulator == value else no
        elif operation == 0x06:
            return value
        else:
            raise AssertionError("unexpected generated BPF operation")
    raise AssertionError("generated policy did not terminate")


@pytest.mark.parametrize("timeout_pointer", [0, 1, 0x1000, 1 << 32, (1 << 64) - 1])
def test_only_empty_pselect_wait_is_admitted_with_kernel_checked_timeout(
    emitted_filter, timeout_pointer
):
    assert evaluate(emitted_filter, 270, (0, 0, 0, 0, timeout_pointer, 0)) == ALLOW


@pytest.mark.parametrize("argument", [0, 1, 2, 3, 5])
@pytest.mark.parametrize("value", [1, 3, 1 << 32, 1 << 63, (1 << 64) - 1])
def test_each_nonempty_pselect_argument_including_high_word_is_denied(
    emitted_filter, argument, value
):
    arguments = [0, 0, 0, 0, 0x1000, 0]
    arguments[argument] = value
    assert evaluate(emitted_filter, 270, tuple(arguments)) == DENY


@pytest.mark.parametrize("number", [7, 23, 232, 271, 281, 999, 0x40000000 | 270])
def test_general_poll_select_epoll_and_unknown_calls_remain_denied(emitted_filter, number):
    assert evaluate(emitted_filter, number) == DENY


@pytest.mark.parametrize(
    "number",
    [
        16,
        41,
        42,
        43,
        49,
        50,
        53,
        56,
        57,
        58,
        59,
        62,
        101,
        165,
        234,
        272,
        285,
        304,
        308,
        322,
        424,
        435,
    ],
)
def test_neighbor_descriptor_quota_filesystem_network_and_process_denials_remain(
    emitted_filter, number
):
    assert evaluate(emitted_filter, number) == DENY


def test_neighbor_fcntl_readbacks_and_prctl_readbacks_keep_their_existing_scope(emitted_filter):
    for command in (0, 1, 2, 3, 1030):
        assert evaluate(emitted_filter, 72, (3, command, 0, 0, 0, 0)) == ALLOW
    for command in (4, 8, 10):
        assert evaluate(emitted_filter, 72, (3, command, 0, 0, 0, 0)) == DENY
    for command in (21, 39):
        assert evaluate(emitted_filter, 157, (command, 0, 0, 0, 0, 0)) == ALLOW
    for command in (22, 38):
        assert evaluate(emitted_filter, 157, (command, 0, 0, 0, 0, 0)) == DENY
    assert evaluate(emitted_filter, 269) == ALLOW
    assert evaluate(emitted_filter, 273) == ALLOW
    assert evaluate(emitted_filter, 270, arch=0x40000003) == KILL
