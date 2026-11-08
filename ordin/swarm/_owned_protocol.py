"""Closed Linux x86-64 owned-worker syscall profiles; no external policy loader."""

import hashlib
import json

WRITE_PROTOCOL = "ordin.swarm.linux_managed_write.v1"
HTTP_PROTOCOL = "ordin.swarm.linux_exact_http.v1"
FIONBIO = 0x5421  # Fixed Linux x86-64 ioctl ABI; only socket nonblocking state.


def wire(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def filter_code(mode):
    allow, deny = 0x7FFF0000, 0x00050001
    code = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    base: tuple[int, ...] = (
        0,
        1,
        3,
        5,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        24,
        25,
        28,
        35,
        39,
        60,
        96,
        98,
        102,
        104,
        107,
        108,
        110,
        131,
        186,
        201,
        202,
        228,
        230,
        231,
        318,
    )
    if mode == "http":
        base += (7, 271)
    for number in base:
        code.extend(((0x15, 0, 1, number), (0x06, 0, 0, allow)))

    def restricted(number, requirements):
        body = []
        for argument, values in requirements:
            body.append((0x20, 0, 0, 16 + argument * 8))
            for index, value in enumerate(values):
                body.append((0x15, len(values) - index, 0, value))
            body.append((0x06, 0, 0, deny))
        body.append((0x06, 0, 0, allow))
        code.append((0x15, 0, len(body), number))
        code.extend(body)

    restricted(157, ((0, (21, 39)),))
    restricted(77, ((0, (1,)),))
    if mode == "write":
        restricted(257, ((0, (3,)), (2, (2752512, 655554)), (3, (0o600,))))
        restricted(263, ((0, (3,)), (2, (0,))))
        restricted(316, ((0, (3,)), (2, (3,)), (4, (1, 2))))
        code.extend(((0x15, 0, 1, 74), (0x06, 0, 0, allow)))
    elif mode == "http":
        restricted(16, ((0, (3,)), (1, (FIONBIO,))))
        for number in (44, 45, 48, 51, 52, 54, 55):
            restricted(number, ((0, (3,)),))
    else:
        raise ValueError("unknown owned-worker mode")
    code.append((0x06, 0, 0, deny))
    return code


def filter_digest(mode):
    return hashlib.sha256(wire(filter_code(mode))).hexdigest()
