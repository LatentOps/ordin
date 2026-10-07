"""Portable, bounded commitments to request authority without persisting values."""

from __future__ import annotations

import hashlib
import math
import json
from decimal import Decimal
from typing import Any, Mapping

REQUEST_COMMITMENT_ALGORITHM = "ordin.authority-json.sha256.v1"
MAX_COMMITMENT_BYTES = 1_048_576
MAX_COMMITMENT_NODES = 4096
MAX_COMMITMENT_DEPTH = 32
MAX_COMMITMENT_ITEMS = 128
MAX_COMMITMENT_TEXT_BYTES = 65_536
MAX_NUMBER_DIGITS = 1024
MAX_NUMBER_EXPONENT = 10_000


def _decimal_token(value: Decimal) -> bytes:
    if not value.is_finite():
        raise ValueError("request_commitment_invalid")
    sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):
        raise ValueError("request_commitment_invalid")
    if len(digits) > MAX_NUMBER_DIGITS or abs(exponent) > MAX_NUMBER_EXPONENT:
        raise ValueError("request_commitment_invalid")
    coefficient = "".join(str(digit) for digit in digits).lstrip("0") or "0"
    if coefficient == "0":
        exponent = 0
    else:
        while coefficient.endswith("0"):
            coefficient = coefficient[:-1]
            exponent += 1
    if abs(exponent) > MAX_NUMBER_EXPONENT:
        raise ValueError("request_commitment_invalid")
    return f"d{sign}:{coefficient}:{exponent};".encode("ascii")


def commitment_json(body: bytes) -> str:
    """Commit exact JSON decimals and reject duplicate decoded object keys."""
    if type(body) is not bytes or len(body) > MAX_COMMITMENT_BYTES:
        raise ValueError("request_commitment_invalid")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("request_commitment_invalid")
            result[key] = value
        return result

    try:
        value = json.loads(body.decode("utf-8"), parse_float=Decimal, object_pairs_hook=unique)
        return request_commitment(value)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("request_commitment_invalid") from None


def request_commitment(value: Any) -> str:
    """Hash a typed JSON tree; dictionary order is neutral, value/type changes aren't.

    Integers use decimal text. Decimal values use their exact normalized decimal
    coefficient and exponent; floats use the decimal spelling sent by Python's
    JSON encoder. Raw JSON callers must use commitment_json to retain precision.
    Strings use UTF-8 bytes with length framing. No normalization, interpretation,
    network access, or persistence occurs here. The pinned runtime implements the
    same versioned encoding; an unsupported backend must reject these grants.
    """
    hasher = hashlib.sha256()
    hasher.update(b"ordin.authority-json.v1\0")
    total = 0
    nodes = 0
    active: set[int] = set()

    def write(data: bytes) -> None:
        nonlocal total
        total += len(data)
        if total > MAX_COMMITMENT_BYTES:
            raise ValueError("request_commitment_invalid")
        hasher.update(data)

    def text(value: str) -> bytes:
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_COMMITMENT_TEXT_BYTES:
            raise ValueError("request_commitment_invalid")
        return encoded

    def walk(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_COMMITMENT_NODES or depth > MAX_COMMITMENT_DEPTH:
            raise ValueError("request_commitment_invalid")
        if item is None:
            write(b"n")
        elif type(item) is bool:
            write(b"t" if item else b"f")
        elif type(item) is int:
            if item.bit_length() > 3402:
                raise ValueError("request_commitment_invalid")
            if len(str(abs(item))) > MAX_NUMBER_DIGITS:
                raise ValueError("request_commitment_invalid")
            write(b"i" + str(item).encode("ascii") + b";")
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("request_commitment_invalid")
            write(_decimal_token(Decimal(repr(item))))
        elif isinstance(item, Decimal):
            write(_decimal_token(item))
        elif isinstance(item, str):
            encoded = text(item)
            write(b"s" + str(len(encoded)).encode("ascii") + b":" + encoded)
        elif isinstance(item, (Mapping, list, tuple)):
            if len(item) > MAX_COMMITMENT_ITEMS or id(item) in active:
                raise ValueError("request_commitment_invalid")
            active.add(id(item))
            if isinstance(item, Mapping):
                if any(not isinstance(k, str) for k in item):
                    raise ValueError("request_commitment_invalid")
                keys = sorted(item, key=text)
                write(b"o" + str(len(keys)).encode("ascii") + b":")
                for key in keys:
                    walk(key, depth + 1)
                    walk(item[key], depth + 1)
            else:
                write(b"l" + str(len(item)).encode("ascii") + b":")
                for child in item:
                    walk(child, depth + 1)
            write(b";")
            active.remove(id(item))
        else:
            raise ValueError("request_commitment_invalid")

    try:
        walk(value, 0)
    except (ValueError, UnicodeError, RuntimeError, RecursionError, KeyError):
        raise ValueError("request_commitment_invalid") from None
    return hasher.hexdigest()


def rpc_authority_commitment(message: Mapping[str, Any]) -> str:
    """Bind method and params; transport correlation IDs confer no authority."""
    return request_commitment(_rpc_projection(message))


def rpc_body_commitment(body: Any) -> str:
    """Bind an ordered RPC batch as a whole, including call multiplicity."""
    request_commitment(body)
    if isinstance(body, (list, tuple)):
        if not body or len(body) > MAX_COMMITMENT_ITEMS:
            raise ValueError("request_commitment_invalid")
        return request_commitment([_rpc_projection(message) for message in body])
    return request_commitment(_rpc_projection(body))


def _rpc_projection(message: Any) -> dict:
    if (
        not isinstance(message, Mapping)
        or set(message) - {"jsonrpc", "id", "method", "params"}
        or message.get("jsonrpc") != "2.0"
        or type(message.get("method")) is not str
        or not 1 <= len(message["method"]) <= 128
        or any(ord(c) <= 32 or ord(c) == 127 or c == "*" for c in message["method"])
        or "id" in message
        and message["id"] is not None
        and type(message["id"]) not in {str, int, float, Decimal}
        or "params" in message
        and message["params"] is not None
        and not isinstance(message["params"], (Mapping, list, tuple))
    ):
        raise ValueError("request_commitment_invalid")
    # Validate even the omitted correlation value so malformed/unbounded IDs
    # cannot disappear from resource validation.
    request_commitment(message)
    result = {"kind": "request" if "id" in message else "notification", "method": message["method"]}
    if "params" in message:
        result["params"] = message["params"]
    return result
