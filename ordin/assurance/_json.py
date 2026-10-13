"""Bounded, detached canonical JSON. Digests are not authentication or encryption."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from ._schemas import MAX_BYTES, MAX_DEPTH, MAX_ITEMS, MAX_TEXT, SCHEMAS, SHAPES

_UNSAFE_TEXT = re.compile(r"[\x00-\x1f\x7f\ud800-\udfff]")


def freeze(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [65536]
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        raise ValueError("assurance JSON structure limit exceeded")
    if isinstance(value, Mapping):
        if len(value) > MAX_ITEMS or any(
            not isinstance(key, str)
            or not key
            or len(key) > 128
            or _UNSAFE_TEXT.search(key) is not None
            for key in value
        ):
            raise ValueError("assurance JSON object limit exceeded")
        return MappingProxyType(
            {key: freeze(child, depth=depth + 1, budget=budget) for key, child in value.items()}
        )
    if isinstance(value, (tuple, list)):
        # Reports may contain more cases/edges than profiles. Schema-specific
        # caps remain mandatory; the global cap also bounds parsing before schema.
        if len(value) > 4096:
            raise ValueError("assurance JSON collection limit exceeded")
        return tuple(freeze(child, depth=depth + 1, budget=budget) for child in value)
    if isinstance(value, str):
        if len(value) > MAX_TEXT or _UNSAFE_TEXT.search(value) is not None:
            raise ValueError("assurance JSON text limit exceeded")
        return value
    if value is None or isinstance(value, (bool, int)):
        if isinstance(value, int) and value.bit_length() > 128:
            raise ValueError("assurance JSON numeric limit exceeded")
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ValueError("assurance JSON requires finite JSON values")


def thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [thaw(child) for child in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        thaw(freeze(value)),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def digest(domain: str, value: Any) -> str:
    return hashlib.sha256(
        (f"ordin.assurance:{domain}:v1\0" + canonical_json(value)).encode()
    ).hexdigest()


def validate(name: str, value: Any) -> None:
    from ordin.schema import validate_instance

    detached = thaw(freeze(value))
    encoded = json.dumps(
        detached, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    if len(encoded.encode()) > MAX_BYTES:
        raise ValueError("assurance JSON byte limit exceeded")
    shape = SCHEMAS[name] if name in SCHEMAS else SHAPES[name]
    if validate_instance(detached, shape):
        # Never copy rejected property names/values into diagnostics.
        raise ValueError(f"invalid {name}: schema validation failed")


def loads(data: str | bytes) -> dict[str, Any]:
    if not isinstance(data, (str, bytes)):
        raise ValueError("assurance JSON requires text or bytes")
    try:
        encoded = data.encode("utf-8") if isinstance(data, str) else data
        if len(encoded) > MAX_BYTES:
            raise ValueError("assurance JSON byte limit exceeded")
        text = encoded.decode("utf-8")
        # Limit nesting before json.loads, independent of Python's recursion limit.
        depth = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > MAX_DEPTH + 1:
                    raise ValueError("assurance JSON structure limit exceeded")
            elif char in "]}":
                depth -= 1

        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("assurance JSON duplicate property")
                result[key] = value
            return result

        def nonfinite(_: str) -> None:
            raise ValueError("assurance JSON requires finite numbers")

        payload = json.loads(text, object_pairs_hook=unique, parse_constant=nonfinite)
        frozen = freeze(payload)
        if not isinstance(frozen, Mapping):
            raise ValueError("assurance JSON requires an object")
        return thaw(frozen)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("invalid assurance JSON") from exc
