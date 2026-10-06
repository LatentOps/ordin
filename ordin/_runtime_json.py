"""Bounded, immutable JSON for the additive runtime contracts."""

from __future__ import annotations

import hashlib
import json
import math
from types import MappingProxyType
from typing import Any, Mapping

MAX_RUNTIME_BYTES = 1_048_576
MAX_RUNTIME_ITEMS = 128
MAX_RUNTIME_TEXT = 4096
MAX_RUNTIME_DEPTH = 10


def thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw(item) for item in value]
    return value


def freeze(value: Any, *, depth: int = 0, max_depth: int = MAX_RUNTIME_DEPTH) -> Any:
    if depth > max_depth:
        raise ValueError("runtime JSON nesting limit exceeded")
    if isinstance(value, Mapping):
        if len(value) > MAX_RUNTIME_ITEMS:
            raise ValueError("runtime JSON property limit exceeded")
        if any(not isinstance(k, str) or not k or len(k) > 128 for k in value):
            raise ValueError("runtime JSON requires bounded text keys")
        return MappingProxyType(
            {k: freeze(v, depth=depth + 1, max_depth=max_depth) for k, v in value.items()}
        )
    if isinstance(value, (tuple, list)):
        if len(value) > MAX_RUNTIME_ITEMS:
            raise ValueError("runtime JSON collection limit exceeded")
        return tuple(freeze(v, depth=depth + 1, max_depth=max_depth) for v in value)
    if isinstance(value, str):
        if len(value) > MAX_RUNTIME_TEXT or any(ord(c) < 32 for c in value):
            raise ValueError("runtime JSON contains oversized text or control characters")
        return value
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ValueError("runtime JSON requires finite JSON values")


def canonical_json(value: Any) -> str:
    return json.dumps(
        thaw(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def validate(name: str, payload: Any) -> None:
    from .schema import validate_instance
    from ._runtime_schemas import SCHEMAS, SHAPES

    freeze(payload)
    if len(canonical_json(payload).encode("utf-8")) > MAX_RUNTIME_BYTES:
        raise ValueError("runtime JSON byte limit exceeded")
    errors = validate_instance(thaw(payload), SCHEMAS[name] if name in SCHEMAS else SHAPES[name])
    if errors:
        # Validation errors can contain rejected values or property names. Keep
        # arbitrary input (including accidentally supplied secrets) out of logs.
        raise ValueError(f"invalid {name}: schema validation failed")


def model_tuple(value: Any, model: type) -> tuple:
    if not isinstance(value, (tuple, list)) or len(value) > MAX_RUNTIME_ITEMS:
        raise ValueError("runtime capabilities require a bounded collection")
    if any(not isinstance(item, model) for item in value):
        raise ValueError(f"runtime capabilities require {model.__name__} values")
    return tuple(value)


def text_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_RUNTIME_ITEMS:
        raise ValueError("runtime text values require a bounded array")
    if any(not isinstance(item, str) for item in value):
        raise ValueError("runtime text array requires string items")
    freeze(value)
    return tuple(value)
