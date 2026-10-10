"""Bounded external JSON and a closed parser for pinned upstream schemas.

Only bundled trusted schemas are read. Artifact $schema/$ref values never fetch
files or URLs. Multiline code and threat-model text remain inert untrusted data.
"""

from __future__ import annotations

import json
import hashlib
import math
import re
from datetime import datetime
from functools import lru_cache
from importlib.resources import files
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit

MAX_BYTES = 1_048_576
MAX_TEXT = 65_536
MAX_DEPTH = 16
MAX_NODES = 65_536
_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")
_LINK = re.compile(r"(?:\]\(|href\s*=\s*['\"])([^\s)'\"]+)", re.IGNORECASE)


def freeze(value: Any, *, depth=0, budget=None) -> Any:
    budget = [MAX_NODES] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        raise ValueError("scanner artifact structure limit")
    if isinstance(value, Mapping):
        if len(value) > 256 or any(
            not isinstance(k, str)
            or not k
            or len(k) > 128
            or any(ord(c) < 32 for c in k)
            or _BAD.search(k)
            for k in value
        ):
            raise ValueError("scanner artifact property limit")
        return MappingProxyType(
            {k: freeze(v, depth=depth + 1, budget=budget) for k, v in value.items()}
        )
    if isinstance(value, (list, tuple)):
        if len(value) > 1024:
            raise ValueError("scanner artifact collection limit")
        return tuple(freeze(v, depth=depth + 1, budget=budget) for v in value)
    if isinstance(value, str):
        if len(value) > MAX_TEXT or _BAD.search(value):
            raise ValueError("scanner artifact text limit")
        return value
    if value is None or type(value) in {bool, int}:
        if type(value) is int and value.bit_length() > 128:
            raise ValueError("scanner artifact numeric limit")
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("scanner artifacts require finite JSON data")


def thaw(value):
    if isinstance(value, Mapping):
        return {k: thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [thaw(v) for v in value]
    return value


def canonical(value) -> str:
    return json.dumps(
        thaw(freeze(value)),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def loads(raw: str | bytes) -> dict:
    if not isinstance(raw, (str, bytes)):
        raise ValueError("scanner artifact must be JSON bytes")
    try:
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(data) > MAX_BYTES:
            raise ValueError("scanner artifact byte limit")
        text = data.decode("utf-8")
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
                    raise ValueError("scanner artifact nesting limit")
            elif char in "]}":
                depth -= 1

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("scanner artifact duplicate JSON property")
                result[key] = value
            return result

        def nonfinite(value):
            raise ValueError("scanner artifact nonfinite number")

        value = json.loads(text, object_pairs_hook=unique, parse_constant=nonfinite)
        if not isinstance(value, dict):
            raise ValueError("scanner artifact root must be object")
        return thaw(freeze(value))
    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise ValueError("scanner artifact JSON invalid") from None


def safe_link(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(ord(c) <= 32 or ord(c) == 127 for c in value)
        or "\\" in value
    ):
        raise ValueError("scanner artifact link invalid")
    parsed = urlsplit(value)
    if parsed.scheme:
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.query
        ):
            raise ValueError("scanner artifact hyperlink unsupported")
        try:
            parsed.port
        except ValueError:
            raise ValueError("scanner artifact port invalid") from None
    else:
        from ordin.assurance._files import relative_parts

        relative_parts(value)


def check_links(value, *, key="") -> None:
    if isinstance(value, Mapping):
        for name, child in value.items():
            check_links(child, key=name)
    elif isinstance(value, (list, tuple)):
        for child in value:
            check_links(child, key=key)
    elif isinstance(value, str) and key not in {"code", "content"}:
        for match in _LINK.finditer(value):
            safe_link(match.group(1))
        if key in {"url", "uri", "remote", "sourceLink", "helpUri"}:
            safe_link(value)


@lru_cache(maxsize=4)
def schema(name: str) -> dict:
    if name not in {"findings", "scan-manifest", "coverage", "patch-risk-assessment"}:
        raise ValueError("unknown trusted scanner schema")
    raw = (
        files("ordin")
        .joinpath("resources")
        .joinpath("codex_security")
        .joinpath(name + ".schema.json")
        .read_bytes()
        .replace(b"\r\n", b"\n")
    )
    expected = {
        "findings": "c2012259f7b485837daa6b53f869da93a2b4460a",
        "scan-manifest": "bf614d85f19926a1347377ad8037925109de1def",
        "coverage": "21e0877db08d4cccc8fe5616feab7f8ef8da50af",
        "patch-risk-assessment": "b89b932582bd31e3f0dcf7ddaff3b9366157b579",
    }
    if hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != expected[name]:
        raise ValueError("bundled scanner schema differs from pinned upstream blob")
    return json.loads(raw)


def _matches(value, expected):
    return {
        "object": lambda: isinstance(value, dict),
        "array": lambda: isinstance(value, list),
        "string": lambda: isinstance(value, str),
        "integer": lambda: type(value) is int,
        "number": lambda: type(value) in {int, float},
        "boolean": lambda: type(value) is bool,
        "null": lambda: value is None,
    }[expected]()


def _equal_json(first, second):
    if type(first) in {int, float} and type(second) in {int, float}:
        return first == second
    if type(first) is not type(second):
        return False
    if isinstance(first, list):
        return len(first) == len(second) and all(_equal_json(a, b) for a, b in zip(first, second))
    if isinstance(first, dict):
        return set(first) == set(second) and all(
            _equal_json(value, second[key]) for key, value in first.items()
        )
    return first == second


def _check(value, shape, definitions, *, closed=True, depth=0):
    if depth > 32:
        raise ValueError("trusted schema nesting limit")
    if "$ref" in shape:
        ref = shape["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/$defs/") or ref[8:] not in definitions:
            raise ValueError("trusted schema reference unsupported")
        return _check(value, definitions[ref[8:]], definitions, closed=closed, depth=depth + 1)
    typ = shape.get("type")
    if typ is not None and not any(
        _matches(value, t) for t in (typ if isinstance(typ, list) else [typ])
    ):
        return False
    if (
        "const" in shape
        and not _equal_json(value, shape["const"])
        or "enum" in shape
        and not any(_equal_json(value, option) for option in shape["enum"])
    ):
        return False
    if isinstance(value, str):
        if len(value) < shape.get("minLength", 0) or len(value) > shape.get("maxLength", MAX_TEXT):
            return False
        if "pattern" in shape and re.search(shape["pattern"], value) is None:
            return False
        if shape.get("format") == "date-time":
            try:
                if datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
                    return False
            except ValueError:
                return False
    if type(value) in {int, float} and (
        value < shape.get("minimum", float("-inf")) or value > shape.get("maximum", float("inf"))
    ):
        return False
    if isinstance(value, dict):
        if len(value) < shape.get("minProperties", 0) or len(value) > shape.get(
            "maxProperties", 256
        ):
            return False
        if any(k not in value for k in shape.get("required", [])):
            return False
        props = shape.get("properties", {})
        extra = shape.get("additionalProperties", not (closed and typ is not None and bool(props)))
        for key, child in value.items():
            if key in props:
                if not _check(
                    child, props[key], definitions, closed=key != "extensions", depth=depth + 1
                ):
                    return False
            elif extra is False:
                return False
            elif isinstance(extra, dict) and not _check(
                child, extra, definitions, closed=closed, depth=depth + 1
            ):
                return False
    if isinstance(value, list):
        if len(value) < shape.get("minItems", 0) or len(value) > shape.get("maxItems", 1024):
            return False
        if shape.get("uniqueItems") is True and any(
            _equal_json(prior, item) for index, item in enumerate(value) for prior in value[:index]
        ):
            return False
        if "items" in shape and any(
            not _check(v, shape["items"], definitions, closed=closed, depth=depth + 1)
            for v in value
        ):
            return False
        if "contains" in shape:
            count = sum(
                _check(v, shape["contains"], definitions, closed=False, depth=depth + 1)
                for v in value
            )
            if not shape.get("minContains", 1) <= count <= shape.get("maxContains", 1024):
                return False
    if any(
        not _check(value, s, definitions, closed=False, depth=depth + 1)
        for s in shape.get("allOf", [])
    ):
        return False
    if "anyOf" in shape and not any(
        _check(value, s, definitions, closed=closed, depth=depth + 1) for s in shape["anyOf"]
    ):
        return False
    if "if" in shape:
        branch = (
            "then"
            if _check(value, shape["if"], definitions, closed=False, depth=depth + 1)
            else "else"
        )
        if branch in shape and not _check(
            value, shape[branch], definitions, closed=False, depth=depth + 1
        ):
            return False
    return True


def validate_document(name: str, value: dict) -> None:
    trusted = schema(name)
    freeze(value)
    if not _check(value, trusted, trusted.get("$defs", {})):
        raise ValueError("scanner artifact differs from pinned supported schema")
    check_links(value)
