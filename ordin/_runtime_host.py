"""Bounded host and identity selectors for explicit operator boundaries."""

from __future__ import annotations

import re


def host_matches(pattern: str, host: str | None) -> bool:
    if not isinstance(pattern, str) or not isinstance(host, str):
        return False
    if pattern.startswith(("*.", "**.")):
        suffix = pattern.split(".", 1)[1]
        if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", suffix):
            return False
        return host.endswith("." + suffix) and (
            pattern.startswith("**.") or len(host.split(".")) == len(suffix.split(".")) + 1
        )
    return "*" not in pattern and pattern == host


def identity_matches(pattern: str | None, value: str | None) -> bool:
    if pattern is None or value is None:
        return pattern == value
    if (
        not isinstance(pattern, str)
        or not isinstance(value, str)
        or len(pattern) > 256
        or len(value) > 256
    ):
        return False
    if "*" not in pattern:
        return pattern == value
    return pattern.endswith("*") and pattern.count("*") == 1 and value.startswith(pattern[:-1])
