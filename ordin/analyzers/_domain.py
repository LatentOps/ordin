from __future__ import annotations

from typing import Sequence


READ_VERBS = frozenset({"describe", "get", "head", "info", "list", "lookup", "read", "show"})
WRITE_VERBS = frozenset(
    {
        "add",
        "apply",
        "associate",
        "attach",
        "authorize",
        "copy",
        "create",
        "deploy",
        "disable",
        "enable",
        "import",
        "invoke",
        "modify",
        "move",
        "publish",
        "put",
        "reboot",
        "register",
        "restore",
        "run",
        "send",
        "set",
        "start",
        "stop",
        "submit",
        "sync",
        "update",
        "upload",
    }
)
DELETE_VERBS = frozenset(
    {
        "delete",
        "deregister",
        "destroy",
        "detach",
        "disassociate",
        "purge",
        "remove",
        "terminate",
    }
)


def option_key(token: str) -> str:
    return token.split("=", 1)[0]


def positionals(
    args: Sequence[str],
    value_options: set[str] | frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    result: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            result.extend(args[index + 1 :])
            break
        if token.startswith("-"):
            key = option_key(token)
            if key in value_options and "=" not in token and token == key:
                index += 2
            else:
                index += 1
            continue
        result.append(token)
        index += 1
    return tuple(result)


def flags(args: Sequence[str]) -> tuple[str, ...]:
    return tuple(token for token in args if token.startswith("-"))


def resource(namespace: str, *parts: str | None) -> str:
    cleaned = [part for part in parts if part]
    return ":".join((namespace, *cleaned)) if cleaned else namespace


def cloud_direction(items: Sequence[str], remote_prefix: str) -> tuple[bool, bool]:
    operands = [item for item in items if not item.startswith("-")]
    if len(operands) < 2:
        return False, False
    source, target = operands[-2], operands[-1]
    return target.startswith(remote_prefix), source.startswith(remote_prefix)


def verb_effect(verb: str) -> str | None:
    normalized = verb.lower().replace("_", "-")
    candidates = {normalized, *(piece for piece in normalized.split("-") if piece)}
    if candidates & DELETE_VERBS:
        return "infrastructure.delete"
    if candidates & WRITE_VERBS:
        return "infrastructure.write"
    if candidates & READ_VERBS:
        return "infrastructure.read"
    return None
