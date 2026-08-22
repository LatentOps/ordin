from __future__ import annotations

import shlex
from pathlib import PurePosixPath
from typing import Sequence


SEGMENT_OPERATORS = {"&&", "||", ";", "|", "&"}
SHELL_EXECUTABLES = {"bash", "dash", "ksh", "sh", "zsh"}
SUDO_OPTIONS_WITH_VALUE = {"-C", "-D", "-g", "-h", "-p", "-R", "-T", "-u"}


def shell_tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def split_shell_segments(command: str) -> tuple[list[list[str]], list[str]]:
    tokens = shell_tokens(command)
    segments: list[list[str]] = []
    operators: list[str] = []
    current: list[str] = []

    for token in tokens:
        if token in SEGMENT_OPERATORS:
            if current:
                segments.append(current)
                current = []
                operators.append(token)
            continue
        current.append(token)

    if current:
        segments.append(current)

    if len(operators) >= len(segments):
        operators = operators[: max(0, len(segments) - 1)]
    return segments, operators


def segment_text(tokens: Sequence[str]) -> str:
    return " ".join(tokens)


def _basename(token: str) -> str:
    return PurePosixPath(token).name if "/" in token else token


def _is_assignment(token: str) -> bool:
    if "=" not in token or token.startswith("="):
        return False
    name, _ = token.split("=", 1)
    return bool(name) and name.replace("_", "a").isalnum() and not name[0].isdigit()


def _strip_wrappers(tokens: Sequence[str]) -> list[str]:
    remaining = list(tokens)

    while remaining and _is_assignment(remaining[0]):
        remaining.pop(0)

    changed = True
    while remaining and changed:
        changed = False
        executable = _basename(remaining[0])

        if executable == "sudo":
            remaining.pop(0)
            while remaining and remaining[0].startswith("-"):
                option = remaining.pop(0)
                if option in SUDO_OPTIONS_WITH_VALUE and remaining:
                    remaining.pop(0)
            changed = True
        elif executable == "env":
            remaining.pop(0)
            while remaining and (remaining[0].startswith("-") or _is_assignment(remaining[0])):
                remaining.pop(0)
            changed = True
        elif executable == "command":
            remaining.pop(0)
            while remaining and remaining[0].startswith("-"):
                remaining.pop(0)
            changed = True

        while remaining and _is_assignment(remaining[0]):
            remaining.pop(0)

    return remaining


def executable_name_from_tokens(tokens: Sequence[str]) -> str | None:
    remaining = _strip_wrappers(tokens)
    if not remaining:
        return None

    executable = _basename(remaining[0]).lower()
    if executable in {"python", "python3"} and len(remaining) >= 3 and remaining[1] == "-m":
        return _basename(remaining[2]).lower()
    return executable


def executable_name(command: str) -> str | None:
    try:
        segments, _ = split_shell_segments(command)
    except ValueError:
        return None
    if not segments:
        return None
    return executable_name_from_tokens(segments[0])


def command_name_candidates(tokens: Sequence[str]) -> set[str]:
    names: set[str] = set()
    if tokens:
        names.add(_basename(tokens[0]).lower())
    effective = executable_name_from_tokens(tokens)
    if effective:
        names.add(effective)
    return names


def shell_script_from_tokens(tokens: Sequence[str]) -> str | None:
    remaining = _strip_wrappers(tokens)
    if not remaining:
        return None
    executable = _basename(remaining[0]).lower()
    if executable not in SHELL_EXECUTABLES:
        return None
    for index, token in enumerate(remaining[1:], start=1):
        if token == "-c" and index + 1 < len(remaining):
            return remaining[index + 1]
    return None
