from __future__ import annotations

import shlex
from pathlib import PurePosixPath
from typing import Sequence


SEGMENT_OPERATORS = {"&&", "||", ";", "|", "&"}
SHELL_EXECUTABLES = {"bash", "dash", "ksh", "sh", "zsh"}
SUDO_OPTIONS_WITH_VALUE = {"-C", "-D", "-g", "-h", "-p", "-R", "-T", "-u"}


def _normalize_unquoted_newlines(command: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False

    for char in command:
        if escaped:
            output.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            output.append(char)
            escaped = True
            continue
        if quote:
            output.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            output.append(char)
        elif char == "\n":
            output.append(" ; ")
        else:
            output.append(char)
    return "".join(output)


def shell_tokens(command: str) -> list[str]:
    normalized = _normalize_unquoted_newlines(command)
    lexer = shlex.shlex(normalized, posix=True, punctuation_chars=";&|<>()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def split_shell_segments(command: str) -> tuple[list[list[str]], list[str]]:
    tokens = shell_tokens(command)
    segments: list[list[str]] = []
    operators: list[str] = []
    current: list[str] = []
    paren_depth = 0

    for token in tokens:
        if token == "(":
            paren_depth += 1
            current.append(token)
            continue
        if token == ")":
            current.append(token)
            paren_depth = max(0, paren_depth - 1)
            continue
        if token in SEGMENT_OPERATORS and paren_depth == 0:
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


def grouped_subshells_from_tokens(tokens: Sequence[str]) -> list[str]:
    scripts: list[str] = []
    depth = 0
    start = 0

    for index, token in enumerate(tokens):
        if token == "(":
            if depth == 0:
                previous = tokens[index - 1] if index > 0 else ""
                if previous == "$" or previous.endswith("$"):
                    continue
                start = index + 1
            depth += 1
        elif token == ")" and depth:
            depth -= 1
            if depth == 0:
                script = segment_text(tokens[start:index]).strip()
                if script:
                    scripts.append(script)
    return scripts


def command_substitutions(command: str) -> list[str]:
    scripts: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False

    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if quote == '"' and char == '"':
            quote = None
            index += 1
            continue
        if quote is None and char == "'":
            quote = "'"
            index += 1
            continue
        if quote is None and char == '"':
            quote = '"'
            index += 1
            continue

        if char == "`":
            cursor = index + 1
            inner_escaped = False
            while cursor < len(command):
                inner = command[cursor]
                if inner_escaped:
                    inner_escaped = False
                elif inner == "\\":
                    inner_escaped = True
                elif inner == "`":
                    script = command[index + 1:cursor].strip()
                    if script:
                        scripts.append(script)
                    index = cursor
                    break
                cursor += 1
            index += 1
            continue

        if char == "$" and index + 1 < len(command) and command[index + 1] == "(":
            start = index + 2
            cursor = start
            depth = 1
            inner_quote: str | None = None
            inner_escaped = False
            while cursor < len(command) and depth:
                inner = command[cursor]
                if inner_escaped:
                    inner_escaped = False
                elif inner == "\\" and inner_quote != "'":
                    inner_escaped = True
                elif inner_quote:
                    if inner == inner_quote:
                        inner_quote = None
                elif inner in {"'", '"'}:
                    inner_quote = inner
                elif inner == "(":
                    depth += 1
                elif inner == ")":
                    depth -= 1
                    if depth == 0:
                        script = command[start:cursor].strip()
                        if script:
                            scripts.append(script)
                        index = cursor
                        break
                cursor += 1
        index += 1

    return scripts
