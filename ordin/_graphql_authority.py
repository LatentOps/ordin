"""Bounded GraphQL operation selection; values are committed separately."""

from __future__ import annotations

import re
from typing import Any, Mapping

MAX_GRAPHQL_NODES = 4096

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_TOKEN = re.compile(
    r'[ \t\r\n]+|#[^\r\n]*|,|\ufeff|\.\.\.|"""(?:\\"""|(?!(?:""")).)*"""'
    r'|"(?:[^"\\\r\n]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
    r"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
    r"|[A-Za-z_][A-Za-z0-9_]*|[!$():=@\[\]{}|]",
    re.DOTALL,
)


class _Parser:
    def __init__(self, source: Any):
        if not isinstance(source, str) or len(source.encode("utf-8")) > 65536:
            raise ValueError("graphql_authority_invalid")
        self.tokens: list[str] = []
        position = 0
        while position < len(source):
            match = _TOKEN.match(source, position)
            if match is None or len(self.tokens) >= MAX_GRAPHQL_NODES:
                raise ValueError("graphql_authority_invalid")
            token = match[0]
            if (
                source.startswith('"""', position)
                and not token.startswith('"""')
                or token[0] in "-0123456789"
                and match.end() < len(source)
                and source[match.end()]
                in "0123456789.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"
            ):
                raise ValueError("graphql_authority_invalid")
            if token.startswith('"') and not token.startswith('"""'):
                cursor = 1
                while cursor < len(token) - 1:
                    if ord(token[cursor]) < 32 and token[cursor] != "\t":
                        raise ValueError("graphql_authority_invalid")
                    if token[cursor] == "\\":
                        cursor += 1
                        if token[cursor] == "u":
                            codepoint = int(token[cursor + 1 : cursor + 5], 16)
                            if 0xD800 <= codepoint <= 0xDFFF:
                                raise ValueError("graphql_authority_invalid")
                            cursor += 4
                    cursor += 1
            if not token.isspace() and not token.startswith("#") and token not in {",", "\ufeff"}:
                self.tokens.append(token)
            position = match.end()
        self.position = 0
        self.fragments: dict[str, list[Any]] = {}
        self.fragment_variables: dict[str, set[str]] = {}
        self.references: set[str] = set()
        self.operations: list[tuple[str, str | None, list[Any], set[str], set[str], set[str]]] = []

    def peek(self):
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self, expected=None):
        result = self.peek()
        if result is None or expected is not None and result != expected:
            raise ValueError("graphql_authority_invalid")
        self.position += 1
        return result

    def name(self):
        result = self.take()
        if len(result) > 128 or not _NAME.fullmatch(result):
            raise ValueError("graphql_authority_invalid")
        return result

    def value(self, depth=0, *, constant=False):
        if depth > 32:
            raise ValueError("graphql_authority_invalid")
        token = self.take()
        if token == "$" and not constant:
            self.references.add(self.name())
        elif token == "[":
            while self.peek() != "]":
                self.value(depth + 1, constant=constant)
            self.take("]")
        elif token == "{":
            seen = set()
            while self.peek() != "}":
                name = self.name()
                if name in seen:
                    raise ValueError("graphql_authority_invalid")
                seen.add(name)
                self.take(":")
                self.value(depth + 1, constant=constant)
            self.take("}")
        elif not (
            _NAME.fullmatch(token) or token.startswith('"') or re.fullmatch(r"-?[0-9].*", token)
        ):
            raise ValueError("graphql_authority_invalid")

    def arguments(self):
        if self.peek() != "(":
            return ()
        self.take()
        seen = set()
        values = []
        while self.peek() != ")":
            name = self.name()
            if name in seen:
                raise ValueError("graphql_authority_invalid")
            seen.add(name)
            self.take(":")
            start = self.position
            self.value()
            values.append((name, tuple(self.tokens[start : self.position])))
        self.take(")")
        if not seen:
            raise ValueError("graphql_authority_invalid")
        return tuple(sorted(values))

    def directives(self):
        while self.peek() == "@":
            self.take()
            self.name()
            self.arguments()

    def type_ref(self, depth=0):
        if depth > 16:
            raise ValueError("graphql_authority_invalid")
        if self.peek() == "[":
            self.take()
            self.type_ref(depth + 1)
            self.take("]")
        else:
            self.name()
        if self.peek() == "!":
            self.take()
            return True
        return False

    def variables(self):
        if self.peek() != "(":
            return set(), set()
        self.take()
        seen = set()
        required = set()
        while self.peek() != ")":
            self.take("$")
            name = self.name()
            if name in seen:
                raise ValueError("graphql_authority_invalid")
            seen.add(name)
            self.take(":")
            non_null = self.type_ref()
            has_default = self.peek() == "="
            if self.peek() == "=":
                self.take()
                self.value(constant=True)
            if non_null and not has_default:
                required.add(name)
            self.directives()
        self.take(")")
        if not seen:
            raise ValueError("graphql_authority_invalid")
        return required, seen

    def selection(self, depth=0):
        if depth > 32:
            raise ValueError("graphql_authority_invalid")
        self.take("{")
        result = []
        while self.peek() != "}":
            if self.peek() == "...":
                self.take()
                if self.peek() == "on" or self.peek() == "@" or self.peek() == "{":
                    if self.peek() == "on":
                        self.take()
                        self.name()
                    self.directives()
                    result.append(("inline", "", self.selection(depth + 1), "", ()))
                else:
                    name = self.name()
                    self.directives()
                    result.append(("spread", name, [], "", ()))
            else:
                name = self.name()
                response = name
                if self.peek() == ":":
                    self.take()
                    name = self.name()
                arguments = self.arguments()
                self.directives()
                children = self.selection(depth + 1) if self.peek() == "{" else []
                result.append(("field", name, children, response, arguments))
        self.take("}")
        if not result:
            raise ValueError("graphql_authority_invalid")
        return result

    def document(self, selected, variables):
        while self.peek() is not None:
            self.references = set()
            if self.peek() == "fragment":
                self.take()
                name = self.name()
                if name == "on" or name in self.fragments:
                    raise ValueError("graphql_authority_invalid")
                self.take("on")
                self.name()
                self.directives()
                self.fragments[name] = self.selection()
                self.fragment_variables[name] = self.references
            else:
                kind, name = "query", None
                required, declared = set(), set()
                if self.peek() != "{":
                    kind = self.take()
                    if kind not in {"query", "mutation", "subscription"}:
                        raise ValueError("graphql_authority_invalid")
                    if self.peek() not in {"(", "@", "{"}:
                        name = self.name()
                    required, declared = self.variables()
                    self.directives()
                nodes = self.selection()
                self.operations.append((kind, name, nodes, required, declared, self.references))
        names = [operation[1] for operation in self.operations]
        if not names or len(set(names)) != len(names) or None in names and len(names) != 1:
            raise ValueError("graphql_authority_invalid")
        if selected is not None and (
            not isinstance(selected, str) or not _NAME.fullmatch(selected)
        ):
            raise ValueError("graphql_authority_invalid")
        matching = [o for o in self.operations if selected is None or o[1] == selected]
        if len(matching) != 1:
            raise ValueError("graphql_authority_invalid")
        fields = set()
        visits = 0
        used = set()
        references = set()
        responses: dict[tuple[str, ...], Any] = {}

        def expand(nodes, prefix=(), active=frozenset(), response_prefix=()):
            nonlocal visits
            for kind, name, children, response, arguments in nodes:
                visits += 1
                if visits > MAX_GRAPHQL_NODES or len(prefix) + len(active) > 32:
                    raise ValueError("graphql_authority_invalid")
                if kind == "field":
                    key = (*response_prefix, response)
                    signature = (name, arguments)
                    if key in responses and responses[key] != signature:
                        raise ValueError("graphql_authority_invalid")
                    responses[key] = signature
                    fields.add(".".join((*prefix, name)))
                    expand(children, (*prefix, name), active, key)
                elif kind == "inline":
                    expand(children, prefix, active, response_prefix)
                else:
                    if name not in self.fragments or name in active:
                        raise ValueError("graphql_authority_invalid")
                    used.add(name)
                    references.update(self.fragment_variables[name])
                    expand(self.fragments[name], prefix, active | {name}, response_prefix)

        operation = matching[0]
        if any(name not in variables or variables[name] is None for name in operation[3]):
            raise ValueError("graphql_authority_invalid")
        for definition in self.operations:
            fields.clear()
            responses.clear()
            references.clear()
            references.update(definition[5])
            expand(definition[2])
            if not references.issubset(definition[4]):
                raise ValueError("graphql_authority_invalid")
        if used != set(self.fragments):
            raise ValueError("graphql_authority_invalid")
        fields.clear()
        responses.clear()
        expand(operation[2])
        return {
            "operation_type": operation[0],
            "operation_name": operation[1],
            "fields": sorted(fields),
        }


def graphql_authorities(body: Any) -> tuple[dict, ...]:
    messages = body if isinstance(body, (list, tuple)) else (body,)
    if not messages or len(messages) > 128:
        raise ValueError("graphql_authority_invalid")
    result = []
    try:
        for message in messages:
            if (
                not isinstance(message, Mapping)
                or set(message) - {"query", "variables", "operationName"}
                or "variables" in message
                and message["variables"] is not None
                and not isinstance(message["variables"], Mapping)
            ):
                raise ValueError("graphql_authority_invalid")
            result.append(
                _Parser(message.get("query")).document(
                    message.get("operationName"), message.get("variables") or {}
                )
            )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("graphql_authority_invalid") from None
    return tuple(result)
