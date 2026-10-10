"""Standalone vetted synthetic worker. The host broker supplies physical isolation."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from typing import Any

PROTOCOL = "ordin.vetted_synthetic_test.v1"


def vet_program(source):
    if not isinstance(source, str) or not 1 <= len(source.encode("utf-8")) <= 4096:
        raise ValueError("unsupported synthetic program")
    try:
        tree = ast.parse(source)
    except (SyntaxError, RecursionError):
        raise ValueError("unsupported synthetic program syntax") from None
    nodes = list(ast.walk(tree))
    if len(nodes) > 64 or len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError("unsupported synthetic program")
    function = tree.body[0]
    if (
        function.name != "within_root"
        or function.decorator_list
        or function.returns
        or function.type_comment
        or getattr(function, "type_params", None)
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Return)
        or function.args.posonlyargs
        or function.args.kwonlyargs
        or function.args.vararg
        or function.args.kwarg
        or function.args.defaults
        or function.args.kw_defaults
        or [arg.arg for arg in function.args.args] != ["path", "root"]
        or any(arg.annotation for arg in function.args.args)
    ):
        raise ValueError("unsupported synthetic program")

    def expression(node, depth=0):
        if depth > 8:
            raise ValueError("synthetic expression limit")
        if isinstance(node, ast.Name) and node.id in {"path", "root"}:
            return
        if isinstance(node, ast.Constant) and type(node.value) is str and node.value in {"", "/"}:
            return
        if (
            isinstance(node, ast.BoolOp)
            and isinstance(node.op, (ast.And, ast.Or))
            and 2 <= len(node.values) <= 4
        ):
            for child in node.values:
                expression(child, depth + 1)
            return
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == len(node.comparators) == 1
            and isinstance(node.ops[0], (ast.Eq, ast.NotEq))
        ):
            expression(node.left, depth + 1)
            expression(node.comparators[0], depth + 1)
            return
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            expression(node.left, depth + 1)
            expression(node.right, depth + 1)
            return
        if (
            isinstance(node, ast.Call)
            and not node.keywords
            and len(node.args) == 1
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"startswith", "rstrip"}
        ):
            expression(node.func.value, depth + 1)
            expression(node.args[0], depth + 1)
            return
        raise ValueError("synthetic program contains an unvetted operation")

    expression(function.body[0].value)
    return ast.unparse(tree) + "\n"


def expected_path_result(path, root):
    # Independent lexical property. Physical paths/aliases are outside this test.
    return path == root or path.startswith(root + "/")


def execute_request(packet):
    expected_fields = {
        "protocol",
        "request_digest",
        "source_digest",
        "suite_digest",
        "runtime_digest",
        "program",
        "cases",
        "limits",
    }
    if (
        not isinstance(packet, dict)
        or set(packet) != expected_fields
        or packet["protocol"] != PROTOCOL
    ):
        raise ValueError("unsupported worker request")
    material = {key: value for key, value in packet.items() if key != "request_digest"}
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    if hashlib.sha256(encoded).hexdigest() != packet["request_digest"]:
        raise ValueError("worker request binding changed")
    limits = packet["limits"]
    bounds = {
        "timeout_ms": (100, 30000),
        "cpu_seconds": (1, 30),
        "memory_mib": (32, 1024),
        "max_processes": (1, 4),
        "max_output_bytes": (1024, 65536),
    }
    if (
        not isinstance(limits, dict)
        or set(limits) != set(bounds)
        or any(
            type(limits[key]) is not int or not low <= limits[key] <= high
            for key, (low, high) in bounds.items()
        )
    ):
        raise ValueError("worker resource contract malformed")
    program = vet_program(packet["program"])
    cases = packet["cases"]
    if not isinstance(cases, list) or not 2 <= len(cases) <= 32:
        raise ValueError("worker case limit")
    namespace: dict[str, Any] = {"__builtins__": {}}
    exec(compile(program, "<vetted-synthetic-predicate>", "exec"), namespace)
    results = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"case_id", "path", "root"}:
            raise ValueError("worker case malformed")
        if any(type(case[key]) is not str or not 1 <= len(case[key]) <= 256 for key in case):
            raise ValueError("worker case malformed")
        actual = namespace["within_root"](case["path"], case["root"])
        if type(actual) is not bool:
            raise ValueError("worker prediction must be boolean")
        results.append({"case_id": case["case_id"], "actual": actual})
    return {
        "protocol": PROTOCOL,
        "request_digest": packet["request_digest"],
        "source_digest": packet["source_digest"],
        "suite_digest": packet["suite_digest"],
        "results": results,
    }


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError("input limit")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate input")
                result[key] = value
            return result

        def reject(_):
            raise ValueError("nonfinite input")

        packet = json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
        result = execute_request(packet)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('{"error":"vetted_test_refused"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
