from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .data import data_health, find_command
from .graph import build_effect_graph
from .indexer import DEFAULT_INDEX_PATH, build_index, build_index_from_lines
from .review import review_command
from .risk import check_command
from .search import search


def print_search(query: str, limit: int, as_json: bool = False) -> None:
    results = search(query, limit=limit)
    if as_json:
        print(json.dumps([result.as_dict() for result in results], indent=2))
        return

    if not results:
        print("No command matches found.")
        return

    for result in results:
        print(result.command)
        print(f"  summary: {result.summary}")
        print(f"  why: {result.why}")
        if result.example:
            print(f"  example: {result.example}")
        if result.suggested_commands:
            print("  suggested:")
            for suggestion in result.suggested_commands:
                print(f"  - {suggestion['command']}")
                if suggestion.get("description"):
                    print(f"    {suggestion['description']}")
        print(f"  risk: {result.risk}")
        print()


def print_explain(command_name: str, as_json: bool = False) -> int:
    command = find_command(command_name)
    if command is None:
        if as_json:
            print(json.dumps({"error": "command_not_found", "command": command_name}, indent=2))
        else:
            print(f'No command card found for "{command_name}".')
        return 1

    if as_json:
        print(json.dumps(command, indent=2))
        return 0

    print(command["command"])
    print(f"  summary: {command['summary']}")
    print(f"  default_risk: {command.get('default_risk', 'unknown')}")
    if command.get("effects"):
        print("  effects:")
        for effect in command["effects"]:
            effect_name = effect.get("effect") if isinstance(effect, dict) else effect
            print(f"  - {effect_name}")
    if command.get("intents"):
        print("  intents:")
        for intent in command["intents"]:
            print(f"  - {intent}")
    if command.get("examples"):
        print("  examples:")
        for example in command["examples"]:
            print(f"  - {example['command']}")
            print(f"    {example['explanation']}")
    return 0


def print_graph(as_json: bool = False) -> int:
    graph = build_effect_graph()
    payload = graph.as_dict()
    if as_json:
        print(json.dumps(payload, indent=2))
        return 0

    node_types: dict[str, int] = {}
    for node in graph.nodes.values():
        node_types[node.type] = node_types.get(node.type, 0) + 1

    print(f"schema_version: {payload['schema_version']}")
    print(f"nodes: {len(graph.nodes)}")
    print(f"edges: {len(graph.edges)}")
    for node_type in sorted(node_types):
        print(f"{node_type}_nodes: {node_types[node_type]}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="commandgraph",
        description="Intent-aware command discovery and safety checks.",
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    search_parser = subparsers.add_parser("search", help="Search commands by intent.")
    search_parser.add_argument("query")
    search_parser.add_argument("--limit", type=int, default=5)
    search_parser.add_argument("--json", action="store_true")

    explain_parser = subparsers.add_parser("explain", help="Show a command card.")
    explain_parser.add_argument("command")
    explain_parser.add_argument("--json", action="store_true")

    graph_parser = subparsers.add_parser(
        "graph",
        help="Inspect the typed command/effect graph.",
    )
    graph_parser.add_argument("--json", action="store_true")

    check_parser = subparsers.add_parser("check", help="Review a command for risk.")
    check_parser.add_argument("command")
    check_parser.add_argument("--json", action="store_true")

    review_parser = subparsers.add_parser(
        "review",
        help="Review a command with optional user intent.",
    )
    review_parser.add_argument("--intent")
    review_parser.add_argument("--command", required=True)
    review_parser.add_argument("--json", action="store_true")

    doctor_parser = subparsers.add_parser("doctor", help="Check local CommandGraph data.")
    doctor_parser.add_argument("--json", action="store_true")

    index_parser = subparsers.add_parser(
        "index",
        help="Build a local command index from apropos or man -k output.",
    )
    index_parser.add_argument("--source", choices=["apropos", "man-k"], default="apropos")
    index_parser.add_argument("--query", default=".")
    index_parser.add_argument("--input", help="Read saved apropos/man -k output from a file.")
    index_parser.add_argument("--output", default=str(DEFAULT_INDEX_PATH))
    index_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    if args.command_name == "search":
        print_search(args.query, args.limit, as_json=args.json)
        return 0

    if args.command_name == "explain":
        return print_explain(args.command, as_json=args.json)

    if args.command_name == "graph":
        return print_graph(as_json=args.json)

    if args.command_name == "check":
        review = check_command(args.command)
        if args.json:
            print(json.dumps(review.as_dict(), indent=2))
        else:
            print(f"decision: {review.decision}")
            print(f"risk: {review.risk}")
            for reason in review.reasons:
                print(f"- {reason}")
            if review.safer_next_step:
                print(f"safer_next_step: {review.safer_next_step}")
        return 0

    if args.command_name == "review":
        review = review_command(args.command, intent=args.intent)
        if args.json:
            print(json.dumps(review.as_dict(), indent=2))
        else:
            print(f"decision: {review.decision}")
            print(f"risk: {review.risk}")
            for reason in review.reasons:
                print(f"- {reason}")
            if review.related_commands:
                print(f"related_commands: {', '.join(review.related_commands)}")
            if review.safer_next_step:
                print(f"safer_next_step: {review.safer_next_step}")
        return 0

    if args.command_name == "doctor":
        health = data_health()
        if args.json:
            print(json.dumps(health, indent=2))
        else:
            print(f"commands: {health['command_count']}")
            print(f"risk_rules: {health['risk_rule_count']}")
            print(f"effects: {health['effect_count']}")
            print(f"graph_nodes: {health['graph_node_count']}")
            print(f"graph_edges: {health['graph_edge_count']}")
            print(f"graph_errors: {len(health['graph_errors'])}")
            for error in health["graph_errors"]:
                print(f"- graph: {error}")
            print(f"missing_schema: {len(health['missing_schema'])}")
            print(f"duplicate_commands: {len(health['duplicate_commands'])}")
            print(f"ok: {str(health['ok']).lower()}")
        return 0 if health["ok"] else 1

    if args.command_name == "index":
        output = Path(args.output)
        try:
            if args.input:
                with Path(args.input).open("r", encoding="utf-8") as handle:
                    result = build_index_from_lines(
                        handle.read().splitlines(),
                        path=output,
                        source="file",
                    )
            else:
                result = build_index(path=output, source=args.source, query=args.query)
        except (OSError, RuntimeError, ValueError) as exc:
            payload = {"error": "index_failed", "message": str(exc)}
            if args.json:
                print(json.dumps(payload, indent=2))
            else:
                print(f"index failed: {exc}")
            return 1

        if args.json:
            print(json.dumps(result.as_dict(), indent=2))
        else:
            print(f"indexed: {result.entry_count}")
            print(f"skipped: {result.skipped_count}")
            print(f"path: {result.path}")
        return 0

    return 1
