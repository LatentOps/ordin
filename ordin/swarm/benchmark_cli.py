"""Explicit offline corpus and unchanged-threshold overhead report generation."""

import argparse
import json
import os
from pathlib import Path
import sys

from ordin.schema import validate_named_schema

from .benchmark import DEFAULT_CORPUS, evaluate
from .overhead_benchmark import measure


def render_markdown(report):
    lines = ["# Swarm safety v1 evaluation", "", f"Exact revision: `{report['revision']}`.", ""]
    if "manifest_sha256" in report:
        lines.extend(
            [
                f"Manifest SHA-256: `{report['manifest_sha256']}`.",
                f"Deterministic judgments SHA-256: `{report['result_sha256']}`.",
                "",
                "| Metric | Count |",
                "| --- | --- |",
            ]
        )
        lines.extend(
            "| " + name + " | " + str(value) + " |" for name, value in report["metrics"].items()
        )
        lines.extend(
            ["", "| Case | Lane | Expected | Actual | Matched |", "| --- | --- | --- | --- | --- |"]
        )
        lines.extend(
            "| "
            + value["id"]
            + " | "
            + value["lane"]
            + " | "
            + value["expected"]
            + " | "
            + value["actual"]
            + " | "
            + str(value["matched"])
            + " |"
            for value in report["results"]
        )
    else:
        lines.extend(
            [
                "| Actors | Core p99 ms | Swarm p99 ms | Owned callback p99 ms |",
                "| --- | --- | --- | --- |",
            ]
        )
        lines.extend(
            "| "
            + str(value["agents"])
            + " | "
            + str(value["core_review_ms"]["p99"])
            + " | "
            + str(value["swarm_review_ms"]["p99"])
            + " | "
            + str(value["owned_callback_forward_ms"]["p99"])
            + " |"
            for value in report["operation_shapes"]
        )
        lines.extend(
            [
                "",
                "Retained session bounded: " + str(report["long_session"]["bounded"]) + ".",
                "",
                "Thresholds: " + json.dumps(report["thresholds"], sort_keys=True) + ".",
            ]
        )
    lines.extend(
        ["", "Result: " + ("passed" if report["ok"] else "failed") + ".", "", "## Limitations", ""]
    )
    lines.extend("- " + value for value in report["limitations"])
    return "\n".join(lines) + "\n"


def _write(path, value):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ordin-swarm-benchmark")
    parser.add_argument("mode", choices=("corpus", "overhead"))
    parser.add_argument("--revision", required=True)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--kernel", action="store_true")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--samples", type=int, default=32)
    parser.add_argument("--long-actions", type=int, default=256)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--markdown", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.kernel and arguments.mode != "corpus":
            raise ValueError("kernel facts belong to the separate corpus lane")
        report = (
            evaluate(
                arguments.corpus,
                revision=arguments.revision,
                include_kernel=arguments.kernel,
                seed=arguments.seed,
            )
            if arguments.mode == "corpus"
            else measure(
                revision=arguments.revision,
                samples=arguments.samples,
                long_actions=arguments.long_actions,
            )
        )
        schema = "swarm_corpus_report" if arguments.mode == "corpus" else "swarm_overhead_report"
        if validate_named_schema(schema, report):
            raise ValueError("evaluation report does not satisfy its published schema")
        raw = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
        if arguments.output:
            _write(arguments.output, raw)
        if arguments.markdown:
            _write(arguments.markdown, render_markdown(report))
        if not arguments.output:
            print(raw, end="")
        return 0 if report["ok"] else 1
    except (ValueError, OSError) as error:
        print("Swarm evaluation refused: " + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
