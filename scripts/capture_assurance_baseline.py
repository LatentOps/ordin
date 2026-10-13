"""Freeze public compatibility evidence before implementing Assurance.

Reads tracked source and an explicitly selected built wheel. It does not run
repository scripts, scanners, models, or any reviewed action.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import platform
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ordin import ActionEnvelope, AgentGate, __all__, __version__
from ordin.schema import SCHEMA_FILES


def capture(wheel: Path) -> dict:
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    tracked = subprocess.check_output(
        [
            "git",
            "ls-files",
            "ordin",
            "integrations/openshell",
            "docs",
            "tests",
            ".github/workflows",
        ],
        cwd=ROOT,
        text=True,
    ).splitlines()
    source = {}
    for name in tracked:
        path = ROOT / name
        if path.suffix not in {".py", ".md", ".yml"}:
            continue
        content = path.read_bytes()
        entry = {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
        if path.suffix == ".py":
            tree = ast.parse(content)
            entry["public_classes"] = [
                node.name
                for node in tree.body
                if isinstance(node, ast.ClassDef) and not node.name.startswith("_")
            ]
            entry["public_functions"] = [
                node.name
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and not node.name.startswith("_")
            ]
        source[name] = entry
    cases = [
        ("safe-git", ActionEnvelope.shell("git status --short", action_id="safe-git")),
        (
            "unknown-mcp",
            ActionEnvelope(
                "mcp",
                "call",
                {"server": "fixture", "tool": "unknown", "arguments": {}},
                action_id="unknown-mcp",
            ),
        ),
        ("root-delete", ActionEnvelope.shell("rm -rf /", action_id="root-delete")),
        (
            "file-write",
            ActionEnvelope(
                "file", "write", {"path": "/fixture/docs/note.md"}, action_id="file-write"
            ),
        ),
        (
            "network-upload",
            ActionEnvelope(
                "network",
                "upload",
                {"url": "https://fixture.invalid/upload"},
                action_id="network-upload",
            ),
        ),
    ]
    gate = AgentGate()
    outcomes = []
    for case_id, action in cases:
        decision = gate.evaluate_action(action)
        outcomes.append(
            {
                "case_id": case_id,
                "action": action.as_dict(),
                "disposition": decision.disposition,
                "review": decision.review.as_dict(),
            }
        )
    with zipfile.ZipFile(wheel) as archive:
        wheel_files = {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in sorted(archive.namelist())
        }
        entrypoints = next(name for name in wheel_files if name.endswith("/entry_points.txt"))
        entrypoint_text = archive.read(entrypoints).decode()
    prior_reports = {}
    for name in (
        "docs/reports/agent-safety-corpus-v1/report.json",
        "docs/reports/integration-evaluation.json",
        "docs/reports/runtime-capability-benchmark.json",
    ):
        path = ROOT / name
        if path.exists():
            content = path.read_bytes()
            data = json.loads(content)
            prior_reports[name] = {
                "sha256": hashlib.sha256(content).hexdigest(),
                "revision": data.get("revision", data.get("source_revision")),
                "top_level_fields": sorted(data),
            }
    return {
        "schema_version": "ordin.assurance_baseline_inventory.v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "revision": revision,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "ordin_version": __version__,
        "public_exports": sorted(__all__),
        "schemas": dict(sorted(SCHEMA_FILES.items())),
        "source_inventory": source,
        "fixtures": outcomes,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "wheel_files": wheel_files,
        "entrypoints": entrypoint_text,
        "prior_reports": prior_reports,
        "limitations": [
            "Static symbol inventory is not a reachability proof.",
            "Representative cases are compatibility fixtures, not effectiveness estimates.",
            "Historical report metrics do not establish candidate performance.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = capture(args.wheel)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(
        json.dumps(
            {
                "revision": payload["revision"],
                "sources": len(payload["source_inventory"]),
                "schemas": len(payload["schemas"]),
                "wheel_files": len(payload["wheel_files"]),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
