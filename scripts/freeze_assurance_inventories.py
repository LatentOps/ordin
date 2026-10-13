"""Freeze synthetic M2 inventory/threat-model evidence; never run fixture source."""

import argparse
import hashlib
import json
from pathlib import Path

from ordin.assurance import (
    AuthorizedRepository,
    RepositoryScope,
    build_threat_model,
    inventory_repository,
    render_threat_model,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/assurance/fixtures/repositories"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    reports = {}
    for name in ("documentation", "payment", "mcp", "monorepo"):
        scope = AuthorizedRepository(
            (FIXTURES / name).resolve(),
            RepositoryScope("fixture/" + name, "fixture-v1"),
            "/fixture/" + name,
        )
        inventory = inventory_repository(scope)
        model = build_threat_model(scope, inventory)
        content = json.dumps(model.as_dict(), indent=2, sort_keys=True) + "\n"
        (args.output / (name + ".json")).write_text(content, encoding="utf-8")
        (args.output / (name + ".md")).write_text(
            render_threat_model(model, include_source_paths=True), encoding="utf-8"
        )
        reports[name] = {
            "snapshot_digest": inventory.snapshot_digest,
            "files": len(inventory.files),
            "facts": len(inventory.facts),
            "routes": len(model.routes),
            "completeness": inventory.completeness,
            "model_digest": model.digest,
        }
    manifest = {
        "schema_version": "ordin.assurance_inventory_fixture_manifest.v1",
        "fixture_source_sha256": {
            p.relative_to(FIXTURES).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(FIXTURES.rglob("*"))
            if p.is_file()
        },
        "reports": reports,
        "limitations": [
            "Synthetic fixture syntax only; no actual reachability or host enforcement claim.",
            "Runtime root-identity digests are environment specific.",
        ],
    }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(reports))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
