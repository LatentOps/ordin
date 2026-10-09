"""Offline SDK example: inspect authorized source, draft, select and compile.

The protection source is a synthetic host fixture, not an installed sandbox.
No repository code, reviewed command, scan, model or grant is executed.
"""

import argparse
import hashlib
import json
from pathlib import Path

from ordin.assurance import (
    AuthorizedRepository,
    ProtectedProfileSelection,
    RepositoryScope,
    build_threat_model,
    compile_approved_profile,
    inventory_repository,
    load_approved_profile,
    propose_profile,
    render_threat_model,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_observation import RuntimeEvidenceSource


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--virtual-root", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-source-paths", action="store_true")
    args = parser.parse_args()
    root = args.repository_root.resolve(strict=True)
    output = args.output.resolve()
    if output.is_relative_to(root):
        raise ValueError("example output must be outside the inspected source root")
    scope = AuthorizedRepository(
        root, RepositoryScope(args.repository_id, args.revision), args.virtual_root
    )
    inventory = inventory_repository(scope)
    model = build_threat_model(scope, inventory)
    profile = propose_profile(model.draft, profile_id="synthetic-example", version="1")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    path = output / "profile.json"
    path.write_text(json.dumps(profile.as_dict(), indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    host_policy = "a" * 64
    source = RuntimeEvidenceSource(
        "synthetic-host-fixture", "b" * 64, "fixture-sandbox", host_policy
    )
    boundary = RuntimeCapabilityBoundary(
        "synthetic-agent",
        filesystem=(FilesystemCapability("write", scope.virtual_root, "prefix"),),
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )
    selection = ProtectedProfileSelection(
        output,
        "profile.json",
        "/fixture/operator/profile.json",
        scope.repository,
        profile.digest,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        "1",
        "synthetic-operator",
        boundary,
        source,
    )
    approved = load_approved_profile(
        selection, current_repository=scope.repository, active_runtime_policy_digest=host_policy
    )
    compiled = compile_approved_profile(approved)
    (output / "draft.json").write_text(
        json.dumps(model.as_dict(), indent=2) + "\n", encoding="utf-8"
    )
    (output / "threat-model.md").write_text(
        render_threat_model(model, include_source_paths=args.include_source_paths), encoding="utf-8"
    )
    (output / "compilation.json").write_text(
        json.dumps(compiled.as_dict(), indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "files": len(inventory.files),
                "facts": len(inventory.facts),
                "draft_authoritative": model.draft.authoritative,
                "compiled_restrictions": len(compiled.action_policy.active_rules),
                "snapshot_digest": inventory.snapshot_digest,
                "protection": "synthetic_host_fixture_only",
                "executes_actions": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
