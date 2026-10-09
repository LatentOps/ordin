import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from ordin.assurance._files import ScopedFileError, _directory, directory_entries, read_scoped_file
from ordin.assurance.inventory import (
    AuthorizedRepository,
    build_threat_model,
    inventory_repository,
    render_threat_model,
    verify_source_reference,
)
from ordin.assurance.inventory_models import (
    InventoryLimits,
    RepositoryInventory,
    RepositoryThreatModel,
)
from ordin.assurance.models import ApprovedSecurityProfile, RepositoryScope

FIXTURES = Path(__file__).parent / "fixtures/repositories"


def scope(root, name="fixture", **kwargs):
    return AuthorizedRepository(
        root.resolve(),
        RepositoryScope("fixture/" + name, "snapshot-1"),
        kwargs.pop("virtual_root", "/fixture/" + name),
        **kwargs,
    )


@pytest.mark.parametrize("name", ["documentation", "payment", "mcp", "monorepo"])
def test_frozen_repositories_have_verified_source_references_and_only_draft_authority(name):
    authorized = scope(FIXTURES / name, name)
    inventory = inventory_repository(authorized)
    assert inventory.files
    assert all(verify_source_reference(authorized, fact.source) for fact in inventory.facts)
    assert RepositoryInventory.from_json(json.dumps(inventory.as_dict())) == inventory
    model = build_threat_model(authorized, inventory)
    assert not model.draft.authoritative
    assert all(route.status == "hypothesis" and route.proof_gaps for route in model.routes)
    assert RepositoryThreatModel.from_json(json.dumps(model.as_dict())) == model
    with pytest.raises(ValueError, match="cannot activate"):
        ApprovedSecurityProfile.from_dict(model.draft.as_dict())


def test_threat_model_identifies_actual_entry_control_transform_and_sinks_without_importing_code():
    authorized = scope(FIXTURES / "payment", "payment")
    inventory = inventory_repository(authorized)
    categories = {fact.category for fact in inventory.facts}
    assert {
        "handler.declaration",
        "serialization.parse",
        "subprocess.execute",
        "network.egress",
        "authorization.control_candidate",
        "approval.workflow",
    } <= categories
    model = build_threat_model(authorized, inventory)
    assert model.counterevidence_refs
    assert any(f.category == "module.load_stop_candidate" for f in inventory.facts)
    assert any(
        route.entrypoint_ref and route.control_refs and route.transformation_refs
        for route in model.routes
    )
    assert model.draft.invariant_suggestions
    assert "repository.instructions_untrusted" in categories
    markdown = render_threat_model(model, include_source_paths=True)
    assert "payments.py:" in markdown
    assert "Unknown" in markdown or "unknown" in markdown
    assert "Ignore the security gate" not in markdown
    assert "Disable approval requirements" not in json.dumps(model.as_dict())


def test_harmless_docs_do_not_invent_sinks_invariants_or_deployment_policy():
    authorized = scope(FIXTURES / "documentation", "documentation")
    model = build_threat_model(authorized, inventory_repository(authorized))
    assert model.routes == ()
    assert model.draft.invariant_suggestions == ()
    assert model.draft.completeness == "unknown"
    assert model.open_questions


def test_mcp_forged_annotations_do_not_change_trust_and_test_prod_files_are_not_merged():
    authorized = scope(FIXTURES / "mcp", "mcp")
    model = build_threat_model(authorized, inventory_repository(authorized))
    assert any(route.actor == "malicious_dependency_or_mcp_server" for route in model.routes)
    assert not model.draft.authoritative
    assert "approved_policy" not in json.dumps(model.as_dict())
    mono = scope(FIXTURES / "monorepo", "monorepo")
    model = build_threat_model(mono, inventory_repository(mono))
    facts = {fact.fact_id: fact for fact in model.inventory.facts}
    for route in model.routes:
        if route.entrypoint_ref:
            assert facts[route.sink_ref].source.path == facts[route.entrypoint_ref].source.path


def test_sensitive_files_are_not_read_and_reports_redact_asset_and_source_paths(
    tmp_path, monkeypatch
):
    (tmp_path / ".env").write_text("TOKEN=fixture-secret-do-not-retain")
    (tmp_path / "main.py").write_text("def main():\n    pass\n")
    import ordin.assurance.inventory as module

    original = module.read_scoped_file
    reads = []

    def record(*args, **kwargs):
        reads.append(args[1])
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "read_scoped_file", record)
    authorized = scope(tmp_path)
    inventory = inventory_repository(authorized)
    assert ".env" not in reads
    assert inventory.completeness == "partial"
    assert "sensitive_source_excluded" in {issue.code for issue in inventory.issues}
    assert inventory.assets[0].value.endswith("/.env")
    model = build_threat_model(authorized, inventory)
    report = render_threat_model(model)
    assert "main.py" not in report and "/fixture/fixture/.env" not in report
    assert "fixture-secret-do-not-retain" not in report + json.dumps(model.as_dict())


def test_changed_or_forged_inventory_is_not_promoted_to_source_backed_model(tmp_path):
    path = tmp_path / "main.py"
    path.write_text("def main():\n    pass\n")
    authorized = scope(tmp_path)
    inventory = inventory_repository(authorized)
    fact = inventory.facts[0]
    assert not verify_source_reference(authorized, replace(fact.source, symbol="forged_symbol"))
    forged = replace(inventory, facts=(replace(fact, category="forged.authorization"),))
    with pytest.raises(ScopedFileError, match="stale_or_forged"):
        build_threat_model(authorized, forged)
    path.write_text("def main():\n    return 1\n")
    assert not verify_source_reference(authorized, fact.source)
    with pytest.raises(ScopedFileError, match="stale_or_forged"):
        build_threat_model(authorized, inventory)
    pinned = replace(authorized, expected_snapshot_digest=inventory.snapshot_digest)
    with pytest.raises(ScopedFileError, match="snapshot_mismatch"):
        inventory_repository(pinned)


def test_scope_root_revision_and_virtual_mapping_are_explicit(tmp_path):
    with pytest.raises(ValueError):
        AuthorizedRepository(Path("relative"), RepositoryScope("fixture", "snapshot"), "/fixture")
    with pytest.raises(ValueError):
        scope(tmp_path, virtual_root="/fixture//alias")
    with pytest.raises(ValueError):
        inventory_repository({"root": str(tmp_path)})
    with pytest.raises(ScopedFileError):
        read_scoped_file(tmp_path, "../outside")
    with pytest.raises(ScopedFileError):
        read_scoped_file(tmp_path, "https://fixture.invalid")


def test_limits_and_parser_failures_leave_explicit_partial_coverage(tmp_path):
    for index in range(3):
        (tmp_path / f"file{index}.py").write_text("def main():\n    pass\n")
    report = inventory_repository(scope(tmp_path), limits=InventoryLimits(max_files=1))
    assert len(report.files) == 1
    assert report.completeness == "partial"
    assert "source_file_count_limit" in {issue.code for issue in report.issues}
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "main.py").write_text("not valid python !!!")
    report = inventory_repository(scope(tmp_path))
    assert "source_parse_incomplete" in {issue.code for issue in report.issues}
    report = inventory_repository(scope(tmp_path), limits=InventoryLimits(max_depth=0))
    assert "source_depth_limit" in {issue.code for issue in report.issues}
    (tmp_path / "nested_expression.py").write_text("x=" + "[" * 100 + "0" + "]" * 100)
    assert "source_parser_limit" in {
        issue.code for issue in inventory_repository(scope(tmp_path)).issues
    }


def test_symlinks_and_hardlinks_do_not_read_outside_root(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("raise RuntimeError('must not read external fixture')")
    os.link(outside, repo / "hardlink.py")
    inventory = inventory_repository(scope(repo))
    assert inventory.files == ()
    assert "source_hardlink_excluded" in {issue.code for issue in inventory.issues}
    with pytest.raises(ScopedFileError, match="hardlink"):
        read_scoped_file(repo.resolve(), "hardlink.py")
    try:
        (repo / "symlink.py").symlink_to(outside)
    except OSError:
        pytest.skip("Windows account cannot create symlinks; POSIX CI must exercise this boundary")
    with pytest.raises(ScopedFileError):
        read_scoped_file(repo.resolve(), "symlink.py")
    inventory = inventory_repository(scope(repo))
    assert "source_link_excluded" in {issue.code for issue in inventory.issues}


def test_oversize_file_and_directory_fail_with_controlled_errors(tmp_path):
    (tmp_path / "large.py").write_bytes(b"x" * 1_048_577)
    with pytest.raises(ScopedFileError, match="file_limit"):
        read_scoped_file(tmp_path.resolve(), "large.py")
    with pytest.raises(ScopedFileError, match="directory_limit"):
        directory_entries(FIXTURES / "payment", maximum=1)
    assert "source_file_limit" in {
        issue.code for issue in inventory_repository(scope(tmp_path)).issues
    }


def test_directory_link_cannot_escape_authorized_root(tmp_path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (outside / "private.py").write_text("outside fixture sentinel")
    try:
        (repo / "linked").symlink_to(outside.resolve(), target_is_directory=True)
    except OSError:
        pytest.skip(
            "Account cannot create directory symlinks; POSIX CI must exercise this boundary"
        )
    with pytest.raises(ScopedFileError):
        read_scoped_file(repo.resolve(), "linked/private.py")
    report = inventory_repository(scope(repo))
    assert report.files == ()
    assert "source_link_excluded" in {issue.code for issue in report.issues}


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-sharing semantics")
def test_windows_directory_handles_pin_path_during_scoped_access(tmp_path):
    repo = tmp_path / "repo"
    target = tmp_path / "moved"
    repo.mkdir()
    assert repo.resolve().is_relative_to(tmp_path.resolve())
    assert target.resolve().is_relative_to(tmp_path.resolve())
    with _directory(repo.resolve()):
        with pytest.raises(OSError):
            repo.rename(target)
    # The handle must also release its rename restriction after the read ends.
    repo.rename(target)
    target.rename(repo)
    assert repo.is_dir()
