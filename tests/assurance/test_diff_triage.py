"""Finite snapshot triage with policy authority checks and explicit gaps."""

from dataclasses import replace
import json

import pytest

from ordin import Ordin
from ordin.assurance import AuthorizedRepository, RepositoryScope, HostCapabilityAuthority
from ordin.assurance.diff_triage import DiffTriageReport, triage_source_diff
from ordin.assurance.models import SecurityProfile, ProtectedAsset
from ordin.assurance.simulation import SimulationPolicy
from ordin.assurance.cli import main
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import NetworkCapability


def snapshots(tmp_path, before_files, after_files):
    roots = []
    for name, files in (("before", before_files), ("after", after_files)):
        root = tmp_path / name
        root.mkdir()
        for path, content in files.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        roots.append(
            AuthorizedRepository(root.resolve(), RepositoryScope("fixture/repo", name), "/fixture")
        )
    return roots


def test_doc_only_changes_have_finite_scope_and_no_execution(tmp_path, monkeypatch):
    first, second = snapshots(tmp_path, {"README.md": "Before"}, {"README.md": "After"})
    monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: pytest.fail("source diff spawned"))
    result = triage_source_diff(first, second)
    assert not result.review_required and result.completeness == "complete"
    assert result.changes[0].categories == ("documentation_only",)
    assert DiffTriageReport.from_dict(result.as_dict()) == result
    assert result.advisory_only and result.limitations


@pytest.mark.parametrize(
    "path,content,category",
    [
        ("src/app.py", "import subprocess\nsubprocess.run(['fixture'])", "new_subprocess_sink"),
        (
            "src/app.py",
            "import urllib.request\nurllib.request.urlopen('https://fixture.invalid')",
            "new_network_sink",
        ),
        ("src/tools.py", "@server.tool()\ndef fixture():\n    pass", "new_tool_surface"),
        ("schemas/mcp.json", "{}", "mcp_schema_modified"),
        ("requirements.txt", "synthetic==1", "dependency_modified"),
        ("uv.lock", "version = 1", "dependency_modified"),
        ("host/boundary.py", "authority = None", "host_boundary_modified"),
        ("src/policy.py", "allow = True", "enforcement_modified"),
    ],
)
def test_changed_security_surfaces_are_candidates(tmp_path, path, content, category):
    first, second = snapshots(tmp_path, {}, {path: content})
    result = triage_source_diff(first, second)
    assert result.review_required and category in result.changes[0].categories
    public = json.dumps(result.public_dict())
    assert path not in public and content not in public
    assert "fixture.invalid" not in public


def test_modified_protected_deploy_and_profile_only_change(tmp_path):
    first, second = snapshots(tmp_path, {"deploy/prod.yaml": "old"}, {"deploy/prod.yaml": "new"})
    old = SecurityProfile(
        "fixture",
        "1",
        first.repository,
        (ProtectedAsset("prod", "path", "/fixture/deploy", "prefix"),),
    )
    new = replace(old, repository=second.repository)
    result = triage_source_diff(first, second, baseline_profile=old, candidate_profile=new)
    assert "protected_surface" in result.changes[0].categories and result.profile_changed
    result = triage_source_diff(
        first, first, baseline_profile=old, candidate_profile=replace(old, version="2")
    )
    assert result.changes == () and result.profile_changed and result.review_required


def test_existing_sink_moved_lines_is_not_claimed_new(tmp_path):
    first, second = snapshots(
        tmp_path,
        {"src/app.py": "import subprocess\nsubprocess.run(['x'])"},
        {"src/app.py": "# header\nimport subprocess\nsubprocess.run(['x'])"},
    )
    result = triage_source_diff(first, second)
    assert "new_subprocess_sink" not in result.changes[0].categories


def test_network_permission_widening_uses_existing_validator(tmp_path):
    first, second = snapshots(tmp_path, {}, {})
    boundary = RuntimeCapabilityBoundary(
        "fixture",
        network=(NetworkCapability("fixture.invalid", 443, "tcp", "write"),),
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )
    old = SimulationPolicy(capability_authorities=(HostCapabilityAuthority("network", boundary),))
    new = SimulationPolicy(
        capability_authorities=(
            HostCapabilityAuthority(
                "network",
                replace(
                    boundary,
                    network=(
                        *boundary.network,
                        NetworkCapability("other.invalid", 443, "tcp", "write"),
                    ),
                ),
            ),
        )
    )
    result = triage_source_diff(first, second, baseline_policy=old, candidate_policy=new)
    assert result.policy_authority_delta == "widened" and result.review_required
    assert result.baseline_policy_digest == old.digest


def test_unknown_policy_algebra_and_source_gaps_remain_partial(tmp_path):
    first, second = snapshots(tmp_path, {"src/app.py": "pass"}, {"src/app.py": "syntax !!!"})
    result = triage_source_diff(first, second)
    assert result.completeness == "partial" and result.review_required and result.gaps
    with pytest.raises(ValueError):
        triage_source_diff(first, second, baseline_policy=SimulationPolicy())
    with pytest.raises(ValueError):
        triage_source_diff(first, replace(second, repository=RepositoryScope("wrong", "after")))


def test_unknown_network_scope_remains_unsupported(tmp_path):
    first, second = snapshots(tmp_path, {}, {})
    old = SimulationPolicy()
    authority = HostCapabilityAuthority(
        "fixture", RuntimeCapabilityBoundary("unknown", network=(NetworkCapability(None, None),))
    )
    # Same authority identity with unknown rights; no sampled match can prove it.
    a = replace(old, capability_authorities=(authority,))
    b = replace(
        old,
        capability_authorities=(
            replace(
                authority,
                boundary=replace(
                    authority.boundary,
                    network=(*authority.boundary.network, NetworkCapability("other.invalid", 443)),
                ),
            ),
        ),
    )
    result = triage_source_diff(first, second, baseline_policy=a, candidate_policy=b)
    assert result.policy_authority_delta == "unsupported" and result.completeness == "partial"


def test_policy_only_change_requires_review_without_source_edits(tmp_path):
    first, second = snapshots(tmp_path, {}, {})
    result = triage_source_diff(
        first,
        second,
        baseline_policy=SimulationPolicy(require_profile=True),
        candidate_policy=SimulationPolicy(),
    )
    assert (
        result.changes == ()
        and result.policy_authority_delta == "widened"
        and result.review_required
    )


def test_optional_ci_example_passes_project_workflow_guard():
    from pathlib import Path
    from scripts.check_workflow_security import workflow_errors

    workflow = (
        Path(__file__).resolve().parents[2]
        / "integrations/codex_security/examples/private-diff-scan.yml"
    )
    assert workflow_errors(workflow) == []
    text = workflow.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text and "pull_request:" not in text
    assert "github.event.repository.private" in text
    assert "approve_source_upload" in text and "retention-days: 3" in text
    assert "continue-on-error" not in text and "ordin-assure codex import" in text


def test_cli_diff_and_mock_are_offline_with_distinct_exit_codes(tmp_path, capsys, monkeypatch):
    first, second = snapshots(tmp_path, {}, {"README.md": "after"})
    monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: pytest.fail("offline CLI spawned"))
    args = [
        "source",
        "diff",
        "--baseline-root",
        str(first.root),
        "--candidate-root",
        str(second.root),
        "--repository",
        "fixture/repo",
        "--baseline-revision",
        "before",
        "--candidate-revision",
        "after",
        "--virtual-root",
        "/fixture",
    ]
    assert main(args) == 0
    assert not json.loads(capsys.readouterr().out)["review_required"]
    for code in (0, 1, 2, 130, 143):
        assert main(["codex", "mock", "--exit-code", str(code)]) == code
        packet = json.loads(capsys.readouterr().out)
        assert packet["operation"] == "mock" and not packet["model_or_network_enabled"]
