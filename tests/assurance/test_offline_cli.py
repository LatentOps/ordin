"""CLI diagnostics never turn supplied profiles, graph labels or grants into authority."""

import io
import json
from dataclasses import replace

import pytest

from ordin import ActionEnvelope
from ordin.assurance import InvariantSelectors, SecurityInvariant, PolicySimulationReport
from ordin.assurance.cli import main
from ordin.assurance.delegation import DelegationAuthority
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability

from .test_profiles import config_profile
from .test_validation import fixture
from .test_models import examples
from .test_assurance_cli import arguments


def write(path, payload):
    path.write_bytes(json.dumps(payload).encode())
    return str(path)


def test_profile_inspection_and_preview_are_data_only(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("preview executed"))
    profile = config_profile(
        SecurityInvariant(
            "no-egress", "forbid_effect", InvariantSelectors(effects=("network.connect",))
        )
    )
    path = write(tmp_path / "profile.json", profile.as_dict())
    assert main(["profile", "inspect", path, "--json"]) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["approved"] is False and inspected["activation_authorized"] is False
    action = write(
        tmp_path / "action.json", ActionEnvelope.shell("curl https://outside.invalid").as_dict()
    )
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert main(["invariants", "check", "--profile", path, "--action", action, "--json"]) == 1
    preview = json.loads(capsys.readouterr().out)
    assert (
        preview["mode"] == "unapproved_content_preview"
        and preview["activation_authorized"] is False
    )
    assert preview["evaluations"][0]["status"] == "violated"
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_host_dependent_and_unknown_effect_previews_remain_inconclusive(tmp_path, capsys):
    profile = config_profile(
        SecurityInvariant("approval", "require_approval", InvariantSelectors())
    )
    p = write(tmp_path / "profile.json", profile.as_dict())
    a = write(tmp_path / "action.json", ActionEnvelope.shell("git status --short").as_dict())
    assert main(["invariants", "check", "--profile", p, "--action", a]) == 2
    packet = json.loads(capsys.readouterr().out)
    assert (
        packet["baseline_disposition"] == "execute"
        and packet["evaluations"][0]["status"] == "inconclusive"
    )


def test_delegation_needs_all_declared_maxima_and_does_not_issue(tmp_path, capsys):
    parent = DelegationAuthority(
        RuntimeCapabilityBoundary("parent", filesystem=(FilesystemCapability("read", "/fixture"),))
    )
    child = replace(parent, capability=replace(parent.capability, boundary_id="child"))
    p = write(tmp_path / "parent.json", parent.as_dict())
    c = write(tmp_path / "child.json", child.as_dict())
    args = ["delegation", "verify", "--parent", p, "--child", c]
    assert main(args) == 2
    assert json.loads(capsys.readouterr().out)["result"] == "inconclusive"
    assert main(args + ["--operator", p, "--task", p]) == 0
    result = json.loads(capsys.readouterr().out)
    assert (
        result["result"] == "within_boundary"
        and not result["grant_issued"]
        and not result["lifecycle_checked"]
    )
    wider = replace(
        child,
        capability=replace(
            child.capability, filesystem=(FilesystemCapability("write", "/fixture"),)
        ),
    )
    write(tmp_path / "child.json", wider.as_dict())
    assert main(args + ["--operator", p, "--task", p]) == 1


def test_imported_graph_cannot_restore_reported_strong_labels(tmp_path, capsys):
    graph = examples()[5].as_dict()
    graph["exposure"] = "established"
    path = write(tmp_path / "graph.json", graph)
    assert main(["attack-path", "analyze", "--evidence", path, "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["reported_exposure"] == "established" and report["origin"] == "imported_claim"
    assert (
        not report["runtime_evidence_authenticated"]
        and report["finding_confirmation"] == "not_performed"
    )


def test_static_finding_review_checks_source_without_runtime_closure(tmp_path, capsys):
    scope, _, candidate, review, *_ = fixture(tmp_path)
    bundle = write(
        tmp_path / "candidate.json",
        {"candidate": candidate.as_dict(), "rubric": review.rubric.as_dict()},
    )
    args = [
        "finding",
        "validate",
        "--input",
        bundle,
        "--mode",
        "static",
        "--source-root",
        str(scope.root),
        "--repository",
        scope.repository.id,
        "--revision",
        scope.repository.revision,
    ]
    assert main(args) == 2
    packet = json.loads(capsys.readouterr().out)
    assert packet["review"]["status"] == "reviewed" and packet["result"] == "inconclusive"
    assert not packet["runtime_reproduction"] and packet["closure"] == "not_performed"


def test_catalog_json_stdin_and_explicit_output_alias(tmp_path, capsys, monkeypatch):
    assert main(["challenge", "list", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["properties"]) == 10
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(config_profile().as_dict())))
    assert main(["profile", "validate", "-", "--json"]) == 0
    capsys.readouterr()
    profile = write(tmp_path / "profile.json", config_profile().as_dict())
    output = tmp_path / "new-report.json"
    assert main(["profile", "inspect", profile, "--output", str(output)]) == 0
    assert json.loads(output.read_text())["approved"] is False
    capsys.readouterr()
    assert main(["profile", "inspect", profile, "--output", str(output)]) == 2


def test_report_compare_is_existing_corpus_bound_comparison(tmp_path, capsys):
    args = arguments(tmp_path)
    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    path = write(tmp_path / "simulation.json", first)
    assert main(["report", "compare", "--before", path, "--after", path, "--json"]) == 0
    packet = json.loads(capsys.readouterr().out)
    assert not packet["changes"]


def test_invalid_stdin_has_coarse_diagnostic_without_secret_echo(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO('{"bad":"sk-synthetic-private-stdin", "bad":1}'))
    assert main(["profile", "validate", "-"]) == 2
    assert "sk-synthetic" not in capsys.readouterr().err


def test_unmodeled_invariant_effect_is_not_reported_satisfied(tmp_path, capsys):
    profile = config_profile(
        SecurityInvariant(
            "unknown-effect", "forbid_effect", InvariantSelectors(effects=("unmodeled.effect",))
        )
    )
    p = write(tmp_path / "profile.json", profile.as_dict())
    a = write(tmp_path / "action.json", ActionEnvelope.shell("git status").as_dict())
    assert main(["invariants", "check", "--profile", p, "--action", a]) == 2
    assert json.loads(capsys.readouterr().out)["evaluations"][0]["status"] == "unsupported"
