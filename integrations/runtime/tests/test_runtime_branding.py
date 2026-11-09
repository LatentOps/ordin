"""New owned names keep pinned upstream identity and legacy wire data exact."""

import hashlib
import json
from pathlib import Path

import pytest

from ordin_runtime import OrdinRuntimeBackend, compile_runtime_policy
from ordin_runtime import cli
from ordin_runtime.observations import parse_runtime_event


ROOT = Path(__file__).resolve().parents[3]
INTEGRATION = ROOT / "integrations/runtime"


def test_distribution_exports_and_resources_use_owned_runtime_names():
    assert OrdinRuntimeBackend.__module__ == "ordin_runtime.compiler"
    assert compile_runtime_policy.__module__ == "ordin_runtime.compiler"
    project = (INTEGRATION / "pyproject.toml").read_text(encoding="utf-8")
    assert (
        'name = "ordin-runtime"' in project
        and 'ordin-runtime = "ordin_runtime.cli:main"' in project
    )
    assert not (ROOT / "integrations/openshell").exists()
    assert not (ROOT / "ordin/swarm/openshell_backend.py").exists()


@pytest.mark.parametrize("arguments", [["--help"], ["doctor", "--help"], ["apply", "--help"]])
def test_public_help_has_only_current_owned_names(arguments, capsys):
    with pytest.raises(SystemExit) as stopped:
        cli.main(arguments)
    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    assert "ordin-runtime" in help_text and "openshell" not in help_text.lower()
    if len(arguments) > 1:
        assert "--runtime-executable" in help_text


@pytest.mark.parametrize("option", ["--runtime-executable", "--openshell"])
def test_hidden_legacy_executable_selector_preserves_explicit_target(option, monkeypatch, capsys):
    seen = []

    def doctor(**parameters):
        seen.append(parameters["cli_executable"])
        return {"status": "success"}

    monkeypatch.setattr(cli, "runtime_doctor", doctor)
    assert cli.main(["doctor", option, "operator-selected-engine"]) == 0
    assert seen == ["operator-selected-engine"]
    assert json.loads(capsys.readouterr().out)["status"] == "success"


def test_upstream_patch_and_manifest_bytes_are_not_reauthored():
    patch = INTEGRATION / "runtime/patches/request-authority-v1.patch"
    identity_file = INTEGRATION / "ordin_runtime/runtime_identity.json"
    identity = json.loads(identity_file.read_text(encoding="utf-8"))
    assert (
        hashlib.sha256(patch.read_bytes()).hexdigest()
        == "8f93705e6bbb8a0460b39cd3c8e11003cc2a81b6beb97229d5c9f4300525d98a"
    )
    assert identity["patch_sha256"] == hashlib.sha256(patch.read_bytes()).hexdigest()
    assert identity["upstream_revision"] == "6648bd0c290efbc41ba131ee9831ee45cd431f94"
    assert (
        identity["source_digest"]
        == "f70ee4a421d3f31c91792e3f6bf4b192544ef5a57b0ea9e776e7017e83cb5673"
    )


def test_upstream_event_vendor_is_accepted_without_rebranding_its_wire_data():
    event = json.loads((INTEGRATION / "tests/fixtures/runtime-events/http-denied.json").read_text())
    assert event["metadata"]["product"]["vendor_name"] == "OpenShell"
    assert parse_runtime_event(event).sandbox_id
