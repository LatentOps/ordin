"""The unavailable CrewAI boundary cannot be enabled by installed metadata or config."""

import builtins
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integrations/swarm"))
from ordin_swarm.adapters import CrewAIAdapter
from ordin_swarm.adapters import contracts
from ordin_swarm.cli import MANIFEST, installation, main, setup, uninstall
from ordin_swarm.demo import run, _crewai
from ordin._runtime_json import digest
from ordin.schema import validate_named_schema


def test_quarantine_precedes_sdk_import_even_when_installed_version_matches(tmp_path, monkeypatch):
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.split(".")[0] in {"crewai", "crewai_core", "chromadb"}:
            pytest.fail("blocked SDK was imported")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    monkeypatch.setattr(contracts, "version", lambda name: contracts.PINS["crewai"][name])
    uninitialized = object.__new__(CrewAIAdapter)
    for operation in (
        lambda: contracts.require_version("crewai"),
        lambda: CrewAIAdapter(None, None, operator=object()),
        lambda: uninitialized.install(None, None, []),
        lambda: uninitialized._before(None),
        lambda: uninitialized.close(),
        lambda: setup("crewai", directory=tmp_path),
        lambda: setup("crewai", directory=tmp_path, dry_run=False),
        lambda: run("crewai"),
        lambda: _crewai(tmp_path),
    ):
        with pytest.raises(ValueError, match="security_blocked"):
            operation()
    assert list(tmp_path.iterdir()) == []
    assert uninitialized.status()["availability"] == "security_blocked"


def test_status_and_doctor_report_no_coverage_or_compatibility_for_quarantined_sdk(
    monkeypatch, capsys
):
    monkeypatch.setattr(contracts, "version", lambda name: contracts.PINS["crewai"][name])
    report = contracts.coverage("crewai", installed=True, connected=True)
    assert report["availability"] == "security_blocked"
    assert not any(report[name] for name in ("compatible", "installed", "connected", "covered"))
    assert not validate_named_schema("swarm_framework_adapter", report)
    for name, value in (
        ("compatible", True),
        ("installed", True),
        ("connected", True),
        ("covered", ["tools"]),
    ):
        assert validate_named_schema("swarm_framework_adapter", {**report, name: value})
    assert main(["doctor", "--framework", "crewai"]) == 1
    diagnosis = json.loads(capsys.readouterr().out)
    assert not diagnosis["environment_compatible"]
    assert "security_blocked_unpatched_chromadb" in diagnosis["diagnostics"]


def test_existing_managed_manifest_can_still_be_removed_during_quarantine(tmp_path):
    payload = installation("crewai")
    (tmp_path / MANIFEST).write_text(json.dumps(payload))
    result = uninstall("crewai", directory=tmp_path, expected_digest=digest(payload))
    assert result["removed"] and not (tmp_path / MANIFEST).exists()
