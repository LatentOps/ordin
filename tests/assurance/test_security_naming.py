"""Public Security commands and migration preserve claim and authority boundaries."""

from dataclasses import replace
import json

import pytest

from ordin.assurance.cli import main as assurance_main
from ordin.entrypoint import main, normalize_argv
from ordin.security import import_native_json
from ordin.security.models import ScannerImportReport

from .test_security_import import bundle


def test_security_is_explicit_and_help_exposes_the_full_command_surface(capsys):
    assert normalize_argv(["security", "import", "--help"]) == ["security", "import", "--help"]
    with pytest.raises(SystemExit) as result:
        main(["security", "--help"])
    assert result.value.code == 0
    help_text = capsys.readouterr().out
    assert "usage: ordin security" in help_text
    for command in (
        "profile",
        "challenge",
        "source",
        "finding",
        "import",
        "import-workflow",
        "mock",
    ):
        assert command in help_text
    assert "codex" not in help_text.lower()
    with pytest.raises(SystemExit):
        main(["--help"])
    assert "security" in capsys.readouterr().out


def test_preferred_commands_preserve_offline_catalog_and_status_codes(capsys, monkeypatch):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: pytest.fail("offline command spawned"))
    assert main(["security", "challenge", "list"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert catalog["execution"] == "bounded_synthetic_only"
    for status in (0, 1, 2, 130, 143):
        assert main(["security", "mock", "--exit-code", str(status)]) == status
        report = json.loads(capsys.readouterr().out)
        assert report["operation"] == "mock"
        assert report["model_or_network_enabled"] is False


def test_preferred_import_redacts_claim_details_and_uses_new_format(tmp_path, capsys):
    scope, _, _, _ = bundle(tmp_path)
    result = main(
        [
            "security",
            "import",
            "--artifact-root",
            str(tmp_path),
            "--repository",
            scope.repository.id,
            "--revision",
            scope.repository.revision,
        ]
    )
    assert result == 0
    packet = json.loads(capsys.readouterr().out)
    assert packet["format"] == "native_json"
    assert packet["finding_confirmation"] == "not_performed"
    assert "metadata_parts" not in packet
    assert "reported_details" not in packet["findings"][0]


def test_previous_assurance_group_remains_hidden_and_equivalent(capsys):
    assert assurance_main(["security", "mock", "--exit-code", "1"]) == 1
    current = json.loads(capsys.readouterr().out)
    assert assurance_main(["codex", "mock", "--exit-code", "1"]) == 1
    assert json.loads(capsys.readouterr().out) == current
    with pytest.raises(SystemExit):
        assurance_main(["--help"])
    assert "codex" not in capsys.readouterr().out.lower()


def test_historical_format_roundtrips_without_rewriting_its_digest(tmp_path):
    scope, _, _, _ = bundle(tmp_path)
    current = import_native_json(scope)
    assert current.format == "native_json"
    historical = replace(current, format="codex_json")
    restored = ScannerImportReport.from_dict(historical.as_dict())
    assert restored.as_dict() == historical.as_dict()
    assert restored.digest == historical.digest
    assert restored.digest != current.digest
    for record in (current, historical):
        with pytest.raises(ValueError, match="scan status/coverage differs"):
            replace(record, scan_status="unknown")


def test_callable_compatibility_preserves_identity():
    from ordin.security import import_codex_json
    from ordin.security.importer import import_codex_json as importer_alias

    assert import_native_json is import_codex_json is importer_alias
