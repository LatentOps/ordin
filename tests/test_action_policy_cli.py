import io
import json
import sys

from ordin import ActionEnvelope
from ordin.cli import main


def _write_policy(path, *, decision="ask"):
    payload = {
        "schema_version": "ordin.policy_set.v1",
        "policy_id": "cli-policy",
        "version": "1",
        "rules": [
            {
                "id": "shell-review",
                "decision": decision,
                "when": {"kinds": ["shell"]},
                "reason": "shell actions require explicit policy review",
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return payload


def test_policy_validate_reports_identity_digest_and_rule_count(tmp_path, capsys):
    path = tmp_path / "policy.json"
    _write_policy(path)

    assert main(["policy", "validate", str(path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)

    assert result["schema_version"] == "ordin.policy_set.v1"
    assert result["policy_id"] == "cli-policy"
    assert result["version"] == "1"
    assert result["rule_count"] == 1
    assert len(result["digest"]) == 64


def test_action_cli_applies_explicit_policy_file(tmp_path, monkeypatch, capsys):
    path = tmp_path / "policy.json"
    _write_policy(path, decision="ask")
    action = ActionEnvelope.shell("git status --short").as_dict()
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(action)))

    assert main(["action", "--stdin", "--policy", str(path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)

    assert result["decision"] == "ask"
    assert result["policy"]["policy_id"] == "cli-policy"
    assert result["policy_matches"][0]["rule_id"] == "shell-review"


def test_action_cli_policy_respects_enforcement_exit_code(tmp_path, monkeypatch, capsys):
    path = tmp_path / "policy.json"
    _write_policy(path, decision="ask")
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps(ActionEnvelope.shell("git status --short").as_dict())),
    )

    assert main(["action", "--stdin", "--policy", str(path), "--json", "--enforce"]) == 20
    result = json.loads(capsys.readouterr().out)
    assert result["decision"] == "ask"


def test_policy_validate_rejects_unknown_fields(tmp_path, capsys):
    path = tmp_path / "policy.json"
    payload = _write_policy(path)
    payload["unexpected"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert main(["policy", "validate", str(path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "invalid_policy"
    assert "schema validation failed" in result["message"]


def test_action_policy_is_never_loaded_implicitly(tmp_path, monkeypatch, capsys):
    hidden = tmp_path / ".ordin"
    hidden.mkdir()
    _write_policy(hidden / "policy.json", decision="block")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps(ActionEnvelope.shell("git status --short").as_dict())),
    )

    assert main(["action", "--stdin", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["decision"] == "allow"
    assert "policy" not in result
