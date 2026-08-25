import json

from ordin.cli import main


def test_check_cli_uses_context_flags_for_root_resolution(capsys):
    exit_code = main(["check", "rm -rf .", "--cwd", "/", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["decision"] == "block"
    assert payload["risk"] == "critical"


def test_review_cli_accepts_context_json_and_serializes_it(capsys):
    exit_code = main(
        [
            "review",
            "--command",
            "git status",
            "--context-json",
            '{"cwd":"/repo","euid":1000,"agent":"cli-test"}',
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["context"]["cwd"] == "/repo"
    assert payload["context"]["agent"] == "cli-test"


def test_explicit_context_flags_override_context_json(capsys):
    exit_code = main(
        [
            "review",
            "--command",
            "git status",
            "--context-json",
            '{"cwd":"/tmp","interactive":true}',
            "--cwd",
            "/repo",
            "--non-interactive",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["context"]["cwd"] == "/repo"
    assert payload["context"]["interactive"] is False


def test_invalid_context_json_fails_cleanly(capsys):
    exit_code = main(
        [
            "check",
            "git status",
            "--context-json",
            "not-json",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["error"] == "invalid_context"
