import json

from ordin.cli import main


def _policy_payload():
    return {
        "schema_version": "ordin.temporal_policy_set.v1",
        "policy_id": "cli-temporal",
        "version": "1",
        "rules": [
            {
                "id": "x-then-y",
                "risk": "high",
                "category": "x_then_y",
                "within_actions": 2,
                "pattern": [
                    {"signals_any": ["signal:x"]},
                    {"signals_any": ["signal:y"]},
                ],
                "reason": "x followed by y",
                "safer_next_step": None,
            }
        ],
    }


def test_temporal_validate_reports_policy_metadata(tmp_path, capsys):
    path = tmp_path / "temporal.json"
    path.write_text(json.dumps(_policy_payload()), encoding="utf-8")

    assert main(["temporal", "validate", str(path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["schema_version"] == "ordin.temporal_policy_set.v1"
    assert payload["policy_id"] == "cli-temporal"
    assert payload["version"] == "1"
    assert payload["rule_count"] == 1


def test_temporal_validate_rejects_unbounded_window(tmp_path, capsys):
    path = tmp_path / "temporal.json"
    payload = _policy_payload()
    payload["rules"][0]["within_actions"] = 33
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert main(["temporal", "validate", str(path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "invalid_temporal_policy"
