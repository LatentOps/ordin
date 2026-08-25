import json

from ordin.cli import main


def test_explain_known_command_json(capsys):
    exit_code = main(["explain", "chmod", "--json"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert '"schema_version": "ordin.command_card.v1"' in captured.out
    assert '"command": "chmod"' in captured.out


def test_graph_exports_versioned_json(capsys):
    exit_code = main(["graph", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["schema_version"] == "ordin.effect_graph.v1"
    assert payload["nodes"]
    assert payload["edges"]


def test_graph_human_output_reports_shape(capsys):
    exit_code = main(["graph"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "schema_version: ordin.effect_graph.v1" in captured.out
    assert "effect_nodes:" in captured.out


def test_doctor_passes(capsys):
    exit_code = main(["doctor"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "effects:" in captured.out
    assert "graph_errors: 0" in captured.out
    assert "ok: true" in captured.out


def test_doctor_has_seed_command_coverage():
    from ordin.data import data_health

    health = data_health()
    assert health["command_count"] >= 30
    assert health["effect_count"] >= 20
    assert health["graph_errors"] == []
