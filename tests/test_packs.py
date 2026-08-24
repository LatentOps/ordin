import json

from commandgraph.analyzers import analyze_tokens, analyzer_pack_bindings
from commandgraph.cli import main
from commandgraph.data import data_health, find_command, load_risk_rules
from commandgraph.packs import (
    discover_packs,
    enabled_packs,
    pack_list_payload,
)
from commandgraph.risk import check_command
from commandgraph.schema import resource_parity_errors, validate_named_schema
from commandgraph.search import search
from commandgraph.shell import shell_tokens


def _rule_ids() -> set[str]:
    return {rule["id"] for rule in load_risk_rules()}


def test_default_packs_are_discovered_loaded_and_schema_valid():
    packs = discover_packs()
    assert {pack.name for pack in packs} >= {"git", "docker"}
    assert {pack.name for pack in enabled_packs()} >= {"git", "docker"}

    payload = pack_list_payload()
    assert payload["schema_version"] == "commandgraph.pack_list.v1"
    assert validate_named_schema("pack_list", payload) == []
    by_name = {pack["name"]: pack for pack in payload["packs"]}
    assert by_name["git"]["loaded"] is True
    assert by_name["docker"]["loaded"] is True


def test_default_packs_supply_command_cards_rules_and_analyzers():
    assert find_command("git") is not None
    assert find_command("docker") is not None
    assert {"force_push", "docker_prune", "docker_rm_force"} <= _rule_ids()

    bindings = analyzer_pack_bindings()
    assert bindings["git"] == "git"
    assert bindings["docker"] == "docker"
    assert analyze_tokens(shell_tokens("git status --short")) is not None
    assert analyze_tokens(shell_tokens("docker ps")) is not None


def test_disabling_all_packs_removes_domain_behavior(monkeypatch):
    monkeypatch.setenv("COMMANDGRAPH_PACKS", "")

    assert enabled_packs() == []
    assert find_command("git") is None
    assert find_command("docker") is None
    assert "force_push" not in _rule_ids()
    assert "docker_prune" not in _rule_ids()
    assert "docker_rm_force" not in _rule_ids()
    assert analyze_tokens(shell_tokens("git status --short")) is None
    assert analyze_tokens(shell_tokens("docker ps")) is None

    git_review = check_command("git status --short")
    assert git_review.decision == "ask"
    assert git_review.risk == "unknown"

    results = search("inspect git history", limit=10)
    assert "git" not in {result.command for result in results}


def test_selective_pack_loading_is_exact(monkeypatch):
    monkeypatch.setenv("COMMANDGRAPH_PACKS", "git")
    assert [pack.name for pack in enabled_packs()] == ["git"]
    assert find_command("git") is not None
    assert find_command("docker") is None
    assert "force_push" in _rule_ids()
    assert "docker_prune" not in _rule_ids()
    assert analyze_tokens(shell_tokens("git status")) is not None
    assert analyze_tokens(shell_tokens("docker ps")) is None

    payload = pack_list_payload()
    by_name = {pack["name"]: pack for pack in payload["packs"]}
    assert by_name["git"]["loaded"] is True
    assert by_name["docker"]["loaded"] is False


def test_wildcard_loads_all_discovered_packs(monkeypatch):
    monkeypatch.setenv("COMMANDGRAPH_PACKS", "*")
    assert {pack.name for pack in enabled_packs()} == {
        pack.name for pack in discover_packs()
    }


def test_unknown_configured_pack_is_reported_by_doctor(monkeypatch):
    monkeypatch.setenv("COMMANDGRAPH_PACKS", "git,does-not-exist")
    health = data_health()
    assert health["ok"] is False
    assert any("does-not-exist" in error for error in health["pack_errors"])


def test_pack_files_match_packaged_resources():
    assert resource_parity_errors() == []


def test_packs_cli_reports_loaded_state(capsys):
    assert main(["packs", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "commandgraph.pack_list.v1"
    assert {pack["name"] for pack in payload["packs"]} >= {"git", "docker"}


def test_doctor_reports_pack_health():
    health = data_health()
    assert health["pack_count"] >= 2
    assert health["loaded_pack_count"] >= 2
    assert {"git", "docker"} <= set(health["loaded_packs"])
    assert health["pack_errors"] == []
    assert health["risk_rule_count"] == health["known_risk_rule_count"]
    assert health["command_count"] == health["known_command_count"]
    assert health["ok"] is True
