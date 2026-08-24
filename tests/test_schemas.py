from ordin.context import ExecutionContext, ReviewRequest
from ordin.data import DATA_DIR, data_health, load_json
from ordin.graph import build_effect_graph
from ordin.review import review_command
from ordin.risk import check_command
from ordin.schema import (
    SCHEMA_FILES,
    resource_parity_errors,
    validate_instance,
    validate_named_schema,
    validate_risk_rule_semantics,
    validate_schema_files,
    validate_template_semantics,
)
from ordin.search import search


def test_checked_in_schema_files_are_well_formed():
    assert len(SCHEMA_FILES) >= 8
    assert validate_schema_files() == []


def test_public_runtime_payloads_satisfy_published_schemas():
    search_result = search("make file runnable", limit=1)[0].as_dict()
    assert validate_named_schema("search_result", search_result) == []

    risk_result = check_command("git status --short").as_dict()
    assert validate_named_schema("risk_review", risk_result) == []

    request = ReviewRequest(
        command="git status --short",
        context=ExecutionContext(cwd="/repo", euid=1000),
    ).as_dict()
    assert validate_named_schema("review_request", request) == []

    review_result = review_command(
        "git status --short",
        context=ExecutionContext(cwd="/repo", euid=1000),
    ).as_dict()
    assert validate_named_schema("review_result", review_result) == []

    graph_result = build_effect_graph().as_dict()
    assert validate_named_schema("effect_graph", graph_result) == []


def test_bundled_risk_rules_and_effect_catalog_satisfy_schemas():
    risk_payload = load_json(DATA_DIR / "risk_rules.json")
    effect_payload = load_json(DATA_DIR / "effects.json")
    assert validate_named_schema("risk_rules", risk_payload) == []
    assert validate_named_schema("effect_catalog", effect_payload) == []


def test_validator_reports_missing_required_property():
    errors = validate_instance(
        {"schema_version": "ordin.command_card.v1"},
        {
            "type": "object",
            "required": ["schema_version", "command"],
            "properties": {
                "schema_version": {"type": "string"},
                "command": {"type": "string"},
            },
        },
    )
    assert any("missing required property 'command'" in error for error in errors)


def test_risk_semantics_detect_invalid_regex_and_duplicate_ids():
    payload = {
        "rules": [
            {"id": "bad", "pattern": "[", "risk": "high"},
            {"id": "bad", "pattern": "ok", "risk": "unsafe"},
        ]
    }
    errors = validate_risk_rule_semantics(payload)
    assert any("invalid regex" in error for error in errors)
    assert any("duplicate id" in error for error in errors)
    assert any("invalid risk" in error for error in errors)


def test_template_semantics_detect_unknown_slots_and_broken_defaults():
    errors = validate_template_semantics(
        [
            {
                "command": "demo",
                "templates": [
                    {
                        "command": "demo {mystery}",
                        "description": "demo",
                        "safe_defaults": {"path": "."},
                    }
                ],
            }
        ]
    )
    assert any("unknown template fields mystery" in error for error in errors)
    assert any("safe_defaults reference path" in error for error in errors)


def test_source_and_packaged_resources_are_identical():
    assert resource_parity_errors() == []


def test_doctor_health_includes_all_validation_layers():
    health = data_health()
    assert health["schema_count"] >= 8
    assert health["schema_errors"] == []
    assert health["risk_rule_errors"] == []
    assert health["template_errors"] == []
    assert health["resource_parity_errors"] == []
    assert health["graph_errors"] == []
    assert health["ok"] is True
