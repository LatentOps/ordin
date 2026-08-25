from ordin.slots import extract_slots
from ordin.templates import render_template, suggest_commands


def test_extracts_common_slots():
    slots = extract_slots('find files named "*.py" in ./src on port 3000')
    assert slots["port"] == "3000"
    assert slots["pattern"] == "*.py"
    assert slots["path"] == "./src"


def test_extracts_url_slot():
    slots = extract_slots("check endpoint https://example.com/health")
    assert slots["url"] == "https://example.com/health"
    assert slots["host"] == "example.com"


def test_renders_template_when_slots_exist():
    command = render_template("lsof -i :{port}", {"port": "3000"})
    assert command == "lsof -i :3000"


def test_does_not_render_when_slot_missing():
    command = render_template("curl -I {url}", {})
    assert command is None


def test_slot_extraction_does_not_invent_path_or_depth():
    slots = extract_slots("make file runnable")
    assert "path" not in slots
    assert "depth" not in slots


def test_mutating_template_requires_explicit_target():
    entry = {
        "templates": [
            {
                "command": "chmod +x {path}",
                "description": "Make a file executable.",
            }
        ]
    }
    assert suggest_commands(entry, "make file runnable") == []


def test_safe_template_defaults_are_opt_in():
    entry = {
        "templates": [
            {
                "command": "find {path} -maxdepth {depth}",
                "description": "Inspect the current directory.",
                "safe_defaults": {"path": ".", "depth": "1"},
            }
        ]
    }
    suggestions = suggest_commands(entry, "find files")
    assert suggestions[0]["command"] == "find . -maxdepth 1"
