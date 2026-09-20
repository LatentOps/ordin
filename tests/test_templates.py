import pytest

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


@pytest.mark.parametrize("port", ["1", "7", "9", "10", "3000", "65535"])
def test_extracts_all_valid_port_widths(port):
    assert extract_slots(f"what is using port {port}")["port"] == port


@pytest.mark.parametrize("port", ["0", "65536", "999999"])
def test_out_of_range_ports_do_not_produce_a_port_slot(port):
    assert "port" not in extract_slots(f"what is using port {port}")


@pytest.mark.parametrize("pattern", ["*.log", "report*", "?config", "config?", "*", "?", "a*.txt"])
def test_preserves_complete_filename_globs(pattern):
    assert extract_slots(f"find files matching {pattern} in ./src")["pattern"] == pattern


def test_quoted_pattern_is_not_replaced_by_a_partial_glob():
    query = 'find files matching "error a*.log archived" in ./src'
    assert extract_slots(query)["pattern"] == "error a*.log archived"


def test_does_not_treat_a_url_query_as_a_filename_glob():
    assert "pattern" not in extract_slots("check endpoint https://example.com/health?verbose=true")


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
