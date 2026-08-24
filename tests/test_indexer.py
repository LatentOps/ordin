import json
import tempfile
from pathlib import Path

from ordin.indexer import build_index_from_lines, parse_apropos_line, parse_apropos_lines
from ordin.data import load_man_index
from ordin.search import search


def test_parse_apropos_line_creates_command_cards():
    entries = parse_apropos_line("rsync (1) - a fast, versatile file copying tool")

    assert entries == [
        {
            "schema_version": "ordin.command_card.v1",
            "command": "rsync",
            "summary": "a fast, versatile file copying tool",
            "aliases": [],
            "intents": ["a fast, versatile file copying tool"],
            "default_risk": "unknown",
            "risk_tags": ["man_page"],
            "examples": [],
            "templates": [],
            "source": "man_index",
            "man_section": "1",
        }
    ]


def test_parse_apropos_lines_skips_non_command_sections():
    lines = [
        "printf (1) - format and print data",
        "printf (3) - formatted output conversion",
        "not an apropos line",
    ]

    entries, skipped = parse_apropos_lines(lines)

    assert [entry["command"] for entry in entries] == ["printf"]
    assert skipped == 2


def test_build_index_and_search_merge(monkeypatch):
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
        index_path = Path(temp_dir) / "man_index.json"
        result = build_index_from_lines(
            ["rsync (1) - remote file copy and synchronization tool"],
            path=index_path,
        )
        monkeypatch.setenv("ORDIN_INDEX", str(index_path))

        results = search("remote synchronization copy", limit=3)

    assert result.entry_count == 1
    assert results[0].command == "rsync"


def test_cli_index_from_input(capsys):
    from ordin.cli import main

    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
        input_path = Path(temp_dir) / "apropos.txt"
        output_path = Path(temp_dir) / "man_index.json"
        input_path.write_text("htop (1) - interactive process viewer\n", encoding="utf-8")

        exit_code = main(
            [
                "index",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--json",
            ]
        )
        captured = capsys.readouterr()
        payload = json.loads(captured.out)

        assert exit_code == 0
        assert payload["entry_count"] == 1
        assert output_path.exists()


def test_corrupt_man_index_is_ignored():
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
        index_path = Path(temp_dir) / "man_index.json"
        index_path.write_text("{not valid json", encoding="utf-8")

        assert load_man_index(index_path) == []
