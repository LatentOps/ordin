"""Offline CLI exit codes, explicit output, redaction and malformed input."""

import json
from pathlib import Path

import pytest

from ordin import ActionEnvelope, Ordin, ReviewPolicy
from ordin.assurance.cli import main
from ordin.assurance.simulation import (
    FrozenCase,
    FrozenCorpus,
    SimulationPolicy,
    simulate_policy_change,
)

from .test_profiles import config_profile


def write(path, packet):
    path.write_text(json.dumps(packet), encoding="utf-8")
    return str(path)


def arguments(tmp_path, candidate=None, corpus=None):
    baseline = SimulationPolicy()
    corpus = corpus or FrozenCorpus.synthetic(
        (
            FrozenCase(
                "safe",
                ActionEnvelope.shell("git status --short"),
                expected="execute",
                label="benign",
            ),
        )
    )
    args = [
        "policy",
        "simulate",
        "--baseline",
        write(tmp_path / "old.json", baseline.as_dict()),
        "--candidate",
        write(tmp_path / "new.json", (candidate or baseline).as_dict()),
        "--corpus",
        write(tmp_path / "corpus.json", corpus.as_dict()),
        "--baseline-revision",
        "fixture-v1",
        "--candidate-revision",
        "fixture-v2",
    ]
    return args


def test_cli_valid_and_read_only_by_default(tmp_path, capsys):
    args = arguments(tmp_path)
    before = {v.name: v.read_bytes() for v in tmp_path.iterdir()}
    assert main(args) == 0
    packet = json.loads(capsys.readouterr().out)
    assert packet["activation_safe"] and packet["coverage"] == "complete"
    assert {v.name: v.read_bytes() for v in tmp_path.iterdir()} == before


def test_cli_security_regression_returns_one(tmp_path, capsys):
    corpus = FrozenCorpus.synthetic(
        (
            FrozenCase(
                "unknown",
                ActionEnvelope(
                    "mcp", "call", {"server": "fixture", "tool": "unknown", "arguments": {}}
                ),
                expected="escalate",
                critical=True,
                label="adversarial",
            ),
        )
    )
    assert (
        main(arguments(tmp_path, SimulationPolicy(Ordin(policy=ReviewPolicy("block"))), corpus))
        == 1
    )
    packet = json.loads(capsys.readouterr().out)
    assert packet["newly_executable"] == ["unknown"] and not packet["activation_safe"]


def test_cli_partial_missing_revision_and_unknown_label(tmp_path, capsys):
    args = arguments(tmp_path)
    assert main(args[:-4]) == 2
    assert not json.loads(capsys.readouterr().out)["activation_safe"]
    corpus = FrozenCorpus((FrozenCase("unknown", ActionEnvelope.shell("git status")),))
    assert main(arguments(tmp_path, corpus=corpus)) == 2
    assert json.loads(capsys.readouterr().out)["coverage"] == "partial"


def test_explicit_output_refuses_overwrite_and_never_alters_policy(tmp_path, capsys):
    args = arguments(tmp_path)
    report = tmp_path / "report.json"
    assert main(args + ["--report", str(report)]) == 0
    output = capsys.readouterr().out
    assert json.loads(report.read_text()) == json.loads(output)
    before = report.read_bytes()
    assert main(args + ["--report", str(report)]) == 2
    capsys.readouterr()
    assert report.read_bytes() == before
    source = tmp_path / "new.json"
    before = source.read_bytes()
    assert main(args + ["--report", str(source)]) == 2
    capsys.readouterr()
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    "content", ['{"schema_version":NaN}', '{"core":{},"core":{}}', '{"schema_version":"unknown"}']
)
def test_malformed_input_uses_safe_error_without_source_echo(tmp_path, capsys, content):
    args = arguments(tmp_path)
    (tmp_path / "new.json").write_text(content + " PRIVATE_FIXTURE_SECRET", encoding="utf-8")
    assert main(args) == 2
    captured = capsys.readouterr()
    assert "PRIVATE_FIXTURE_SECRET" not in captured.err + captured.out
    assert json.loads(captured.err)["coverage"] == "unknown"


def test_profile_validate_does_not_approve(tmp_path, capsys):
    assert (
        main(["profile", "validate", write(tmp_path / "profile.json", config_profile().as_dict())])
        == 0
    )
    assert json.loads(capsys.readouterr().out)["approved"] is False


def test_default_report_contains_no_fixture_parameters_or_source_command(tmp_path, capsys):
    secret = "PRIVATE_FIXTURE_SECRET_DO_NOT_PUBLISH"
    corpus = FrozenCorpus.synthetic(
        (
            FrozenCase(
                "private",
                ActionEnvelope(
                    "mcp",
                    "call",
                    {"server": "fixture", "tool": "unknown", "arguments": {"token": secret}},
                ),
                label="adversarial",
                expected="escalate",
            ),
        )
    )
    assert main(arguments(tmp_path, corpus=corpus)) == 2
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
    assert "arguments" not in captured.out


def test_diff_requires_same_corpus_and_rejects_partial_reports(tmp_path, capsys):
    corpus = FrozenCorpus.synthetic(
        (
            FrozenCase(
                "safe",
                ActionEnvelope.shell("git status --short"),
                expected="execute",
                label="benign",
            ),
        )
    )
    policy = SimulationPolicy()
    report = simulate_policy_change(
        policy, policy, corpus, baseline_revision="fixture-v1", candidate_revision="fixture-v1"
    )
    baseline = write(tmp_path / "a.json", report.as_dict())
    candidate = write(tmp_path / "b.json", report.as_dict())
    assert main(["policy", "diff", "--baseline", baseline, "--candidate", candidate]) == 0
    assert json.loads(capsys.readouterr().out)["changes"] == []
    payload = report.as_dict()
    payload["corpus_digest"] = "f" * 64
    write(Path(candidate), payload)
    assert main(["policy", "diff", "--baseline", baseline, "--candidate", candidate]) == 2
    capsys.readouterr()
