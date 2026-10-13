"""All documented standalone examples ship and run offline without target execution."""

import importlib
import json

import pytest

from ordin.assurance.examples import EXAMPLES, run_examples


def test_every_standalone_example_runs_without_execution_or_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("offline example attempted process or network execution")

    monkeypatch.setattr("socket.socket", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    report = run_examples(scratch_root=tmp_path)
    assert report["all_passed"] and report["example_count"] == len(EXAMPLES) == 8
    assert {row["module"].rsplit(".", 1)[1] for row in report["examples"]} == set(EXAMPLES)
    assert all(row["result"] == "passed" for row in report["examples"])
    assert not any(
        report[key]
        for key in (
            "actions_executed",
            "target_code_executed",
            "model_or_scanner_called",
            "artifacts_retained",
        )
    )
    assert list(tmp_path.iterdir()) == []
    serialized = json.dumps(report)
    assert str(tmp_path) not in serialized and "/fixture/source" not in serialized
    assert all(
        len(row["source_sha256"]) == len(row["stdout_sha256"]) == 64 for row in report["examples"]
    )


def test_contradicted_example_never_receives_a_passing_audit(tmp_path, monkeypatch):
    module = importlib.import_module("ordin.assurance.examples.attack_path")
    monkeypatch.setattr(
        module,
        "main",
        lambda: print(
            json.dumps({"exposure": "confirmed", "reachability": "observed", "proof_gaps": []})
        ),
    )
    with pytest.raises(ValueError, match="contradicted"):
        run_examples(scratch_root=tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("change", ["extra", "missing"])
def test_example_inventory_cannot_silently_omit_shipped_work(tmp_path, monkeypatch, change):
    import ordin.assurance.examples as examples

    names = {name + ".py" for name in EXAMPLES} | {"__init__.py", "__main__.py"}
    if change == "extra":
        names.add("unreviewed_example.py")
    else:
        names.remove("delegation.py")
    for name in names:
        (tmp_path / name).touch()
    monkeypatch.setattr(examples, "files", lambda _: tmp_path)
    with pytest.raises(ValueError, match="manifest"):
        run_examples(scratch_root=tmp_path)


def test_checkout_entrypoints_retain_packaged_api_identity():
    for name in EXAMPLES:
        checkout = importlib.import_module("examples.assurance." + name)
        packaged = importlib.import_module("ordin.assurance.examples." + name)
        assert checkout.main is packaged.main
        if hasattr(packaged, "fixture"):
            assert checkout.fixture is packaged.fixture
