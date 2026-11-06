"""The installed fixture must distinguish real kernel evidence and host bypass."""

from pathlib import Path
import json

from ordin.schema import validate_named_schema


def test_owned_demo_refuses_an_unsupported_host_without_a_callback_fallback(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "integrations/swarm"))
    import ordin_swarm.owned_demo as demo

    monkeypatch.setattr(demo.platform, "machine", lambda: "unsupported-fixture-architecture")
    report = demo.run()
    assert report["status"] == "unsupported" and report["physical_enforcement"] is False
    assert not validate_named_schema("swarm_owned_demo", report)


def test_owned_demo_verifies_exact_child_and_retains_host_bypass(monkeypatch):
    from tests.test_swarm_broker import require_kernel

    require_kernel()
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "integrations/swarm"))
    from ordin_swarm.owned_demo import run

    report = run()
    assert report["status"] == "completed" and report["physical_enforcement"] is True
    assert report["raw_host_bypass"] == "uncovered_success"
    assert not report["whole_host_enforced"] and not report["coordinator_exercised"]
    assert report["mediated_out_of_scope_request"] == "denied_before_worker"
    assert report["stale_epoch_authorization"] == report["authorization_replay"] == "refused"
    assert not validate_named_schema("swarm_owned_demo", report)
    assert str(Path.home()) not in json.dumps(report)
