import json
import os
from dataclasses import replace

import pytest

from ordin import (
    ActionEnvelope,
    Ordin,
    RuntimeCapabilityBoundary,
    RuntimeCapabilityContract,
    RuntimeObservation,
    RuntimeEvidenceSource,
    derive_runtime_capability_contract,
)
from ordin.entrypoint import main
from ordin.runtime_codec import action_review_from_dict


def write_json(path, payload, *, private=False):
    path.write_text(json.dumps(payload))
    if private:
        path.chmod(0o600)
    return str(path)


def test_review_codec_round_trip_preserves_original_review_and_does_not_reclassify():
    review = Ordin().review_action(ActionEnvelope.shell("git status --short", action_id="cli-1"))
    decoded = action_review_from_dict(json.loads(json.dumps(review.as_dict())))
    assert decoded.as_dict() == review.as_dict()
    assert derive_runtime_capability_contract(decoded) == derive_runtime_capability_contract(review)
    payload = review.as_dict()
    payload["unknown_review_field"] = "secret-value"
    with pytest.raises(ValueError, match="invalid"):
        action_review_from_dict(payload)
    payload = review.as_dict()
    payload["provenance"]["final_decision"] = "block"
    with pytest.raises(ValueError, match="mismatch"):
        action_review_from_dict(payload)


def test_capability_derive_and_validate_do_not_execute_or_access_network(
    tmp_path, capsys, monkeypatch
):
    import socket
    import subprocess

    review = Ordin().review_action(ActionEnvelope.shell("cat /repo/README.md", action_id="cli-2"))
    path = write_json(tmp_path / "review.json", review.as_dict())

    def forbidden(*args, **kwargs):
        raise AssertionError("core runtime CLI executed or contacted a runtime")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    assert main(["capability", "derive", "--review", path, "--json"]) == 0
    contract = json.loads(capsys.readouterr().out)
    assert contract == derive_runtime_capability_contract(review).as_dict()
    contract_path = write_json(tmp_path / "contract.json", contract)
    assert main(["capability", "validate", contract_path, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "success"


def test_capability_verify_only_within_boundary_succeeds(tmp_path, capsys):
    from test_capability_delta import read_review

    review = read_review()
    contract = derive_runtime_capability_contract(review)
    boundary = RuntimeCapabilityBoundary(
        "read-only",
        filesystem=contract.filesystem,
        process=contract.process,
        privilege=contract.privilege,
    )
    contract_path = write_json(tmp_path / "contract.json", contract.as_dict())
    boundary_path = write_json(tmp_path / "boundary.json", boundary.as_dict())
    assert main(["capability", "verify", contract_path, "--boundary", boundary_path, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["result"] == "within_boundary"
    write_json(tmp_path / "boundary.json", replace(boundary, filesystem=()).as_dict())
    assert main(["capability", "verify", contract_path, "--boundary", boundary_path, "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["result"] == "exceeds_boundary"


def test_ordinary_observation_json_cannot_bless_strong_runtime_labels(tmp_path, capsys):
    observation = RuntimeObservation("caller-event", "action-1")
    path = write_json(tmp_path / "observation.json", observation.as_dict())
    assert main(["runtime-observation", "validate", path, "--json"]) == 0
    capsys.readouterr()
    review = Ordin().review_action(ActionEnvelope.shell("git status", action_id="action-1"))
    contract = derive_runtime_capability_contract(review)
    source = RuntimeEvidenceSource("openshell", "a" * 64, "named-sandbox", "b" * 64)
    event = source.observe(
        contract,
        observation_id="runtime-event",
        trust="backend_enforced",
        enforcement_point="network",
        outcome="denied",
        operation="network.connect",
    )
    write_json(tmp_path / "observation.json", event.as_dict(), private=True)
    assert main(["runtime-observation", "validate", path, "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_runtime_input"
    source_path = write_json(tmp_path / "source.json", source.as_dict(), private=True)
    assert (
        main(["runtime-observation", "validate", path, "--trusted-source", source_path, "--json"])
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "success"


def test_world_readable_or_symlink_trusted_source_is_rejected_on_posix(tmp_path, capsys):
    if os.name != "posix":
        pytest.skip("owner-only mode checks are POSIX-specific")
    source = RuntimeEvidenceSource("openshell", "a" * 64, "sandbox", "b" * 64)
    source_path = write_json(tmp_path / "source.json", source.as_dict())
    observation = RuntimeObservation("caller", "action")
    path = write_json(tmp_path / "event.json", observation.as_dict(), private=True)
    assert main(["runtime-observation", "validate", path, "--trusted-source", source_path]) == 2
    assert json.loads(capsys.readouterr().out)["reason_code"] == "runtime_input_invalid"


def test_invalid_duplicate_oversized_inputs_do_not_echo_private_values(tmp_path, capsys):
    secret = "NEVER_ECHO_RUNTIME_INPUT_SECRET"
    path = tmp_path / "bad.json"
    for content in ('{"bad":"' + secret + '","bad":"again"}', "[]", "x" * 1_048_577):
        path.write_text(content)
        assert main(["capability", "validate", str(path), "--json"]) == 2
        output = capsys.readouterr().out
        assert secret not in output and json.loads(output)["error"] == "invalid_runtime_input"


def test_additive_root_exports_and_help_are_discoverable(capsys):
    import ordin

    assert ordin.RuntimeCapabilityContract is RuntimeCapabilityContract
    assert callable(ordin.propose_capability_delta)
    with pytest.raises(SystemExit) as result:
        main(["--help"])
    assert result.value.code == 0
    help_text = capsys.readouterr().out
    assert "capability" in help_text and "runtime-observation" in help_text
