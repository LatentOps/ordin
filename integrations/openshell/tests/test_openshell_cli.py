import json
from pathlib import Path

import pytest

from ordin import ActionEnvelope, Ordin
from ordin._runtime_json import digest
from ordin.runtime_codec import read_runtime_json
from ordin_openshell import cli as module
from ordin_openshell.cli import main
from ordin_openshell.apply_audit import PolicyApplyAudit
from ordin_openshell.backend_cli import OpenShellCLI
from ordin_openshell.correlation import CorrelationStore
from ordin_openshell.doctor import openshell_doctor
from test_apply import FakeCLI, setup_plan, boundary_for
from test_observations import event_fixture, register_event, source_context


def write(path, payload, *, private=False):
    path.write_text(json.dumps(payload))
    if private:
        path.chmod(0o600)
    return str(path)


def test_compile_contract_output_validate_and_missing_prover_are_data_only(tmp_path, capsys):
    backend, plan = setup_plan()
    path = write(tmp_path / "contract.json", plan.contract.as_dict())
    policy = str(tmp_path / "policy.json")
    assert (
        main(
            [
                "compile-contract",
                "--contract",
                path,
                "--uid",
                "1000",
                "--gid",
                "1000",
                "--output",
                policy,
            ]
        )
        == 0
    )
    compiled = json.loads(capsys.readouterr().out)
    assert compiled["plan"]["policy_digest"] == plan.policy_digest
    assert json.loads(Path(policy).read_text()) == plan.as_dict()["policy"]
    assert main(["validate", "--policy", policy]) == 0
    assert json.loads(capsys.readouterr().out)["policy_digest"] == plan.policy_digest
    assert (
        main(
            [
                "prove",
                "--policy",
                policy,
                "--boundary",
                policy,
                "--prover",
                "definitely-missing-ordin-test-prover",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["reason_code"] == "openshell_prover_missing"


def test_compile_review_retains_unknowns_and_existing_block_decision(tmp_path, capsys):
    for command in ("curl https://example.com", "rm -rf /"):
        review = Ordin().review_action(ActionEnvelope.shell(command, action_id="review-input"))
        path = write(tmp_path / "review.json", review.as_dict())
        assert main(["compile", "--review", path, "--uid", "1000", "--gid", "1000"]) == 2
        packet = json.loads(capsys.readouterr().out)
        assert packet["status"] == "unsupported" and packet["plan"] is None
        if review.decision == "block":
            assert "decision.block" in packet["unsupported_fields"]


def test_approved_apply_cli_shows_policy_digest_and_requires_exact_operator_approval(
    tmp_path, capsys, monkeypatch
):
    backend, plan = setup_plan("ask")
    fake = FakeCLI(plan)
    monkeypatch.setattr(module, "OpenShellCLI", lambda *args: fake)
    contract = write(tmp_path / "contract.json", plan.contract.as_dict())
    policy = write(tmp_path / "policy.json", plan.as_dict()["policy"])
    audit_path = str(tmp_path / "apply.jsonl")
    arguments = [
        "apply",
        "--contract",
        contract,
        "--policy",
        policy,
        "--sandbox",
        "demo",
        "--uid",
        "1000",
        "--gid",
        "1000",
        "--audit",
        audit_path,
    ]
    assert main(arguments) == 2
    preparation = json.loads(capsys.readouterr().out)
    assert preparation["status"] == "requires_approval"
    assert preparation["preparation"]["policy_digest"] == plan.policy_digest
    assert fake.set_calls == 0
    assert main(arguments + ["--approve-request", preparation["preparation"]["request_id"]]) == 0
    packet = json.loads(capsys.readouterr().out)
    assert packet["status"] == "applied" and packet["active_policy_digest"] == plan.policy_digest
    assert fake.set_calls == 1
    assert PolicyApplyAudit(audit_path).verify()["events"] == 2


def test_apply_cli_refuses_policy_not_bound_to_supplied_contract_before_backend_calls(
    tmp_path, capsys, monkeypatch
):
    backend, plan = setup_plan()
    fake = FakeCLI(plan)
    monkeypatch.setattr(module, "OpenShellCLI", lambda *args: fake)
    contract = write(tmp_path / "contract.json", plan.contract.as_dict())
    policy = plan.as_dict()["policy"]
    next(iter(policy["network_policies"].values()))["endpoints"][0]["rules"][0]["allow"][
        "method"
    ] = "DELETE"
    policy_path = write(tmp_path / "policy.json", policy)
    assert (
        main(
            [
                "apply",
                "--contract",
                contract,
                "--policy",
                policy_path,
                "--sandbox",
                "demo",
                "--uid",
                "1000",
                "--gid",
                "1000",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["status"] == "unsupported"
    assert fake.calls == []


def test_ingest_cli_uses_private_correlation_and_never_guesses_action_identity(tmp_path, capsys):
    backend, plan = setup_plan()
    event, source = event_fixture(), source_context()
    event_path = write(tmp_path / "event.json", event)
    assert main(["ingest-event", "--event", event_path]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "uncorrelated"
    contract = write(tmp_path / "contract.json", plan.contract.as_dict())
    source_path = write(tmp_path / "source.json", source.as_dict(), private=True)
    store = CorrelationStore(tmp_path / "correlation.db")
    register_event(store, event, plan.contract, source)
    arguments = [
        "ingest-event",
        "--event",
        event_path,
        "--contract",
        contract,
        "--source-context",
        source_path,
        "--correlation-db",
        str(store.path),
        "--now-ms",
        "2000",
    ]
    assert main(arguments) == 0
    assert (
        json.loads(capsys.readouterr().out)["observation"]["action_digest"]
        == plan.contract.action_digest
    )
    assert main(arguments) == 2
    assert json.loads(capsys.readouterr().out)["reason_code"] == "runtime_observation_duplicate"


def test_shadow_cli_preserves_report_privacy_without_loading_or_applying_runtime_state(
    tmp_path, capsys
):
    backend, plan = setup_plan()
    cases = {
        "cases": [
            {
                "contract": plan.contract.as_dict(),
                "boundary": boundary_for(plan.contract).as_dict(),
                "observations": [],
                "source": source_context().as_dict(),
                "operator": {
                    "uid": 1000,
                    "gid": 1000,
                    "resource_kinds": {},
                    "credential_providers": {},
                },
            }
        ]
    }
    path = write(tmp_path / "cases.json", cases, private=True)
    assert main(["shadow-report", "--cases", path]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["metrics"]["contracts_fully_representable"] == 1
    assert "api.github.com" not in output and "/usr" not in output


def test_doctor_reports_missing_installation_without_touching_a_sandbox(capsys):
    assert (
        main(
            [
                "doctor",
                "--openshell",
                "missing-ordin-test-cli",
                "--prover",
                "missing-ordin-test-prover",
            ]
        )
        == 2
    )
    output = json.loads(capsys.readouterr().out)
    assert not output["sandbox_mutated"]
    assert not output["checks"]["cli"]["available"]
    assert output["compatibility"]["policy_schema_version"] == 1
    assert output["checks"]["yaml"]["required"] is False


def test_doctor_only_probes_versions_and_schema_not_runtime_mutation(monkeypatch):
    import subprocess
    import ordin_openshell.doctor as doctor
    from ordin_openshell.prover import OpenShellProverResult, MODELED_DOMAINS

    calls = []
    monkeypatch.setattr(doctor.shutil, "which", lambda executable: "/trusted/" + executable)

    def run(arguments, *, stdout, **kwargs):
        assert arguments[1:] == ["--version"] and kwargs["stdin"] == subprocess.DEVNULL
        calls.append(arguments)
        stdout.write((Path(arguments[0]).name + " 0.1.2\n").encode())
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(doctor.subprocess, "run", run)
    monkeypatch.setattr(
        doctor,
        "verify_with_openshell_prover",
        lambda *a, **k: OpenShellProverResult(
            "within_boundary", "fixture", {"domains": sorted(MODELED_DOMAINS)}
        ),
    )
    result = openshell_doctor()
    assert result["status"] == "success" and not result["sandbox_mutated"]
    assert len(calls) == 2 and result["checks"]["compiler_schema"]["prover_checked"]


def test_invalid_operator_metadata_is_rejected_without_echoing_secret(tmp_path, capsys):
    backend, plan = setup_plan()
    contract = write(tmp_path / "contract.json", plan.contract.as_dict())
    secret = "NEVER_RECORD_CLI_OPERATOR_SECRET"
    config = write(tmp_path / "config.json", {"resource_kinds": {"token": secret}}, private=True)
    assert (
        main(
            [
                "compile-contract",
                "--contract",
                contract,
                "--uid",
                "1000",
                "--gid",
                "1000",
                "--operator-config",
                config,
            ]
        )
        == 2
    )
    output = capsys.readouterr().out
    assert secret not in output and json.loads(output)["status"] == "unsupported"
