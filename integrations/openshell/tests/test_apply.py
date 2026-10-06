import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from ordin._runtime_json import digest
from ordin.enforcement_backend import EnforcementPlan
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin_openshell.apply import (
    apply_openshell_policy,
    canonical_runtime_policy,
    prepare_openshell_apply,
)
from ordin_openshell.apply_audit import PolicyApplyAudit
from ordin_openshell.backend_cli import OpenShellCLI, OpenShellCommandError, load_json
from ordin_openshell.compiler import OpenShellBackend
from ordin_openshell.prover import OpenShellProverResult, MODELED_DOMAINS, parse_prover_json
from test_compiler import supported_contract


def setup_plan(decision="allow"):
    backend = OpenShellBackend((1000, 1000))
    contract = replace(supported_contract(), decision=decision, contract_id="")
    return backend, backend.compile(contract).plan


def boundary_for(contract):
    return RuntimeCapabilityBoundary(
        "fixture",
        filesystem=contract.filesystem,
        network=contract.network,
        process=contract.process,
        privilege=contract.privilege,
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )


class FakeCLI:
    """Structured 0.1.2 response fixture; no sandbox or action actually runs."""

    workspace = "default"
    context = {"executable": "fixture-openshell", "gateway": "fixture", "workspace": "default"}

    def __init__(self, plan):
        self.policy = copy.deepcopy(plan.as_dict()["policy"])
        self.policy["network_policies"] = {}
        self.version = 1
        self.calls = []
        self.set_calls = 0
        self.full_reads = 0
        self.before_read = None
        self.after_set = None
        self.loaded_status = "loaded"
        self.admission_state = "accepted"
        self.fail_set = False
        self.sandbox_id = "sandbox-unique-id"

    def require_compatible(self):
        self.calls.append(("--version",))

    def json(self, arguments, **kwargs):
        self.calls.append(tuple(arguments))
        if arguments[:2] == ("policy", "get"):
            if "--rev" not in arguments:
                self.full_reads += 1
                if self.before_read:
                    self.before_read(self)
            packet = {
                "scope": "sandbox",
                "sandbox": "demo",
                "version": self.version,
                "active_version": self.version,
                "hash": digest(self.policy),
                "status": self.loaded_status if "--rev" in arguments else "effective",
                "config_revision": self.version,
                "policy_source": "sandbox",
                "policy": copy.deepcopy(self.policy),
            }
            return packet
        assert arguments[:2] == ("sandbox", "get")
        return {
            "name": "demo",
            "workspace": self.workspace,
            "id": self.sandbox_id,
            "created_at": "2026-10-06T00:00:00Z",
            "phase": "Ready",
            "current_policy_version": self.version,
            "policy_source": "sandbox",
            "configuration_admission": {
                "state": self.admission_state,
                "policy_version": self.version,
                "policy_hash": digest(self.policy),
                "config_revision": self.version,
            },
            "policy": copy.deepcopy(self.policy),
        }

    def run(self, arguments, **kwargs):
        self.calls.append(tuple(arguments))
        assert arguments[:3] == ("policy", "set", "demo")
        assert "--wait" in arguments and "--timeout" in arguments
        self.set_calls += 1
        snapshot = Path(arguments[arguments.index("--policy") + 1])
        self.policy = json.loads(snapshot.read_text())
        self.version += 1
        if self.after_set:
            self.after_set(self)
        if self.fail_set:
            raise OpenShellCommandError("openshell_cli_timeout", uncertain=True)
        return ""


def prepare(backend, plan, cli, **kwargs):
    kwargs.pop("audit", None)
    return prepare_openshell_apply(plan, backend=backend, sandbox="demo", cli=cli, **kwargs)


def approve_and_apply(backend, plan, cli, **kwargs):
    preparation = prepare(backend, plan, cli, **kwargs)
    return apply_openshell_policy(
        plan,
        backend=backend,
        sandbox="demo",
        cli=cli,
        approval_request_id=preparation.request_id,
        **kwargs,
    )


def test_named_sandbox_approval_is_bound_to_action_contract_policy_and_runtime_state():
    backend, plan = setup_plan("ask")
    cli = FakeCLI(plan)
    preparation = prepare(backend, plan, cli)
    assert preparation.status == "requires_approval" and cli.set_calls == 0
    packet = preparation.as_dict()
    assert packet["action_digest"] == plan.contract.action_digest
    assert packet["contract_id"] == plan.contract.contract_id
    assert packet["policy_digest"] == plan.policy_digest
    result = apply_openshell_policy(plan, backend=backend, sandbox="demo", cli=cli)
    assert result.status == "requires_approval" and cli.set_calls == 0
    result = approve_and_apply(backend, plan, cli)
    assert result.status == "applied" and result.mutation_attempted
    assert result.current.policy_digest == plan.policy_digest and cli.set_calls == 1
    assert all(call[0] in {"--version", "policy", "sandbox"} for call in cli.calls)
    assert not any(
        word in {"exec", "create", "start", "delete"} for call in cli.calls for word in call
    )
    source = result.evidence_source("a" * 64)
    assert source.sandbox_id == "sandbox-unique-id" and source.policy_digest == plan.policy_digest


@pytest.mark.parametrize("sandbox", ["", "--global", "demo;bad", "../other", "demo\nother"])
def test_invalid_sandbox_rejects_before_any_backend_operation(sandbox):
    backend, plan = setup_plan()
    cli = FakeCLI(plan)
    with pytest.raises(ValueError, match="identity"):
        apply_openshell_policy(plan, backend=backend, sandbox=sandbox, cli=cli)
    assert cli.calls == []


def test_block_shadow_and_changed_policy_cannot_enter_apply():
    backend, plan = setup_plan()
    blocked = replace(plan.contract, decision="block", contract_id="")
    with pytest.raises(ValueError):
        EnforcementPlan("openshell", blocked, plan.policy)
    cli = FakeCLI(plan)
    assert prepare(backend, replace(plan, mode="shadow"), cli).status == "unsupported"
    assert prepare(replace(backend, mode="shadow"), plan, cli).status == "unsupported"
    changed = plan.as_dict()["policy"]
    changed["filesystem_policy"]["read_write"] = ["/"]
    assert prepare(backend, replace(plan, policy=changed), cli).status == "unsupported"
    assert cli.calls == []


def test_exact_approval_cannot_be_reused_for_changed_review_decision_or_boundary():
    backend, plan = setup_plan()
    cli = FakeCLI(plan)
    first = prepare(backend, plan, cli)
    _, ask_plan = setup_plan("ask")
    result = apply_openshell_policy(
        ask_plan, backend=backend, sandbox="demo", cli=cli, approval_request_id=first.request_id
    )
    assert result.status == "requires_approval" and cli.set_calls == 0
    result = apply_openshell_policy(
        plan,
        backend=backend,
        sandbox="demo",
        cli=cli,
        approval_request_id=first.request_id,
        capability_boundary=boundary_for(plan.contract),
    )
    assert result.status == "requires_approval" and cli.set_calls == 0


def test_capability_boundary_exceedance_refuses_even_an_approval_token():
    backend, plan = setup_plan()
    cli = FakeCLI(plan)
    boundary = replace(boundary_for(plan.contract), network=())
    result = apply_openshell_policy(
        plan,
        backend=backend,
        sandbox="demo",
        cli=cli,
        capability_boundary=boundary,
        approval_request_id="fake",
    )
    assert result.status == "exceeds_boundary" and cli.calls == []
    assert result.preparation.verification[-1]["step"] == "capability_boundary"


@pytest.mark.parametrize("state", ["exceeds_boundary", "unsupported", "inconclusive", "error"])
def test_non_success_prover_coverage_or_result_prevents_apply(monkeypatch, state):
    import ordin_openshell.apply as module

    backend, plan = setup_plan()
    cli = FakeCLI(plan)
    monkeypatch.setattr(
        module,
        "verify_with_openshell_prover",
        lambda *a, **k: OpenShellProverResult(
            state,
            "fixture_prover_reason",
            {"domains": ["network_rest"]},
            {"domain": "filesystem", "path": "/private/target"},
        ),
    )
    result = apply_openshell_policy(
        plan,
        backend=backend,
        sandbox="demo",
        cli=cli,
        backend_boundary_policy=plan.policy,
        approval_request_id="fake",
    )
    assert result.status == state and cli.calls == []
    assert result.preparation.verification[-1]["coverage"]["domains"] == ("network_rest",)
    assert "/private/target" not in json.dumps(result.as_dict())


def test_prover_success_must_bind_to_the_actual_policy_snapshot_bytes(monkeypatch):
    import ordin_openshell.apply as module

    backend, plan = setup_plan()
    cli = FakeCLI(plan)
    monkeypatch.setattr(
        module,
        "verify_with_openshell_prover",
        lambda *a, **k: OpenShellProverResult(
            "within_boundary",
            "fixture",
            {"domains": sorted(MODELED_DOMAINS)},
            candidate_digest="a" * 64,
            boundary_digest="b" * 64,
        ),
    )
    prepared = prepare(backend, plan, cli, backend_boundary_policy=plan.policy)
    assert prepared.status == "unsupported"
    assert prepared.reason_code == "openshell_prover_input_binding_mismatch"
    assert cli.calls == []


def test_verified_boundary_runs_on_snapshots_and_preserves_audit_linkage(monkeypatch, tmp_path):
    import ordin_openshell.apply as module

    backend, plan = setup_plan()
    cli = FakeCLI(plan)
    observed = []

    def prove(candidate, boundary, **kwargs):
        observed.append(json.loads(candidate.read_text()))
        assert candidate != boundary
        return OpenShellProverResult(
            "within_boundary",
            "fixture",
            {"domains": sorted(MODELED_DOMAINS)},
            candidate_digest=hashlib.sha256(candidate.read_bytes()).hexdigest(),
            boundary_digest=hashlib.sha256(boundary.read_bytes()).hexdigest(),
            prover_version="0.1.2",
        )

    monkeypatch.setattr(module, "verify_with_openshell_prover", prove)
    audit = PolicyApplyAudit(tmp_path / "apply.jsonl")
    result = approve_and_apply(
        backend,
        plan,
        cli,
        backend_boundary_policy=plan.policy,
        capability_boundary=boundary_for(plan.contract),
        audit=audit,
    )
    assert result.status == "applied" and len(observed) == 2
    assert all(packet == plan.as_dict()["policy"] for packet in observed)
    verified = audit.verify()
    assert verified["ok"] and verified["events"] == 2
    records = [json.loads(line) for line in audit.path.read_text().splitlines()]
    assert records[1]["previous_hash"] == records[0]["event_hash"]
    assert records[0]["contract_id"] == plan.contract.contract_id
    assert records[0]["action_digest"] == plan.contract.action_digest
    assert records[0]["policy_digest"] == plan.policy_digest
    assert len(records[0]["verification"]) == 3
    assert "/usr" not in audit.path.read_text() and "api.github.com" not in audit.path.read_text()
    with pytest.raises(ValueError, match="checkpoint"):
        audit.verify(expected_last_hash="a" * 64)


def test_audit_failure_before_mutation_is_fail_closed(tmp_path):
    backend, plan = setup_plan()
    cli = FakeCLI(plan)
    audit = PolicyApplyAudit(tmp_path / "bad.jsonl")
    audit.path.write_text('{"incomplete":true}')
    result = approve_and_apply(backend, plan, cli, audit=audit)
    assert result.status == "unsupported" and not result.mutation_attempted and cli.set_calls == 0


def test_policy_change_after_approval_and_during_final_read_is_detected():
    backend, plan = setup_plan()
    cli = FakeCLI(plan)

    def drift(instance):
        if instance.full_reads == 3:
            instance.version += 1

    cli.before_read = drift
    result = approve_and_apply(backend, plan, cli)
    assert result.status == "inconclusive" and result.reason_code == "openshell_policy_drift"
    assert not result.mutation_attempted and cli.set_calls == 0


def test_startup_changes_and_unloaded_or_unadmitted_configuration_refuse_apply():
    backend, plan = setup_plan()
    for setting in ("filesystem", "loaded", "admission"):
        cli = FakeCLI(plan)
        if setting == "filesystem":
            cli.policy["filesystem_policy"]["read_only"].append("/etc")
        elif setting == "loaded":
            cli.loaded_status = "pending"
        else:
            cli.admission_state = "pending"
        result = approve_and_apply(backend, plan, cli)
        assert result.status in {"unsupported", "inconclusive"} and cli.set_calls == 0


def test_effective_provider_authority_added_after_set_is_not_treated_as_verified():
    backend, plan = setup_plan()
    cli = FakeCLI(plan)

    def extra_provider(instance):
        rule = next(iter(copy.deepcopy(instance.policy["network_policies"]).values()))
        rule["endpoints"][0]["host"] = "unrelated.example.com"
        instance.policy["network_policies"]["provider-extra"] = rule

    cli.after_set = extra_provider
    result = approve_and_apply(backend, plan, cli)
    assert result.status == "inconclusive" and result.mutation_attempted and cli.set_calls == 1
    with pytest.raises(ValueError, match="not_verified"):
        result.evidence_source("a" * 64)


def test_timeout_is_uncertain_and_never_retries_even_if_the_policy_changed():
    backend, plan = setup_plan()
    cli = FakeCLI(plan)
    cli.fail_set = True
    result = approve_and_apply(backend, plan, cli)
    assert result.status == "inconclusive" and result.mutation_attempted
    assert cli.set_calls == 1
    with pytest.raises(ValueError):
        result.evidence_source("a" * 64)


def test_readback_accepts_only_known_authority_neutral_defaults():
    _, plan = setup_plan()
    policy = plan.as_dict()["policy"]
    policy["filesystem_policy"].pop("read_write")
    key, rule = next(iter(policy["network_policies"].items()))
    rule["name"] = key
    endpoint = rule["endpoints"][0]
    endpoint.update(tls="", path="", access="", deny_rules=[], allow_encoded_slash=False)
    assert digest(canonical_runtime_policy(policy)) == plan.policy_digest
    endpoint["tls"] = "skip"
    with pytest.raises(ValueError, match="unsupported"):
        canonical_runtime_policy(policy)


def test_malformed_backend_json_and_prover_state_fail_closed():
    for text in ('{"version":1,"version":2}', '{"value":NaN}', "[]"):
        with pytest.raises(ValueError):
            load_json(text)
    from test_prover import response

    payload = response()
    payload["result"] = []
    assert parse_prover_json(json.dumps(payload), returncode=0).result == "error"


def test_cli_calls_use_literal_argv_and_do_not_leak_backend_diagnostics(monkeypatch):
    import subprocess
    import ordin_openshell.backend_cli as module

    calls = []
    monkeypatch.setattr(module.shutil, "which", lambda name: "/trusted/openshell")

    def run(argv, *, stdout, **kwargs):
        calls.append(argv)
        assert "shell" not in kwargs and kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        stdout.write(b"openshell 0.1.2\n")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(module.subprocess, "run", run)
    OpenShellCLI(gateway="local", workspace="default").require_compatible()
    assert calls == [
        ["/trusted/openshell", "--workspace", "default", "--gateway", "local", "--version"]
    ]
    endpoint_cli = OpenShellCLI(gateway_endpoint="http://127.0.0.1:18780")
    endpoint_cli.require_compatible()
    assert calls[-1] == [
        "/trusted/openshell",
        "--workspace",
        "default",
        "--gateway-endpoint",
        "http://127.0.0.1:18780",
        "--version",
    ]
    assert endpoint_cli.context["gateway_endpoint"] == "http://127.0.0.1:18780"


@pytest.mark.parametrize(
    "endpoint",
    [
        "file:///tmp/gateway",
        "http://user:secret@example.com",
        "http://example.com?token=secret",
        "http://example.com/path",
        "http://example.com#secret",
        "http://example.com:65536",
        "https://@api.example.com/",
        "https://:@api.example.com/",
        "https://api.example.com:0/",
        "https://api.example.com:PRIVATE_PORT_VALUE/",
    ],
)
def test_gateway_endpoint_cannot_carry_credentials_or_unmodeled_connection_data(endpoint):
    with pytest.raises(ValueError, match="openshell_gateway_endpoint_invalid") as error:
        OpenShellCLI(gateway_endpoint=endpoint)
    assert endpoint not in str(error.value) and "PRIVATE_PORT_VALUE" not in str(error.value)


@pytest.mark.parametrize(
    "arguments",
    [
        ("exec", "demo", "rm", "-rf", "/"),
        ("sandbox", "create", "demo"),
        ("policy", "set", "demo", "--global", "--policy", "a", "--wait"),
        ("policy", "get", "--global", "--full", "--output", "json"),
    ],
)
def test_management_adapter_cannot_execute_actions_or_mutate_global_policy(arguments):
    with pytest.raises(ValueError):
        OpenShellCLI().run(arguments)
