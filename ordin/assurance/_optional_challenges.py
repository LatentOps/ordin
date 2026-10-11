"""Closed offline failure fixtures over actual optional routing and core APIs.

Only the project-owned mock provider is selected. No caller may supply a
provider, program, endpoint or source. Imported/serialized output never gains
execution authority. The old security-properties-v1 input remains unchanged.
"""

from __future__ import annotations

from dataclasses import replace
from collections.abc import Mapping
import importlib
import json
from pathlib import Path
import tempfile
import threading

from ordin import ActionEnvelope, AgentGate, Ordin, ReviewPolicy
from ordin.action_policy import ActionPolicyCondition, ActionPolicyRule, ActionPolicySet
from ordin.tool_calls import ToolResourceBinding, ToolSemanticRule, ToolSemanticsRegistry

from ._json import digest, freeze, thaw
from ._property_challenges import Outcome
from .gate import AssuranceGate
from .host import HostEvidenceSource
from .models import RepositoryScope
from .origins import register_instruction_origin, correlate_source_use

VERSION = "optional-failures-v1"
PROPERTY = "optional_failure_mode"
SCENARIOS = (
    "benign_supported",
    "disabled",
    "shadow_risk",
    "core_deny",
    "core_ask",
    "mandatory_unavailable",
    "mandatory_timeout",
    "mandatory_transport",
    "mandatory_malformed",
    "mandatory_refused",
    "mandatory_untrusted_content",
    "mandatory_version_mismatch",
    "mandatory_question_mismatch",
    "mandatory_uncertain",
    "call_budget",
    "configuration_change",
    "deadline_timeout",
    "concurrency_budget",
    "scanner_missing",
    "scanner_canceled",
    "malformed_workflow",
    "validation_refused",
)
MODEL_SCENARIOS = SCENARIOS[:-4]


def fixture_packet(property_id, scenario, value, variant, *, noise=True):
    if (
        property_id != PROPERTY
        or not isinstance(scenario, str)
        or scenario not in SCENARIOS
        or type(value) is not int
        or not 0 <= value <= 999
        or variant not in {"actual", "seeded_unsafe_checker"}
        or type(noise) is not bool
    ):
        raise ValueError("unknown bounded optional failure fixture")
    packet = {
        "schema_version": "ordin.assurance_optional_failure_input.v1",
        "generator_version": VERSION,
        "property_id": PROPERTY,
        "scenario": scenario,
        "value": value,
        "variant": variant,
        "assumptions_digest": digest("optional_failure_assumptions", [VERSION, SCENARIOS]),
    }
    if noise:
        packet["noise"] = {"synthetic_padding": [f"unused{value}", "benign fixture notes"]}
    return packet


def _gate(scenario):
    rules = ToolSemanticsRegistry(
        "optional-fixture",
        "1",
        (
            ToolSemanticRule(
                "read",
                "mcp",
                "read_file",
                ("filesystem.read",),
                server="fixture",
                resources=(ToolResourceBinding("path", "path"),),
            ),
        ),
    )
    policy = None
    if scenario in {"core_deny", "core_ask"}:
        policy = ActionPolicySet(
            "fixture-policy",
            "1",
            (
                ActionPolicyRule(
                    "fixture-restriction",
                    "block" if scenario == "core_deny" else "ask",
                    ActionPolicyCondition(kinds=("mcp",)),
                ),
            ),
        )
    return AssuranceGate(
        AgentGate(
            Ordin(
                tool_semantics=rules,
                action_policy=policy,
                policy=ReviewPolicy("block") if scenario == "core_ask" else ReviewPolicy(),
            )
        )
    )


def _state(sdk, gate, action, host, source):
    task = "Read the owned synthetic document"
    baseline = gate.evaluate_action(action, host_context=host)
    origin = register_instruction_origin(
        source,
        origin_id="fixture-task",
        kind="authorized_user",
        classification="public",
        content=task,
    )
    text = action.parameters["arguments"]["path"]
    selected_origin = register_instruction_origin(
        source,
        origin_id="selected-document",
        kind="authorized_user",
        classification="public",
        content=text,
    )
    selected_use = correlate_source_use(
        source,
        selected_origin,
        action,
        use_id="selected-use",
        argument_path=("parameters", "arguments", "path"),
        usage="instruction_context",
    )
    state = sdk.sanitize_decision_state(
        gate,
        baseline,
        host_context=host,
        task_origin=origin,
        task_text=task,
        snippets=(sdk.SelectedSnippet(selected_origin, selected_use, text),),
        inspection=sdk.request_semantic_inspection(
            source, action, reasons=("ambiguous_task_alignment",)
        ),
    )
    return baseline, state


def _model(scenario, value):
    try:
        sdk = importlib.import_module("ordin_decision_models")
        for name in (
            "MockDecisionModel",
            "RoutingPolicy",
            "SemanticInspectionRouter",
            "sanitize_decision_state",
            "request_semantic_inspection",
            "SelectedSnippet",
        ):
            if not callable(getattr(sdk, name, None)):
                return None
    except ImportError:
        return None
    gate = _gate(scenario)
    action = ActionEnvelope(
        "mcp",
        "call",
        {
            "server": "fixture",
            "tool": "read_file",
            "arguments": {"path": f"/fixture/read{value}"},
        },
        action_id="optional-fixture",
    )
    source = HostEvidenceSource(
        f"fixture-agent{value}",
        RepositoryScope("fixture/optional", "fixture-v1"),
        "a" * 64,
        1,
        "b" * 64,
        "c" * 64,
    )
    host = source.context()
    baseline, state = _state(sdk, gate, action, host, source)
    mode = (
        "disabled"
        if scenario == "disabled"
        else "shadow"
        if scenario == "shadow_risk"
        else "enforced-escalation"
    )
    policy = sdk.RoutingPolicy(
        mode=mode,
        mandatory_action_kinds=("mcp",),
        required_question_ids=("material_intent_mismatch",),
        max_total_calls=1,
    )
    behavior = (
        scenario.removeprefix("mandatory_") if scenario.startswith("mandatory_") else "normal"
    )
    if behavior in {"unavailable", "uncertain"}:
        behavior = "normal"
    score = 0.5 if scenario == "mandatory_uncertain" else 0.95 if scenario == "shadow_risk" else 0.1
    provider = sdk.MockDecisionModel({"material_intent_mismatch": score}, behavior=behavior)
    if scenario == "configuration_change":

        class Changing:
            def __init__(self):
                self.inner = sdk.MockDecisionModel({"material_intent_mismatch": 0.1})
                self._descriptor = self.inner.descriptor

            @property
            def descriptor(self):
                return self._descriptor

            @property
            def calls(self):
                return self.inner.calls

            def evaluate(self, *args, **kwargs):
                result = self.inner.evaluate(*args, **kwargs)
                self._descriptor = replace(self.descriptor, model_version="mock-changed")
                return result

        provider = Changing()
    release = finished = None
    if scenario in {"deadline_timeout", "concurrency_budget"}:
        release, finished = threading.Event(), threading.Event()
        policy = replace(policy, deadline_ms=20, max_concurrency=1, max_total_calls=2)

        class Waiting:
            def __init__(self):
                self.inner = sdk.MockDecisionModel({"material_intent_mismatch": 0.1})

            @property
            def descriptor(self):
                return self.inner.descriptor

            @property
            def calls(self):
                return self.inner.calls

            def evaluate(self, *args, **kwargs):
                try:
                    assert release is not None
                    release.wait(1)
                    return self.inner.evaluate(*args, **kwargs)
                finally:
                    assert finished is not None
                    finished.set()

        provider = Waiting()
    router = sdk.SemanticInspectionRouter(
        gate, policy=policy, provider=None if scenario == "mandatory_unavailable" else provider
    )
    if release is not None:
        try:
            result = router.evaluate_action(action, state=state, host_context=host)
            lease_held = router._budget.snapshot()["inflight"] == 1
            deadline_observed = (
                result.model_evidence is not None and result.model_evidence.error_class == "timeout"
            )
            if scenario == "concurrency_budget":
                result = router.evaluate_action(action, state=state, host_context=host)
                deadline_observed &= "semantic.call_budget_exceeded" in result.reason_codes
        finally:
            release.set()
        assert finished is not None
        completed = finished.wait(2)
    else:
        result = router.evaluate_action(action, state=state, host_context=host)
    if scenario == "call_budget":
        first = result
        result = router.evaluate_action(action, state=state, host_context=host)
        control = first.may_execute and "semantic.call_budget_exceeded" in result.reason_codes
    else:
        # The preserved benign counterpart uses identical action/context and a
        # fresh router. A failed benign inspection is unknown, never a failure
        # proof against the mandatory-outage property.
        healthy = sdk.SemanticInspectionRouter(
            gate, policy=policy, provider=sdk.MockDecisionModel({"material_intent_mismatch": 0.1})
        )
        healthy_result = healthy.evaluate_action(action, state=state, host_context=host)
        control = healthy_result.disposition == baseline.disposition
        if scenario == "core_ask":
            control = healthy_result.requires_approval
        if release is not None:
            control &= lease_held and deadline_observed and completed
    expected = scenario in {"benign_supported", "disabled", "shadow_risk"}
    observed = result.may_execute
    details_ok = (
        result.review.as_dict() == baseline.review.as_dict()
        and (scenario not in {"disabled", "core_deny"} or provider.calls == 0)
        and (
            scenario != "configuration_change"
            or not router.binding_matches(result, action, state=state, host_context=host)
        )
    )
    return (
        expected,
        observed,
        control and details_ok,
        action.as_dict(),
        {
            "routing": policy.as_dict(),
            "source": source.key,
            "scenario": scenario,
            "provider_behavior": behavior,
            "score": score,
        },
        baseline.may_execute,
    )


def _core(scenario, value):
    # Actual parser/approval refusal APIs with owned bounded files. No reviewed
    # action, scanner binary, model worker or target program is executed.
    with tempfile.TemporaryDirectory(prefix="ordin-optional-failure-") as directory:
        root = Path(directory)
        if scenario in {"scanner_missing", "scanner_canceled"}:
            from .codex_security.scanner import ScannerSelection, inspect_scanner

            for name in ("cwd", "state"):
                (root / name).mkdir(mode=0o700)
            executable = root / "absent-native-scanner"
            pin = "0" * 64
            if scenario == "scanner_canceled":
                import hashlib

                marker = b"Owned synthetic marker; never executable."
                executable.write_bytes(marker)
                pin = hashlib.sha256(marker).hexdigest()
            selected = ScannerSelection(executable, pin, "fixture-v1", root / "cwd", root / "state")
            cancel = threading.Event()
            if scenario == "scanner_canceled":
                cancel.set()
            checked = inspect_scanner(selected, cancel=cancel)
            protected = checked.status == ("canceled" if cancel.is_set() else "unavailable")
        elif scenario == "malformed_workflow":
            from .codex_security.workflow import WorkflowImportScope, import_workflow_claims

            (root / "workflow.json").write_text(json.dumps({"approved": True, "status": "fixed"}))
            try:
                checked = import_workflow_claims(
                    WorkflowImportScope(
                        root, RepositoryScope("fixture/optional", "fixture-v1"), "verify_fix"
                    )
                )
                protected = (
                    checked.closure == "not_performed" and checked.completeness != "complete"
                )
            except ValueError:
                protected = True  # Explicit malformed-input refusal also grants nothing.
        else:
            from .inventory import AuthorizedRepository
            from .sandbox_tests import VettedSandboxRuntime, run_sandbox_test
            from .synthetic_tests import (
                SyntheticPathCase,
                SyntheticPathSuite,
                load_synthetic_suite,
                load_vetted_program,
            )
            from .models import SourceReference
            import hashlib

            repo = RepositoryScope("fixture/optional", "fixture-v1")
            target = root / "target"
            target.mkdir()
            (target / "guard.py").write_text(
                "def within_root(path, root):\n    return path.startswith(root)\n"
            )
            suite = SyntheticPathSuite(
                "fixture",
                (
                    SyntheticPathCase("benign", "/synthetic/project/file", "/synthetic/project"),
                    SyntheticPathCase(
                        "adverse", "/synthetic/project-other/file", "/synthetic/project"
                    ),
                ),
            )
            (target / "suite.json").write_text(json.dumps(suite.as_dict()))
            scope = AuthorizedRepository(target, repo, "/fixture")

            def ref(name):
                return SourceReference(
                    name, 1, repo.revision, hashlib.sha256((target / name).read_bytes()).hexdigest()
                )

            program = load_vetted_program(scope, ref("guard.py"))
            tests = load_synthetic_suite(scope, ref("suite.json"))
            source = HostEvidenceSource("fixture", repo, "a" * 64, 1, "b" * 64, "c" * 64)
            runtime = VettedSandboxRuntime(
                root / "absent-native-broker",
                "0" * 64,
                root / "_sandbox_worker.py",
                "0" * 64,
                (str(root / "_sandbox_worker.py"),),
                root,
                root,
                "0" * 64,
                (target,),
            )
            checked = run_sandbox_test(scope, source, runtime, program, tests, None)
            protected = checked.status == "refused" and not checked.results
    return (
        False,
        not protected,
        True,
        {"scenario": scenario, "value": value},
        {
            "default_authority": "none",
            "failed_optional_evidence": "cannot_grant",
        },
        True,
    )


def outcome(packet):
    if not isinstance(packet, Mapping):
        raise ValueError("optional failure capture must be a JSON object")
    canonical = fixture_packet(
        packet.get("property_id"),
        packet.get("scenario"),
        packet.get("value"),
        packet.get("variant"),
        noise="noise" in packet,
    )
    if thaw(freeze(packet)) != canonical:
        raise ValueError("optional failure assumptions or selectors changed")
    scenario, value = canonical["scenario"], canonical["value"]
    measured = _model(scenario, value) if scenario in MODEL_SCENARIOS else _core(scenario, value)
    if measured is None:
        return Outcome(
            "unsupported",
            "unsupported",
            False,
            "assurance.challenge.optional_sdk_unavailable",
            digest("property_action", canonical),
            canonical["assumptions_digest"],
            "unsupported",
            False,
        )
    expected, actual, assessable, action, policy, unsafe_projection = measured
    if not assessable:
        return Outcome(
            "unsupported",
            "unsupported",
            False,
            "assurance.challenge.benign_control_unresolved",
            digest("property_action", action),
            digest("property_policy", policy),
            "unsupported",
            False,
        )
    if canonical["variant"] == "seeded_unsafe_checker" and not expected:
        actual = unsafe_projection  # Closed mutant discards refusal/attention/binding.
    return Outcome(
        "accepted" if expected else "rejected",
        "accepted" if actual else "rejected",
        True,
        "assurance.challenge.optional_failure_evaluated",
        digest("property_action", action),
        digest("property_policy", policy),
        "control" if expected else "non_decreasing",
        expected,
    )
