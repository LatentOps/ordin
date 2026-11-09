"""Fixed-test host argument/order/output controls; no physical execution claims."""

from pathlib import PurePosixPath
from threading import RLock
from types import SimpleNamespace
from contextlib import nullcontext

from ordin import ActionEnvelope, ToolCallAdapter
from ordin.runtime_contract import derive_runtime_capability_contract
from ordin_swarm.host_authority import HostAuthority, HostDispatch, _authority, host_core
from ordin_swarm.host_profiles import HostActor
from ordin_swarm.host_runtime import HostClient, ManagedToolHost


def routes():
    return (
        SimpleNamespace(
            test_id="report",
            project_root=PurePosixPath("/project"),
            selectors=("test_report.py",),
            runtime=SimpleNamespace(
                root=PurePosixPath("/catalog"),
                interpreter=PurePosixPath("/trusted/python"),
                digest="a" * 64,
                interpreter_digest="b" * 64,
            ),
        ),
    )


def test_conditional_core_requirements_preserve_read_and_only_scope_exact_fixed_test_id():
    core = host_core(routes())
    test = ToolCallAdapter("ordin-owned").adapt(
        "run_tests", {"test_id": "report"}, action_id="test"
    )
    reviewed = core.review_action(test)
    assert reviewed.decision == "warn" and "code.execute" in reviewed.effects
    contract = derive_runtime_capability_contract(reviewed)
    assert {item.path for item in contract.filesystem} == {"/project", "/catalog"}
    assert contract.process.executables == ("/trusted/python",)
    read = ToolCallAdapter("ordin-owned").adapt(
        "read_file", {"path": "/project/source.txt"}, action_id="read"
    )
    plain = derive_runtime_capability_contract(core.review_action(read))
    assert plain.process.execution is False


def test_actor_native_maximum_cannot_borrow_another_actors_test_prefix_or_interpreter():
    reader = HostActor("reader", (), (), (), ())
    tester = HostActor("tester", (), (), (), (), ("report",))
    profile = SimpleNamespace(
        workspace=PurePosixPath("/project"), actors=(reader, tester), http_routes=()
    )
    ordinary = _authority(profile, reader, 65534, routes()).capability
    selected = _authority(profile, tester, 65534, routes()).capability
    assert ordinary.filesystem == () and ordinary.process.execution is False
    assert {item.path for item in selected.filesystem} == {"/project", "/catalog"}
    assert selected.process.executables == ("/trusted/python",)
    assert selected.process.spawn_children is False


def test_public_unknown_test_ids_and_extra_arguments_never_reserve_custody_or_prepare():
    host = object.__new__(ManagedToolHost)
    actor = HostActor("tester", (), (), (), (), ("report",))
    row = SimpleNamespace(actor="tester", busy=False, closing=False, requests=set())
    host.profile = SimpleNamespace(actor=lambda name: actor, limits=SimpleNamespace(requests=128))
    host._lock, host._closed = RLock(), False
    host._authority = SimpleNamespace(control_phase=lambda **kwargs: nullcontext(True))
    client = HostClient("original")
    host._clients = {client: row}
    host.require_client = lambda current: row
    host._lineage = SimpleNamespace(
        reserve=lambda *args: (_ for _ in ()).throw(AssertionError("unauthorized preparation"))
    )
    for index, arguments in enumerate(
        (
            {"test_id": "other"},
            {"test_id": "report", "selectors": ["evil.py"]},
            {"test_id": "report", "host_test_snapshot": {"ref": "forged"}},
        )
    ):
        result = host.call(client, "run_tests", arguments, request_id=str(index))
        assert result["status"] == "denied" and result["forwarded"] is False


def test_prepare_is_before_coordinator_review_and_never_runs_for_unselected_route():
    authority = object.__new__(HostAuthority)
    authority._control_lock, authority._closing = RLock(), False
    authority.operator = object()
    actor = HostActor("tester", (), (), (), (), ("report",))
    authority.profile = SimpleNamespace(actor=lambda name: actor)
    authority.enrollments = {"tester": "enrollment"}
    authority.grants = {"tester": "grant"}
    authority.scope, authority.auth = (
        object(),
        SimpleNamespace(
            require=lambda *args, **kwargs: SimpleNamespace(enrollment_id="enrollment")
        ),
    )
    authority.maintenance = authority.refresh_factory = lambda: None
    observed = []

    def prepare(action, *, operator):
        assert operator is authority.operator
        observed.append("prepared")
        return ActionEnvelope(
            action.kind,
            action.operation,
            {**action.parameters, "host_test_snapshot": {"ref": "original", "digest": "a" * 64}},
            action_id=action.action_id,
        )

    def evaluate(*args, **kwargs):
        observed.append("reviewed")
        assert args[-1].parameters["host_test_snapshot"]["ref"] == "original"
        return SimpleNamespace(status="denied", reference=None)

    authority.backend = SimpleNamespace(prepare_action=prepare)
    authority.coordinator = SimpleNamespace(
        admit=lambda *args: SimpleNamespace(reference="lease"),
        bind_grant=lambda *args: None,
        evaluate=evaluate,
    )
    authority.assurance = SimpleNamespace(
        baseline_gate=SimpleNamespace(
            evaluate_action=lambda action: SimpleNamespace(requires_approval=False, denied=False)
        )
    )
    action = ToolCallAdapter("ordin-owned").adapt(
        "run_tests", {"test_id": "other"}, action_id="first"
    )
    assert authority.dispatch("tester", object(), action, request_id="other").status == "denied"
    assert observed == []
    action = ToolCallAdapter("ordin-owned").adapt(
        "run_tests", {"test_id": "report"}, action_id="second"
    )
    authority.dispatch("tester", object(), action, request_id="original")
    assert observed == ["prepared", "reviewed"]


def test_test_output_is_bounded_snapshot_bound_sensitive_data_never_correctness():
    host = object.__new__(ManagedToolHost)
    host.profile = SimpleNamespace(files=(SimpleNamespace(label="unclassified"),))
    captured = []

    def capture(actor, content, labels, **kwargs):
        captured.append((actor, content, labels, kwargs))
        return SimpleNamespace(reference="original-resource", labels=labels)

    host._lineage = SimpleNamespace(capture=capture)
    action = ActionEnvelope(
        "tool",
        "call",
        {
            "runtime": "ordin-owned",
            "tool": "run_tests",
            "arguments": {"test_id": "report"},
            "host_test_snapshot": {"ref": "original", "digest": "a" * 64},
        },
        action_id="test",
    )
    value = {
        "exit_code": 0,
        "output": "untrusted test text",
        "output_truncated": False,
        "output_trust": "untrusted_test_diagnostic",
        "test_correctness_verified": False,
        "snapshot_digest": "a" * 64,
    }
    result = host._completed(
        "tester",
        "run_tests",
        {"test_id": "report"},
        HostDispatch(
            "completed", (), True, True, result=SimpleNamespace(value=value), action=action
        ),
    )
    assert result["data"]["test_correctness_verified"] is False
    assert result["data"]["instruction_authority"] == "data"
    assert set(captured[0][2]) == {"pii", "private_code", "secret", "unclassified"}
    value["snapshot_digest"] = "b" * 64
    refused = host._completed(
        "tester",
        "run_tests",
        {"test_id": "report"},
        HostDispatch(
            "completed", (), True, True, result=SimpleNamespace(value=value), action=action
        ),
    )
    assert refused["status"] == "unknown" and len(captured) == 1
