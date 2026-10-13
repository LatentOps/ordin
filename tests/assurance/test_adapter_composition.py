"""Existing host protocols/sessions retain behavior under deterministic Assurance composition."""

from dataclasses import FrozenInstanceError

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import AssuranceGate, HostEvidenceSource
from ordin.assurance.adapters import AssuranceAdapterGate
from ordin.assurance.models import SecurityInvariant, InvariantSelectors
from ordin.session import IntegrationSession, SessionIdentity, configuration_digest
from ordin.claude_code import ClaudeCodeIntegration, CLAUDE_CODE_RUNTIME
from ordin.codex import CodexIntegration, CODEX_RUNTIME
from ordin.cursor import CursorIntegration, CURSOR_RUNTIME

from .test_profiles import selected, config_profile, approve, REPO, POLICY_HASH
from tests.test_claude_code import _pre_payload
from tests.test_codex import _payload
from tests.test_cursor import payload


def adapter(tmp_path, *, rule=None):
    tmp_path.mkdir(exist_ok=True)
    profile = approve(
        selected(
            tmp_path,
            config_profile(
                rule
                or SecurityInvariant(
                    "approval", "require_approval", InvariantSelectors(kinds=("shell",))
                )
            ),
        )
    )
    source = HostEvidenceSource(
        "fixture-host", REPO, "b" * 64, 1, POLICY_HASH, profile.selection_digest
    )
    guarded = AssuranceGate(AgentGate(), profile)
    return AssuranceAdapterGate(guarded, source)


def test_existing_host_approval_semantics_and_session_denials(tmp_path):
    gate = adapter(tmp_path)
    claude_session = IntegrationSession(SessionIdentity(CLAUDE_CODE_RUNTIME, "session-1"), gate)
    claude = ClaudeCodeIntegration(gate=gate, session=claude_session)
    output = claude.pre_tool_output(_pre_payload("Bash", {"command": "git status --short"}))
    assert output["hookSpecificOutput"]["permissionDecision"] == "ask"
    codex_session = IntegrationSession(SessionIdentity(CODEX_RUNTIME, "session"), gate)
    codex = CodexIntegration(gate=gate, session=codex_session)
    output = codex.pre_tool_output(_payload())
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert codex_session.snapshot()["denied_action_ids"]
    from ordin.cursor import _identity as cursor_identity

    cursor_session = IntegrationSession(cursor_identity(payload()), gate)
    cursor = CursorIntegration(gate=gate, session=cursor_session)
    assert cursor.pre_tool_output(payload())["permission"] == "deny"
    assert cursor_session.snapshot()["denied_action_ids"]


def test_core_hard_denial_and_disabled_profile_parity_are_preserved(tmp_path):
    gate = adapter(tmp_path)
    assert gate.evaluate_action(ActionEnvelope.shell("rm -rf /")).denied
    source = gate.source
    disabled = AssuranceAdapterGate(AssuranceGate(), source)
    action = ActionEnvelope.shell("git status --short")
    assert disabled.evaluate_action(action) == AgentGate().evaluate_action(action)
    assert configuration_digest(disabled) != configuration_digest(AgentGate())
    with pytest.raises(FrozenInstanceError):
        disabled.source = source


def test_assurance_profile_and_source_changes_reject_snapshot_restore(tmp_path):
    gate = adapter(tmp_path)
    session = IntegrationSession(SessionIdentity("fixture", "s"), gate)
    session.evaluate(ActionEnvelope.shell("git status --short", action_id="first"))
    saved = session.snapshot()
    changed = adapter(
        tmp_path / "changed",
        rule=SecurityInvariant(
            "block-connect",
            "forbid_effect",
            InvariantSelectors(effects=("network.connect",)),
            on_violation="block",
        ),
    )
    assert configuration_digest(gate) != configuration_digest(changed)
    with pytest.raises(ValueError):
        IntegrationSession.restore(session.identity, changed, saved)
    IntegrationSession.restore(session.identity, gate, saved)


def test_context_is_host_owned_and_history_is_retained(tmp_path):
    gate = adapter(tmp_path)
    session = IntegrationSession(SessionIdentity("fixture", "s"), gate)
    session.evaluate(ActionEnvelope.shell("git status", action_id="one"))
    session.evaluate(ActionEnvelope.shell("git diff", action_id="two"))
    assert [row["action_id"] for row in session.snapshot()["history"]["actions"]] == ["one", "two"]
    with pytest.raises(ValueError):
        AssuranceAdapterGate(gate.assurance, gate.source, context_options={"approved": True})


def test_existing_mcp_proxy_retains_approval_refusal_and_state(tmp_path):
    from ordin.mcp_proxy import MCPStdioSafetyProxy, APPROVAL_REQUIRED_CODE
    from tests.test_mcp_proxy import _read_semantics, _call

    approved = approve(
        selected(
            tmp_path,
            config_profile(
                SecurityInvariant(
                    "approve-mcp", "require_approval", InvariantSelectors(kinds=("mcp",))
                )
            ),
        )
    )
    source = HostEvidenceSource(
        "fixture-host", REPO, "b" * 64, 1, POLICY_HASH, approved.selection_digest
    )
    bridge = AssuranceAdapterGate(
        AssuranceGate(AgentGate(Ordin(tool_semantics=_read_semantics())), approved), source
    )
    proxy = MCPStdioSafetyProxy(server_id="fixture", gate=bridge, session_id="fixture-session")
    response = proxy.process_client_message(_call(arguments={"path": "/fixture/readme"}))
    assert not response.forward and response.response["error"]["code"] == APPROVAL_REQUIRED_CODE
