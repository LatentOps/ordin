# Reference composition with existing adapters

`AssuranceAdapterGate` subclasses the existing deterministic `AgentGate` interface
and delegates actual review to an `AssuranceGate`. Inject it into existing
`ClaudeCodeIntegration`, `CodexIntegration`, `CursorIntegration` or
`MCPStdioSafetyProxy`; their adapters, output formats and session implementation
are reused. No host parser or transport is forked.

```python
from ordin import AgentGate
from ordin.assurance import AssuranceGate, AssuranceAdapterGate
from ordin.claude_code import ClaudeCodeIntegration, CLAUDE_CODE_RUNTIME
from ordin.session import IntegrationSession, SessionIdentity

# The protected host supplies actual approved_profile/source handles.
guard = AssuranceGate(AgentGate(), approved_profile)
bridge = AssuranceAdapterGate(guard, source)
session = IntegrationSession(SessionIdentity(CLAUDE_CODE_RUNTIME, host_session_id), bridge)
integration = ClaudeCodeIntegration(gate=bridge, session=session)
response = integration.pre_tool_output(host_payload)
```

The host owns session/process identity and actual operator-selected profile,
source and approval/assessment/credential collections. Hook input cannot supply
those facts. Context options are validated typed immutable collections; no callback
or semantic provider is accepted by this deterministic wrapper. It performs no
inference, account discovery, model setup, tool execution or OS enforcement.
Optional model evidence must be collected separately through explicitly bounded
SDK routing; mandatory model outages cannot become permission to execute.

Claude preserves `ask` for escalation. Codex/Cursor pre-tool hooks and MCP calls
without approval support deny or refuse forwarding, and their existing session
retains that refusal. Core hard denial remains denial. Permission-request behavior
continues to preserve the host's own approval UI rather than claiming to approve
broader sandbox rights.

Session configuration includes a closed optional Assurance binding for the
profile/requirements/context/source. Default core gate digests are unchanged.
Snapshots cannot restore history under changed profile/source configuration, and
runtime changes require a fresh gate/session. The protected host still checks
current identities/epochs, grant lifecycle and backend resources at use time.

The composition tests exercise real host outputs and independent sessions, MCP
refusal, hard-denial/default parity, retained history, immutable context and
snapshot rejection. They do not prove a live host deployment or kernel sandbox.
