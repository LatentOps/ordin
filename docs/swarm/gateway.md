# Explicit swarm tool mediation

SwarmToolGateway owns a protected forwarding boundary for calls actually routed
through it. It reuses IntegrationSession and SwarmGate, retaining one bounded
history per enrolled actor. It is not a sandbox and cannot prevent direct calls,
inherited handles or tools that bypass the gateway.

## SDK forwarding

~~~python
from ordin import ActionEnvelope
from ordin.swarm import CoverageManifest, InMemoryAgentRegistry, SwarmGate, SwarmToolGateway

registry = InMemoryAgentRegistry("tenant", "swarm")
adapter = object()  # Verified host-side runtime adapter in a real integration.
channel = registry.bind_channel(adapter, runtime_id="python")
context = registry.enroll(
    channel, adapter, agent_id="worker", session_id="session",
    coverage=CoverageManifest("intercept"),
)
gateway = SwarmToolGateway()
actor = gateway.bind_agent(context, SwarmGate(registry), channel, adapter,
                           routes=frozenset({"sdk"}))
authorization = gateway.prepare(actor, ActionEnvelope.shell("git status --short"))
if authorization.ticket is not None:
    result = gateway.forward(actor, authorization.ticket, host_owned_executor)
~~~

The host keeps actor handles, channels, executors and tickets outside agent
control. Enrollment requires a current original identity. The gateway replaces
caller action IDs with an opaque host correlation ID and binds the exact
normalized action, decision, actor, history, evidence snapshot and expiry.
The executor receives a detached action with unchanged parameters.

A ticket admits one forwarding attempt. It is consumed before invoking the
executor, including failed attempts. Changed actions, wrong actors, copied
handles, replay, expired identity/ticket or changed policy/history/evidence
reject without invoking the executor. There is one active attempt per actor.
The review-to-forward transaction is serialized per gateway, including MCP
round trips, so another actor's journal update cannot race that transaction.
Separately prepared tickets still require a fresh binding check at forwarding.

An operator-provided assessment_provider may supply protected SwarmAssessment
receipts after the host action ID and review inputs are known. The callback is
a trusted host integration, not action data or policy code; its receipts still
undergo every SwarmGate binding/expiry check. Missing mandatory checks remain
conservative.

## Approval, results and coverage

Warn/ask never produces a forwarding ticket. Without an actual host approval UI,
the gateway reports denial. With approval_ui enabled it may report escalation,
but it still issues no ticket and does not fabricate approval. A separate
approved workflow must re-review the action. The current gateway does not
replace the enforcing broker or delegated commit API.

An executor result is a host call result, not proof that predicted effects
occurred. Host adapters may return GatewayOutcome with completed, failed or
pending status. Pending/asynchronous acceptance records forwarding without
inventing completion. Raw result dictionaries cannot assign those Python host
types or become sealed RuntimeObservation evidence.

If an event ingestor is configured, the gateway records its collected
proposal/review/commit/forward/result facts after the forwarding attempt. This
keeps the authorization snapshot stable during that attempt. Forwarded means the
host executor was invoked, not that an upstream server received or completed an
effect. A journal failure leaves an explicit gap and blocks subsequent forwarding;
the attempt is still consumed and never automatically retried.

The [status schema](../../schemas/swarm-gateway-status.v1.schema.json) reports
observe/intercept/enforce/uncovered mode, each route and journal gaps. Routes are
shell, MCP, file, database, HTTP and direct SDK. Only explicitly registered routes
in intercept/enforce enrollment are mediated. Observe/uncovered enrollment never
gets a forwarding ticket. An enforce mode label does not upgrade mediation into
physical enforcement.

## MCP stdio and Streamable HTTP host adapters

SwarmMCPAdapter wraps the maintained MCPStdioSafetyProxy parser, contract
observer and result correlation. Each actor/server adapter owns a separate MCP
session. Tool calls also pass the swarm gateway. Use a host-owned stdio
round-trip function or Streamable HTTP client as its transport:

~~~python
from ordin.swarm import SwarmMCPAdapter

mcp = SwarmMCPAdapter(gateway, actor, server_id="approved-server",
                     shell_tools=frozenset({"shell"}))
response = mcp.call(request_object, protected_stdio_or_http_roundtrip)
~~~

The registered routes must include MCP. The optional MCPHTTPConfig must match the
pinned server ID. The transport owns HTTP authentication, version/session headers,
connection setup and framing; existing MCPHTTPServer behavior is unchanged.
This adapter is explicit host-side composition, not automatic enrollment of
arbitrary HTTP clients or a claim that the old CLI proxy has acquired identity.

The adapter replaces upstream request IDs with host UUIDs and restores client
IDs after exact response matching. Two actors may use the same client ID without
sharing pending-call state. Parameters and the pinned tool/server identity stay
unchanged. Malformed calls, unsupported methods, wrong response IDs and upstream
failures do not produce a second attempt. Contract pinning and tool-list change
notifications reuse the existing observer. A tool rename in response text cannot
change the pending tool identity.

Only tools/call is an action route. Initialize, initialized notifications,
tools/list and ping retain protocol handling. Other methods return an explicit
uncovered-method error until a dedicated adapter exists. A transport can pass
upstream notifications to observe_notification().

MCP error/isError/task acceptance is normalized by the maintained reviewer.
Response text, claimed approvals and observed_effects are not promoted into
trusted effects. The event journal contains host result facts and digests,
not raw MCP results.

## Maintained hooks

SwarmHookAdapter reuses Claude Code, Codex, Cursor and Hermes payload adaptation,
then calls prepare/forward at the protected host boundary. It preserves native
validation and replaces payload correlation IDs with the host action ID.
Use its call(payload, executor) API where the host controls the actual tool
invocation. It does not install hidden hooks or authenticate a CLI process from
model-authored hook JSON. Current single-agent hook behavior remains unchanged.

The optional ordin-swarm package reexports these thin host adapters; the core
retains zero required dependencies. No transport starts on import. Native
delegated execution still requires its action-bound issuer/broker integration;
the gateway rejects that configuration instead of treating a pure delegation
preview as a committed use.
