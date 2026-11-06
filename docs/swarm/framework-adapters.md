# Framework adapters and the host SDK

The optional `ordin-swarm` package connects existing tool boundaries to Ordin.
It does not replace a framework's planner, download a model, load callbacks from
JSON, infer identity from a tool description, or make an unwrapped agent a
sandbox. Importing the package starts no service or model.

## Verified version contracts

The following exact distributions are checked before installation and tool
forwarding. Other versions require conformance verification; they do not inherit
a protection claim from a similar API name.

| Adapter | Tested distributions | Actual boundary | Existing runtime |
| --- | --- | --- | --- |
| LangGraph | `langgraph==1.2.20`, `langgraph-prebuilt==1.1.1`, `langchain-core==1.7.6` | ToolNode wrapper plus guarded synchronous StructuredTool callback after native argument validation | Rebuild ToolNode and its compiled graph |
| CrewAI — security blocked | Historical hook tests used `crewai==1.15.35`, `crewai-core==1.15.35` | No active coverage; required ChromaDB has unresolved advisories | Setup, adapter construction and fixtures refuse before importing the SDK, including an externally installed matching version |
| AutoGen legacy | `autogen-core==0.7.5` | Owned SingleThreadedAgentRuntime intervention handler and native synchronous FunctionTool callback | Create a runtime with the original intervention handler |
| Custom Python | No framework dependency | Original protected SDK session or verified HostSessionEndpoint dispatch table | Live future-call routing where the host provides a verified setter |

The active maintained-framework conformance gate covers LangGraph. CrewAI is
temporarily quarantined; this release does not claim two available maintained
framework integrations. Microsoft
has [archived AutoGen](https://github.com/microsoft/autogen); its adapter is
explicitly pinned legacy compatibility. It is not described as maintained
upstream support. The public contracts researched for these adapters are
[LangGraph ToolNode](https://reference.langchain.com/python/langgraph.prebuilt/tool_node/ToolNode),
[CrewAI tool hooks](https://docs.crewai.com/v1.15.35/en/learn/tool-hooks), and
[AutoGen intervention handlers](https://microsoft.github.io/autogen/stable/user-guide/core-user-guide/cookbook/tool-use-with-intervention.html).
The version matrix and quarantine were checked on 2026-11-06.
The optional extras also pin the common native argument parser to
`pydantic==2.14.2`. CI uses separate hash-locked dependency closures under
`requirements/swarm-*.txt`, generated from the tested Linux Python 3.12
environment with `scripts/lock_swarm_frameworks.py` and primary PyPI hashes.

### LangGraph UUID dependency boundary

The tested LangGraph closure includes LangSmith 0.14.17, whose
[published metadata](https://pypi.org/pypi/langsmith/0.14.17/json) requires
`uuid-utils>=0.12.0,<1.0`. The managed lock retains 0.19.0; UUID Utils 1.2.0 does
not satisfy this requirement. The optional extra and lock generator state the
same compatible range explicitly. These are dependency-resolution bounds, not
an attestation of arbitrary externally installed dependency combinations.

### AutoGen legacy dependency boundary

AutoGen Core 0.7.5's [published dependency metadata](https://pypi.org/pypi/autogen-core/0.7.5/json)
requires `protobuf~=5.29.3`; the tested lock retains 5.29.6. Protobuf 7.x does not
satisfy that requirement. The optional extra and lock generator state the same
constraint explicitly, without bypassing dependency resolution.

Protobuf Python 5.x [ended upstream support on 31 March 2026](https://protobuf.dev/support/version-support/#python).
This AutoGen path is retained as opt-in archived compatibility. Its installed
fixture and hash pins do not establish upstream maintenance, a patched dependency
closure, or security clearance. Core, custom and LangGraph paths do not require
this AutoGen dependency. The release manifest's dependency security clearance
remains `not_established`.

### CrewAI dependency quarantine

The CrewAI 1.15.35 runtime requires ChromaDB 1.5.9. At the review date the
[published ChromaDB release](https://pypi.org/project/chromadb/1.5.9/) has no
published fix listed for
[GHSA-f4j7-r4q5-qw2c](https://github.com/advisories/GHSA-f4j7-r4q5-qw2c),
[GHSA-36p7-vc44-83pf](https://github.com/advisories/GHSA-36p7-vc44-83pf),
[GHSA-2wm9-hf6c-p5cr](https://github.com/advisories/GHSA-2wm9-hf6c-p5cr) and
[GHSA-xph7-9rjv-w5fr](https://github.com/advisories/GHSA-xph7-9rjv-w5fr).
The active CrewAI extra, dependency lock and SDK provisioning lane are removed.
The retained implementation cannot be enabled through setup, a matching version,
an environment variable or copied configuration. Status reports
`availability:security_blocked`, false compatibility and no covered paths.

This removes Ordin's active installation and adapter exposure; it does not patch
upstream or uninstall packages from an operator's environment. Existing managed
manifests can still be uninstalled with their original digest. Do not install
CrewAI through this integration while quarantined. Re-enablement requires a code
change after a verified fixed dependency closure and fresh real SDK conformance
and dependency-security checks. Previous offline hook passes do not clear these
dependency findings or authorize a production rollout.

Before upgrading an already running deployment, use the original operator path
to fence and drain its protected work, stop the affected runtime, and restart
with the quarantined package. Installing new code cannot hotpatch an old process
or retroactively revoke unmediated tools or credentials. Use the supported
upstream credential-revocation procedure where needed. Status inspection and
managed-manifest uninstall remain available; the blocked adapter cannot import
the SDK to operate on an old runtime or act as a cleanup shortcut.

## Install and run without paid services

From a checkout, install core and the selected optional extra:

```bash
python -m pip install -e . -e "integrations/swarm[langgraph]"
python examples/swarm/framework_adapter_demo.py --framework langgraph
```

Replace `langgraph` with `autogen` for its pinned legacy SDK. The custom
Python fixture needs only core and `integrations/swarm`:

```bash
python examples/swarm/framework_adapter_demo.py --framework custom
```

Run fixtures in a separate Python process. They use only synthetic private data,
local tools, finite local model responses where a planner is needed, and a
temporary workspace. Runtime network connections and telemetry are disabled
for the fixture process. There is no implicit model or embedding download.

Every active fixture performs an allowed artifact read, sends its original lineage
through the real message gateway to a second agent, verifies inherited private
labels, and denies both the upload and an unrepresented child-creation tool.
The child request receives no grant and never reaches its callback. This is
not a claim that a framework's native delegation flags implement issuer
attenuation. Applications needing delegated children must enroll and bind the
actual current grants through the protected delegation/coordinator service.
The report links the post-tool outcome, exposes no fixture payload, and reports
`physical_enforcement:false` and `observed_exfiltration:unknown`.

## Original identity and exact effects

`SwarmSDK.bind` accepts an operator-owned runtime object, original registry
context, host channel, adapter, gate, gateway and lifecycle callback. The
lifecycle callback must keep returning the same original object. The context
owns agent, physical session, task, epoch and delegation identity. Model
messages, CrewAI roles, LangGraph state/config fields and AutoGen tool names
cannot enroll or rebind a principal.

`register_tool` retains the original callable, a host configuration guard and
either the existing ToolCallAdapter or an explicit host action builder. The
host must supply reviewed semantics through Ordin's ToolSemanticsRegistry or a
deterministic action builder. Unrepresented tool semantics retain the core
warning/escalation/block outcome; unavailable native approvals never become
permission. The SDK does not implement a second framework-specific policy
engine.

`prepare` copies bounded JSON arguments, assigns a host action ID, calls the
maintained gateway and retains an original one-use call handle. `forward`
rechecks current identity, lifecycle, tool configuration and exact arguments
immediately before the bound callback. A request ID cannot be replayed,
including with changed arguments. A retry with a new ID undergoes a fresh
review and reservation. Callback failures retain native framework error
handling and are not automatically retried by the SDK.

Arguments are bounded to 64 KiB of JSON, twelve levels, 4,096 nodes and exact
interoperable JSON integers. Foreign Python objects, nonfinite numbers and
unrepresented native injection paths fail closed. The host owns callback
configuration and mutable globals outside these arguments. It must protect
that code and dispatch table from the agent; these adapters do not defend
against hostile Python already running inside the trusted host process.

### Framework-specific limits

LangGraph authorization occurs inside the guarded function after native
validation/coercion, so the callback receives the reviewed normalized values.
The adapter preserves ToolNode's configured error handling. Injected
state/store/runtime/config arguments, native async tool routes and non-JSON
Command/Send results require a stronger adapter and return non-success. Removing
the outer wrapper does not make the guarded inner callback executable without
its original per-call scope. Arbitrary graph nodes remain uncovered.

The quarantined CrewAI implementation is retained for a future verified fix;
the following describes its historical hook boundary, not available coverage.
It binds original Agent and Task objects and validates the original tool
schema/callback relationship. Its inner callback requires a one-use scope from
the native hook, including across native worker threads. A missing, swallowed
or foreign hook cannot forward the tool. Native caches must be disabled
explicitly. Restored/checkpointed callbacks do not restore protected object
identity; re-enroll and rebuild them. Closing removes only this adapter's hooks
and fences its SDK session. It restores its original tool table when no executor
has been built; an existing executor requires a controlled rebuild.

AutoGen binds native producer/recipient routes inside the original owned
runtime. FunctionCall names select an original registered tool, rather than
providing identity. Unknown senders, wrong recipients, duplicate JSON fields,
replayed IDs, mutated function pointers and direct calls without a native scope
are refused. Broadcast and distributed runtime tool paths are unsupported.
The archived version's intervention-denial queue accounting can prevent
`stop_when_idle` from returning; the adapter uses the documented immediate
runtime stop. That fences queued work and does not roll back a running callback.

CustomRuntimeAdapter uses the existing SwarmAttachManager and HostSessionEndpoint
readback check. `bind_sdk` adopts that exact original gateway actor; it does not
invent a process restart, copy an identity report, or discard history to attach
permissions. Detach restores an unchanged owned routing slot and fences old
handles. Pre-attach history stays unknown.

## Messages, artifacts and coordinator routes

FrameworkDataBridge explicitly binds original SDK contexts to existing
SwarmSourceFlow, SwarmMessageGateway peers and SwarmArtifactGateway sources.
Opaque FrameworkData handles retain private bytes and original lineage. An
artifact read keeps ACL/version checks; an authorized handoff verifies the
actual original delivery outcome and recipient lineage before exposing data
to the next bound session. Copies of a handle, mismatched bytes, another actor
and JSON metadata cannot create lineage or policy authority.

Use `bridge.use(...)` to supply the original exact-byte LineageUse to the
existing source-flow check. Native framework task context, message text,
checkpoint stores, vector stores and plugin transports are still uncovered
unless they pass through these explicit typed bridges. Receiving a message
authorizes data delivery, rather than receiver execution.

`SwarmSDK.bind_coordinator` binds the original coordinator scope, authenticated
workload and broker channels, current lease, native grant and registered owned
broker. It evaluates and reserves through the coordinator, then uses its single
guarded dispatch. It does not separately consume a core delegation ticket or
budget forwarding reservation. The actual broker compiles and executes the
canonical action. The framework callback is not substituted for that executor.
Successful completion requires the original verified broker result. Lost
acknowledgements or uncertain effects stay uncertain and cannot be retried by
replaying a call handle.

The physical claim is limited to the broker's supported owned executor route;
the generic callback route always remains interception. Read
[enforcing-broker.md](enforcing-broker.md) and [coordinator.md](coordinator.md)
for supported request/resource constraints and durable reconciliation. Existing
direct network, credentials, background workers, remote plugins and arbitrary
host shells are not automatically contained by a framework adapter.

FrameworkJSONClient reuses the coordinator's real mutually authenticated TLS
protocol. A frame is a four-byte big-endian length followed by at most 65,536
bytes of UTF-8 JSON. The existing coordinator request/response schemas and
ten-second per-request deadline apply. Identity comes from the protected
certificate enrollment and fixed server scope. Producer and broker operations
remain separated. There is no JSON-selected tenant/role, executable callback,
offline authority restoration, reconnect or automatic retry.

## Setup, status and doctor

```bash
ordin-swarm-adapter doctor --framework langgraph
ordin-swarm-adapter setup --framework langgraph --directory ./my-integration --dry-run
ordin-swarm-adapter setup --framework langgraph --directory ./my-integration --install
```

The explicit directory must already exist. Setup never overwrites a file and
creates only a private managed manifest. It reports `runtime_installed:false`:
an on-disk manifest cannot install an in-process tool hook or authorize an
effect. Uninstall requires that unchanged manifest's returned digest. It does
not delete unrelated user configuration.

CLI doctor checks installed versions and reports an unbound runtime. Live
coverage comes from the original in-process adapter's `status()`/`doctor()` and
the gateway/coordinator, rather than a copied JSON report. Covered synchronous
calls, unavailable approvals, restart requirements and every unwrapped path
remain visible. A framework interception test and an original kernel broker
receipt are separate evidence.

Pinned SDK conformance lives under `integrations/swarm/tests`; core SDK, typed
service and actual broker composition regressions live under `tests`. The
active framework CI matrix uses isolated environments, disables implicit pytest
plugin autoload and runtime network access, and runs real two-agent workflows
plus forged/replayed/mutated/concurrent/error/unsupported-path controls. Wheel
smoke covers the optional adapter package and its base install without model
or framework dependencies.
The separate mandatory `CrewAI security quarantine` lane installs no CrewAI or
ChromaDB package, checks their absence and verifies that matching external SDK
metadata cannot bypass the block. It reports quarantine, rather than positive
CrewAI conformance.

Runtime schema loading uses the resources owned by the installed Ordin package.
A sibling `site-packages/schemas` directory installed by another SDK cannot
shadow these validators. Checkout source schemas remain part of the explicit
source/package parity gate.
