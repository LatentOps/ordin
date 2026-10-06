# Runtime observations and trust

`RuntimeObservation`, `RuntimeObservationHistory`, and `RuntimeEvidenceSource`
are additive root-package exports. `ordin runtime-observation validate file.json`
accepts ordinary caller-asserted JSON. Strong labels require explicit
`--trusted-source private/source.json` and a private host-owned observation file.
This operator restoration path is separate from ordinary action input. Protect
the source/evidence files and collection channel; owner-only files do not provide
cryptographic attestation or resist a compromised trusted owner.

`RuntimeObservation` (`ordin.runtime_observation.v1`) adds enforcement evidence
beside the existing caller-supplied `ActionObservation`. It does not execute
actions or replace predicted semantics. `RuntimeObservationHistory` retains
immutable observations and the original reviewed capability contracts.

Trust labels have distinct meanings:

| Label | Meaning |
| --- | --- |
| `caller_asserted` | An ordinary caller reports a fact, as with `ActionObservation`. |
| `backend_observed` | Host-owned integration code reports that the backend observed an event. |
| `backend_enforced` | Host-owned integration code reports an enforcement decision at that control point. |

These labels trust the reporting adapter/runtime path. They are not cryptographic
remote attestation. Python code in the trusted host process can construct a
`RuntimeEvidenceSource`; the host must protect that API and its event input.
An in-process attacker or a compromised runtime is outside this boundary.

Ordinary `from_dict()` and direct constructors reject strong trust labels.
Normal action input and MCP/tool JSON cannot supply a source authorization.
The host explicitly creates a source bound to backend, session digest, named
sandbox, and policy digest, then emits correlated observations:

```python
from ordin import ActionEnvelope, AgentGate, IntegrationSession, SessionIdentity
from ordin.runtime_observation import RuntimeEvidenceSource

session = IntegrationSession(SessionIdentity("host", "example"), AgentGate())
source = RuntimeEvidenceSource(
    "openshell", session.runtime_session_digest, "example-sandbox", "a" * 64
)
session.bind_runtime_source(source)
session.evaluate(ActionEnvelope.shell("git status --short", action_id="step-1"))
contract = session.runtime_contract("step-1")

# Only trusted event collection code should report this backend fact.
observation = source.observe(
    contract, observation_id="event-1", trust="backend_enforced",
    enforcement_point="network", outcome="denied", operation="http.request",
    reason_code="policy_denied",
)
session.observe_runtime(observation)
```

The source is reporting authority, not permission to run an action. The integration
still owns authentic event collection and policy-drift detection. Policy scope
changes require explicit `bind_runtime_action_source()` for the affected reviewed
action after external validation/verification; this API never applies policy.

Correlation rejects unknown or ambiguous action IDs, changed canonical action
digests, conflicting contract IDs, wrong session/sandbox/policy scopes, and
duplicate observation IDs. Runtime session review provenance includes a monotonic
sequence and reset epoch. Reused IDs cannot reuse an old reviewed contract after
reset or retention eviction. Observations for a denied action can describe a
denial; they cannot claim that the blocked action completed.

Outcomes distinguish permission from execution. `allowed` means that a control
point permitted an operation; it does not claim successful completion. `completed`
adds observed-effect and observed-success signals. `denied` adds denied-attempt
and observed-failure signals, and `failed` adds observed-failure. Predicted effects
always remain. Runtime events can strengthen a later decision, including when
reported completed effects were absent from the original prediction.

Normalized signals include `signal:runtime-denied`, `signal:runtime-allowed`,
`signal:runtime-enforced`, `signal:runtime-observed`, control-point and reason
signals, and existing observed-effect/success/failure namespaces. Default temporal
policy version 2 adds tested rules for denied secret-like access before upload,
repeated backend-enforced policy denials toward the same exact resource, and an
equivalent mutation after privilege denial. They describe attempts against a
boundary, without asserting malicious intent. New runtime evidence uses the
execution enforcement order and cannot lower an existing ask/warn/block.

Artifacts reject unknown fields, non-finite values, oversized collections, raw
headers/bodies, credential metadata, and URLs containing userinfo/query/fragment.
Metadata is limited to event digest/schema version and precise request/process
identity fields. No raw runtime payload is retained. Provenance retains digests
and trust/point/outcome; default audit hashes resource values and identifiers.
Hashing does not encrypt low-entropy resources, so protect local evidence.

Legacy `IntegrationSession.snapshot()` remains v1. Runtime evidence has a separate
`ordin.runtime_session.v1` sidecar with no action parameters. Use
`snapshot_bundle()` / `restore_runtime()` for manual persistence, or the existing
private `SqliteSessionStore`, which stores both parts in one transaction. Restoring
strong evidence requires host-owned source objects via `runtime_sources=`.
The legacy part still contains caller action parameters and retains its existing
privacy requirements. Sources, histories, serialized size, and provenance are
bounded; oversized evidence fails instead of dropping records silently. Ending
or resetting a runtime session clears its records and requires a fresh source.
