# Optional semantic risk evidence

The separate `integrations/decision_models` package implements provider-neutral
typed input, privacy selection, offline mocks, conservative routing and an
explicit asynchronous TypeSafe adapter and explicit local Laya worker. It is
separate from command-search reranking and absent from Ordin's default runtime.
Real model/hardware effectiveness and full calibration acceptance remain open.

The host builds `SanitizedDecisionState` from a current `AssuranceDecision` using
`sanitize_decision_state`. It checks action/profile/history/context binding.
Authorized task text requires a private protected instruction-origin handle and
matching complete bytes; it cannot come from an agent role label. Snippets require
matching source/use/action handles. Credentials are omitted, private/unknown
classification prevents hosted use, and public summaries contain only hashes and
counts. Selected private text remains available through `as_dict()` for explicit
host review and provider input; never treat it as a routine public report.

`request_semantic_inspection` records a protected exact-action request for
ambiguous task alignment, unclear effect, proximity to a trust boundary or
cross-agent flow. Actual source-use/effect metadata also supplies bounded signals.
Those facts ask a question; they establish neither persuasion nor exploitation.
No question or budget means no optional inference. Profiles may designate
mandatory action/effect classes and exact required questions; missing context or
inspection never becomes a successful required check.

The five fixed questions cover task mismatch, possible secret egress, suspicious
permission expansion, untrusted instruction following and suspicious delegation.
Questions are versioned immutable definitions and batched where supported.
Answers must match the question names, state digest and pinned provider version.
Probabilities are predictions, not authorization, calibration proof, finding
confirmation or backend observations. Generated text, unknown names, malformed
answers, booleans-as-scores and nonfinite/out-of-range scores are refused.

Routing defaults to `disabled`. `shadow` records advisory evidence and preserves
the baseline disposition. `enforced-escalation` can add escalation at the selected
threshold or when a mandatory inspection fails/is uncertain. A core denial skips
providers; core asks retain attention even after a low model score. Typed router
results seal their baseline/configuration/state and cannot be restored from JSON
or changed through a dataclass replacement. Use `binding_matches` before forwarding
an action; the caller still owns approval, execution and physical enforcement.

Call count, concurrency, input bytes and deadlines are bounded. Timed-out sync
workers keep their lease until they actually finish, preventing unbounded
background work. The host must isolate a local inference worker against resource
or process escape; a Python thread timeout does not stop arbitrary native code.
Async provider cancellation propagates and closes the transport. Synchronous
routing refuses an async-only hosted provider, rather than hiding a network wait
inside a hook. Host-specific adapter deadline/response integration remains M11.

The TypeSafe contract was verified against its [published schema](https://api.typesafe.ai/openapi.json).
Discovery returns account-available model names; no alias is assumed. Inference
sends one bounded state with named `noul` questions and checks the returned model,
answers and usage. The selected CA file is hashed before TLS setup, the destination
is fixed to `api.typesafe.ai:443`, proxy environment is unused and redirects/retries
are refused. Nonstandard/compressed/chunked framing is currently unsupported and
fails closed. No live account/API response has been exercised in this work.

`authorize_hosted_disclosure` requires an actual action-bound `HostApproval` and
satisfied host assessment with kind/invariant `semantic_hosted_scope` /
`semantic.hosted_scope`, matching the protected profile/source. The request binds
the exact state/question/model/configuration, short lifetime and request/spend
budgets. The host must verify actual API credential routing, service egress,
protected configuration and account/gateway spend enforcement before issuing that
assessment. The primitive receipt contains no host issuance/execution interface.
It is not a physical sandbox or billing controller. The service contract offers
no request currency cap, and observed token counts cannot prove spend enforcement.

Laya package/version/source blobs and model-card license were inspected; no actual
weights/ML package were loaded during these checks. The local backend requires a
native pinned Python interpreter and fixed `_laya_worker.py`, private home/trusted
working directory and reviewed complete installed dependency tree. Checkpoint
artifacts consist of safetensors, RL/encoder config and local tokenizer files;
unknown executable artifacts, links/hardlinks, custom remote-code configuration,
changed byte hashes and unsupported tokenizer mutation refuse setup. Selected
runtime/checkpoint paths must stay outside target and enclosing Git worktrees.
The operator prepares any tokenizer correction separately, reviews it and pins
the resulting bytes. Model input contains selected semantic text/signals rather
than opaque audit hashes; the complete sanitized record still binds the request.

`authorize_local_model` requires protected setup approval and a satisfied host
assessment with kind/invariant `semantic_local_scope` / `semantic.local_scope`.
The host must actually isolate the worker: no network or credentials, read-only
checkpoint and immutable runtime, no target/private asset mounts, and bounded
CPU/memory/process lifetime. A primitive one-use setup scope reaches the provider;
it contains no host issuance object. Offline/telemetry flags and stripped child
environment support this boundary but do not establish physical enforcement.

`LayaDecisionModel.initialize` is explicit. It verifies hashes/version/device and
starts a persistent bounded JSON worker only after approval. Laya imports/loads
occur in that worker. Unexpected version/device, tokenizer/loader mutation or
truncated state/options remain unresolved, never successful predictions. Requests
bind state/question/checkpoint digests and monotonic request IDs. Call quotas,
scope expiry/configuration change, setup/call timeout, output overflow and async
cancellation end the process and ordinary descendants. Windows uses suspended
creation plus a Job Object; POSIX process execution is unverified locally. Broker
isolation is still needed against privileged process escape and native resource
abuse. Routine telemetry contains hashes/counts/device, not source or diagnostics.

The real-provider recipes in `ordin_decision_models.examples` default to disabled.
Enable them only with an actual selected checkpoint/runtime or consented hosted
provider and current sanitized state/questions. No ordinary example downloads
weights, discovers accounts, infers automatically or executes a reviewed action.

`evaluation.py` supports bounded synthetic `SemanticCorpus` partitions. Duplicate
content is detected independently of renamed IDs/labels; fitting accepts only
complete unambiguous development controls. A frozen threshold binds the provider
and development/prediction digests; held-out/shift evaluation rejects overlap or
version/threshold drift. Precision/recall, ROC and step-wise PR average precision,
ECE/Brier and Wilson rate intervals are independent calculations. Empty/one-class
samples retain undefined metrics. Per-model metrics include only supported scored
cases; aggregate results retain deterministic denials, abstentions, ambiguous
cases, critical misses and developer friction. Timing includes fixture input
review and routing; per-family coverage/misses remain explicit.

Current verified scope is protocol/privacy/routing, fake HTTP/API and synthetic
worker/metric behavior. Live inference/hardware, independently labeled frozen
workloads and actual effectiveness/friction/latency acceptance remain open.
Synthetic mock probabilities do not demonstrate threat detection.
