# Optional Ordin decision models

This separate package provides typed semantic risk evidence. Core Ordin imports,
gate construction and ordinary commands perform no inference, model setup or
provider calls. No new mandatory core dependency is added.

```python
from ordin_decision_models import MockDecisionModel, RoutingPolicy, SemanticInspectionRouter

router = SemanticInspectionRouter()  # disabled
```

Use `python -I -m ordin_decision_models.demo` after installing the local optional
wheel to run the entirely synthetic offline example. It prints redacted results
for disabled, shadow and enforced-escalation modes; no command is executed.
The mock's predetermined values verify plumbing, not model effectiveness.

The provider-neutral `DecisionModel` and `AsyncDecisionModel` protocols take only
`SanitizedDecisionState` and a finite versioned `SecurityQuestionSet`. They return
Ordin's `ModelRiskEvidence` with bounded probabilities and input/question/version
binding. Current security questions use the typed yes/no (`noul`) API. Alternate
choice/score or generated-text responses cannot substitute for those answers.

Privacy inputs require the current Assurance gate review. Trusted task bytes must
match a protected `authorized_user` instruction origin. Selected snippets must
match protected source-use handles and exact action bytes. Unknown/private
classification or detected credentials refuses hosted inference. Routine state
summaries contain hashes/counts; `state.as_dict()` is the selected private model
input and must not be logged. Text is hidden from normal object representations.
No raw action/history forwarding or tool/host issuance object reaches a provider.

Host-authenticated inspection triggers describe actual ambiguity, unclear effect,
near-boundary work or cross-agent flow. Low-risk ordinary operations with no real
question skip inference. Required policy classes fail closed for missing context,
unavailable/malformed/uncertain predictions, exhausted budgets and timeouts.
Shadow preserves sampled disposition; enforced mode may add escalation and never
remove a deterministic restriction. It cannot approve, execute, publish or patch.

The TypeSafe adapter implements the inspected [0.2.0 API schema](https://api.typesafe.ai/openapi.json):
explicit bearer-authenticated model discovery, followed by batched named typed
questions. Select a discovered name and pin the expected returned model version.
The implementation fixes HTTPS host/port, pins operator-selected CA bytes, rejects
redirects and unsupported framing, bounds bytes/deadlines and performs no retry.
It is async only; synchronous routing refuses to call it implicitly.

Both discovery and inference need protected host consent and a conclusive
`semantic_hosted_scope` assessment for actual credential/egress/spend controls.
The provider receives a short-lived bounded primitive receipt, not the issuing
host source/profile. Review the exact selected state/question payload before
recording approval. A JSON consent flag or digest alone is insufficient.
The API exposes no per-request currency cap; the host must verify the actual
account/gateway spend ceiling. Token accounting cannot establish that ceiling.

Laya release 0.4.1 and its checkpoint APIs/license are pinned in resources.
`LocalCheckpoint`, `LocalModelRuntime`, `authorize_local_model` and
`LayaDecisionModel` provide explicit local setup and persistent inference. The
native interpreter, worker, complete checkpoint and transitive installation are
host selected and pinned outside target/Git roots. Safe tensors and local
tokenizer/encoder files are required; unknown executable artifacts, changed
hashes and tokenizer configurations requiring mutation refuse setup. No weights
are downloaded. The host must verify actual no-egress/read-only/resource isolation
before issuing the protected local assessment. Offline environment flags support
that isolation; they do not replace the physical broker. See the local API
details and limitations in the main documentation.

`evaluation.py` provides frozen development/held-out/shift corpora, content-based
disjointness checks, development-only threshold selection, per-model calibration/
ROC/PR metrics and aggregate restrictions/coverage/friction/latency. Synthetic
metric tests verify calculations without claiming model threat effectiveness.
`examples.py` contains opt-in local/hosted recipes requiring actual host-supplied
scope, selected inputs and provider configuration; disabled examples do nothing.

The full held-out security evaluation, calibration/friction/latency acceptance
and live TypeSafe/Laya checks remain open. Fake transports/mocks prove contract
and restriction behavior only. See [decision models](../../docs/assurance/decision-models.md).
