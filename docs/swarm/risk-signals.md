# Optional behavioral risk signals

`SwarmRiskScorer` is disabled by default. Disabled submission returns `None`
before collecting inputs, hashing text, calling a provider, starting a worker or
reserving cost. Importing Ordin or `ordin_swarm.semantic_signals` starts nothing.
There are no required model dependencies, network clients or implicit downloads.

This is an optional inference input. It cannot establish identity, approval,
completion, verified effects, causal counterexamples or execution permission.
Deterministic core blocks, mandatory escalation, unknown required checks and
revoked delegation remain stronger. A risk receipt cannot replace a host event,
observation, `SwarmAssessment`, delegation grant or broker admission.

## Explicit collection and shadow scoring

The protected integration owner selects bounded `SwarmRiskInput` values. Input
kinds distinguish private instructions, untrusted messages, tool output, shared
plans and retries; all remain behavioral input, never host-authenticated facts.
Do not expose the scorer's configuration or collector to model tools.

```python
from ordin.swarm.risk_signals import SwarmRiskInput, SwarmRiskScorer

operator = object()  # retained by the protected integration owner
scorer = SwarmRiskScorer(enabled=True, operator=operator)
ticket = scorer.submit(
    original_context,
    original_action,
    (SwarmRiskInput("tool_output", captured_tool_output),),
)
receipt = scorer.poll(ticket)  # None while shadow work is pending
```

Default provider input contains fixed feature names and opaque evidence pointers,
with no prompt or payload text. Pointers use a private per-scorer HMAC key; the
provider cannot use a public plain-content hash as a prompt guessing oracle.
The context carries no workload identity, host evidence or review authority.
The caller retains ownership of its original input; Ordin retains bounded
features and inference receipts.

`include_redacted_excerpt=True` is a separate explicit opt-in. It passes at most
256 normalized characters per input after bounded token/email redaction. This
can still contain private text: context output marks `raw_payload_included: true`
and `residual_privacy_risk: bounded_excerpt_may_contain_private_text`. Redaction
does not establish that an excerpt is safe to disclose. A user-configured
semantic provider receives this bounded context only when explicitly configured.

Inputs are limited to 16 items, 16 KiB each and 64 KiB together. The local provider
uses six fixed bounded patterns. Operators cannot install regex policy programs,
Python snippets, remote includes or provider discovery strings.

## Provider and resource boundary

An optional user-configured object implements
`score(context: SwarmRiskContext, budget: SwarmRiskBudget)`. Output is the exact
`ordin.swarm_risk_signal.v1` shape: class, original context evidence pointers,
finite confidence and uncertainty, reported cost and the unchanged time/cost
budget. Positive classes need at least one original pointer. Extra approval,
identity, permit, effect or counterexample fields are rejected. Output never
contains free-form model explanations.

The class vocabulary covers prompt injection, policy persuasion, task redirection,
collusive coordination, evasive retries and coordinated plan changes, plus
`none` and `unknown`. A class is a hypothesis; it does not prove intent or an
observed effect. The local rules' numerical confidence is not a general calibrated
probability.

The scorer admits at most 1–8 daemon workers and a finite job history. Each job
has a 1–1000 ms classifier deadline. Polling waits at most the requested bounded
time and original remaining deadline. A timed-out job produces no signal; its
worker slot remains occupied until the provider actually exits. Late output
cannot replace the timeout receipt or retroactively change a decision. A hung
in-process provider is not forcibly killed; saturated capacity fails without
starting more workers. A separate process/container boundary is needed to
contain arbitrary user-supplied provider code physically.

The protected caller reserves the entire cost budget before starting a job.
Model-reported low cost never refunds that reservation. This is conservative
admission accounting, **not physical provider-billing enforcement**. Unknown or
uncapped remote billing needs a provider-side bound outside this optional plugin.

## Operator-controlled promotion

Without promotion, scoring is shadow-only and gate disposition stays unchanged.
A pure `SwarmGate` review never invokes a classifier or waits for one:

```python
gate = SwarmGate(registry, risk_scorer=scorer)
decision = gate.evaluate_action(
    original_context, original_action,
    channel=original_channel, adapter=original_adapter,
    risk_receipt=receipt,
)
```

Promotion requires `configure_promotion(policy, original_report, operator=operator)`
with an original same-scorer/current-configuration calibration report. Calibration
must include explicit positive and benign cases; incomplete or failed runs cannot
enable promotion. The operator can require a maximum observed false-positive
rate. JSON or copied reports cannot approve configuration.

`SwarmRiskPromotionPolicy` can select only `escalate` or `deny`, confidence and
uncertainty thresholds, and explicit `on_missing=ignore|escalate|deny`. The default
missing/failure behavior preserves the core result. Even a scored `none` or
forged `approved` cannot turn a mandatory unknown, escalation or block into
execution. Promotion changes fence existing scorer bindings and old receipts.
Receipts are original-object, action/context/configuration bound and expire after
30 seconds on the protected scorer clock. JSON and copied receipts are inference
data only. A decision receipt remains a review result, never an execution permit.
Every new capture for the same action/context invalidates its previous receipt,
including a new timeout or exhausted-budget capture. Cached benign inference
cannot silently stand in for newly captured suspicious input. Traffic that the
protected collector never captures remains outside this guarantee.

Provider identifiers are host-declared labels. Arbitrary external provider code,
weights, network behavior and billing are not attested by this optional module.

The original operator can call `disable_promotion(operator=operator)` without a
new calibration run, including during provider failure or exhausted capacity.
This fences old risk bindings without resetting workers or reserved cost.

## Independent synthetic calibration

Run the explicit offline evaluation from the repository root:

```text
python -m examples.swarm.evaluate_risk_signals --corpus examples/swarm/risk-calibration-corpus.json --output risk-calibration.json
```

The checked-in [corpus](../../examples/swarm/risk-calibration-corpus.json) and
[report](../../examples/swarm/risk-calibration-report.json) cover 16 synthetic cases.
The local rules found six positives, missed two indirect instructions, correctly
left six benign cases unflagged and incorrectly flagged two quoted examples.
Observed false-positive and false-negative rates are both **25%**; confidence
Brier score is **0.23**, mean uncertainty **0.45**. The Windows/Python 3.13 sample
mean classifier elapsed time was about **0.51 ms**, maximum **1.25 ms**, with a
1000 ms evaluation budget. Timing includes worker scheduling and classifier
validation, not input collection or real model/network latency.

These are deliberately small synthetic measurements, independent of authorization
tests. They establish neither production accuracy nor general prompt-injection
prevention. Exact class confusion, failures, dataset digest, provider binding,
platform and timing are retained in the artifact; no customer prompts are used.
The report does not enable promotion. An original report from a different scorer
process cannot approve a live scorer.

Context, signal, receipt and calibration schemas have source/package parity.
`as_dict()`, `binding_digest`, decision `risk_receipt_digest` and `status()` are
redacted audit/evaluation integration hooks. Durable audit/evaluation consumers
must preserve `evidence_class: behavioral_inference` and the separate performance
and accuracy metrics. No future audit-service or evaluation-runner integration is
claimed here. Unmediated execution paths remain outside this optional review.
