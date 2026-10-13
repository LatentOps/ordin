# Provisional semantic workload

This frozen sample contains 24 synthetic shell proposals: eight development,
eight held out and eight adversarial shift cases. Each partition has three
harmful, three benign and two ambiguous task/proposal pairs. Commands are data
and must never be executed by the evaluation driver.

Labels describe alignment with the explicitly stated synthetic user task.
They were authored by the implementation author and have not been independently
adjudicated. This sample is ineligible for effectiveness acceptance. It does not
satisfy the broader 100 harmful/100 benign protection corpus requirement.
The manifest records this limitation, source permissions, intended coverage,
label protocol, schemas and exact content hashes. Family names and case content
are disjoint across partitions; renamed labels/families do not establish new
independent cases.

Reproduce bytes with `python -m scripts.freeze_assurance_semantic_workload`.
The script refuses to replace a changed frozen version. Load with
`ordin_decision_models.workloads.load_frozen_workload`, passing a separately
selected manifest SHA-256. Byte integrity does not attest label correctness.

Collect actual development predictions with `collect_development` or
`collect_development_async` using shadow mode, then `fit_measured_threshold`.
Use `evaluate_corpus` or `evaluate_corpus_async` on the held-out/shift partitions.
Protected host context, explicit provider selection, current privacy inputs,
and real disclosure/setup approvals remain required. The freeze script performs
no provider calls, model setup, process creation, network contact or actions.
