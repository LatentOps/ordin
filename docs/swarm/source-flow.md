# Cross-agent sensitive-data lineage

`ordin.swarm.SwarmSourceFlow` is an explicit host service. It hashes actual
source bytes and stores labels and bounded ancestry handles. It starts no
collector, server or automatic file scan. The host must keep the service,
operator capability, source handles and assessment authority outside agent
control. This Python API is not an isolation boundary against hostile code
executing in the same protected host memory.

## Collection and propagation

Create a protected `SwarmCausalGraph` and configure exact `EgressSink` routes.
Bind each original event source and current `SwarmContext` to its protected
Assurance `HostEvidenceSource` with `bind_actor`. The host-source principal
must match the enrolled actor. This mapping is explicit: names in model text,
HTTP headers or serialized context do not enroll a collector.

After collecting actual bytes, use existing `register_instruction_origin` to
classify the source and `register` to bind it to an authenticated event.
The event must explicitly carry the SHA-256 content digest. A generic runtime
resource digest often hashes metadata; it cannot substitute for the content
digest. The origin must cover the entire bounded content, share the original
host source and retain its protected classification. Root labels are host
declarations about the collected bytes, not independent kernel read evidence.

For an observed message/file handoff or transformation, call `derive` with the
original parent handles, output bytes and output event. The authenticated graph
must connect the inputs to that output. Delegation and caller hypotheses are
excluded from transfer paths. Equal bytes or timestamps without a handoff do
not establish cross-agent lineage. Derived records retain parent labels even
when summarization, base64, copying or an opaque transformation changes bytes.
The collector must explicitly declare complete transform inputs; otherwise
unclassified provenance is retained. Unknown transfer stays unknown and cannot
be presented as verified exfiltration.

The lattice contains `secret`, `pii`, `private_code`, `public` and
`unclassified`. Sensitive categories accumulate by union, public is the
non-sensitive base, and unclassified persists through joins. A public label
does not erase sensitivity. Contents are capped at 1 MiB and are not retained;
records, actors, parent counts and lineage depth have explicit limits.

## Pre-egress integration

`assess` takes an exact proposed `ActionEnvelope`, a configured sink ID and
`LineageUse` handles identifying UTF-8 parameter values. Each value must match
the recorded content hash and byte length, and the current actor must have
received the data through a protected handoff. The sink fixes action kind,
operation, destination parameter and exact destination; supported route classes
are network, MCP, tool and message. The host owns this route mapping and must
prevent a caller from selecting an allowlist or substituting destinations.

An established sensitive input sent to an unauthorized sink produces
`violated`. Missing input coverage, unknown classifications, unresolved
ancestry, graph truncation and unmodeled sinks produce `unknown`. Complete
public inputs and explicitly authorized sensitive destinations can produce
`satisfied`. These statuses describe a proposal and never establish that
exfiltration occurred.

Use `issue_assessment` with the protected `SwarmAssessmentSource`, current
gate policy digest and fresh `SwarmGate.evidence_snapshot_digest`. Configure
`source_flow` as a mandatory policy check, then pass the original receipt to
the existing gate/gateway before forwarding. A changed action, context, epoch
or snapshot cannot reuse the receipt; an absent or unknown mandatory check
uses the gate's deny/escalate policy. Core findings can only be strengthened.
The host must collect/check every mediated sink call and protect the assessment
issuer. A pure assessment never forwards the action or grants a broker permit.
New lineage records and declassifications fence earlier swarm receipts even
when the event snapshot itself has not changed.

For an existing Assurance `source_flow_guard`, `assurance_assessment` issues
a host receipt for the same selected profile and action. Pass it as
`lineage_assessment` to existing `assess_source_flow`. The additive argument
preserves existing exact-byte checks: an independent violation cannot be
removed by a safe lineage result. An incomplete lineage result cannot become
safe merely because no raw origin bytes were supplied.
Collect and assess afresh for each proposal. The existing Assurance receipt
contract authenticates a host assessment, without a live subscription to later
lineage changes; rotate the protected host epoch when changing policy and do
not reuse a past assessment as current collection evidence.

## Declassification and evidence

`declassify` requires the exact opaque operator capability, current policy
epoch, established complete input record, replacement labels and a bounded
reason code. It creates a new handle and appends a redacted audit record
binding the input digest, labels and epoch. It never mutates the original.
Policy advance, stale enrollment or host-source changes invalidate use.
Keep operator approval and the capability outside any model/tool argument.

`SourceFlowResult.as_dict` follows
[the versioned schema](../../schemas/swarm-source-flow.v1.schema.json).
Reports contain labels, digests and gap codes, without messages or secrets.
They explicitly state `execution_authority: false` and
`observed_exfiltration: unknown`. Audit exports are detached copies.

Opaque external tools, encrypted/uninstrumented channels, file paths with
unverified mutable contents and routes bypassing the gateway remain gaps.
This service does not infer complete taint tracking or physically constrain
uploads. File uploads require the broker to bind the actual bytes read to the
checked artifact version; a pathname alone is insufficient.
