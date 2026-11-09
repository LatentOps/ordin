# Private swarm operations

The host can explicitly attach a private audit journal and an authenticated
operator endpoint to original coordinator, gate, broker and containment objects.
Imports start no service and send no telemetry. The core package has no telemetry
dependency. The optional `ordin-swarm[telemetry]` extra supports explicit local
OpenTelemetry SDK exports. OCSF export works without that extra or Ordin Runtime.

## Host configuration and custody

Create `SwarmAuditJournal(path, key=key, tenant_id=tenant, operator=bootstrap,
clock=coordinator.clock, create=True)` once in an owner-only directory. Supply a
cryptographically random key of at least 32 bytes from protected host storage.
Keep the key, bootstrap capability, operator TLS private keys and journal outside
workload/model access. Do not put them in agent configuration or reports. Use the
same key to reopen that tenant journal with `create=False`; a missing, wrong-key
or damaged journal requires explicit investigation, never automatic reset.
Key rotation creates a separate journal/domain with a separately retained anchor;
it does not silently rewrite old identities. Database owner permissions are an
access boundary, not encryption or protection against the machine owner.

Bind `SwarmAuditSource(journal, coordinator, scope, control=control,
operator=bootstrap, containment=controller)` to the original components. It
automatically observes that scope's configured original gates and brokers. Bind
other standalone gates explicitly with `gate.bind_audit(source,
operator=bootstrap)`. The source requires the original coordinator DB clock and
one exact tenant/swarm/task scope. Independent raw/unwrapped routes remain
uncovered. Stop producers, call `flush(operator=bootstrap, timeout=5)` and then
`close(operator=bootstrap)` during orderly shutdown; check both results.

For causal evidence, explicitly call `source.bind_causal_graph(original_graph,
operator=bootstrap)`. This also captures redacted message metadata only after the
original event ingestor commits it. Supplied JSON graphs, caller assertions and
model risk cannot issue protected host evidence. An unconfigured, stale,
incomplete, foreign-task or truncated causal source is reported as a gap. A
causal review candidate requires exact actor/session/action/epoch correlation to
an original deterministic gate review and explicit protected parent edges.
Delegation ancestry and timestamps alone are not data-flow edges. Candidate
paths end at reviewed intent; successful exploitation remains `unknown`.

Configure a `SwarmOperatorDirectory` with pinned actual operator certificates,
finite roles and explicit task grants, then construct
`SwarmOperatorAPI(directory, (source,), operator=bootstrap, governance=service)`.
The host owns the mutually authenticated TLS listener and calls `serve_one` on
an accepted verified server socket. No discovery or listener starts implicitly.
Deployments own TLS certificate issuance, revocation and listener access.
Certificate possession authenticates the enrolled credential; TLS cannot prove
human presence or that two credentials belong to different people.

| Operation | Required role and boundary |
| --- | --- |
| list/status/graph/explain/incidents/policy/coverage | `observe`, exact task |
| export | `export`, exact task; no raw-data mode |
| pause/revoke | matching control role, current TLS/RBAC, exact agent/task |
| swarm-wide pause/revoke | additionally explicit `swarm-control` task grant |
| sweep | `retain`, exact task; bounded artifact scan |
| approve/deny | matching role plus actual governance policy/quorum/currentness |

Pause/revoke publish the original durable containment fence before asynchronous
cleanup. They do not wait for an in-flight native execution barrier. A fence
prevents new admissions; it does not prove an already started effect stopped.
Status retains `unknown`/`unable_to_stop` outcomes where appropriate. Approval
uses the original [human governance](approval.md) service and its current proof,
epoch, quorum, TTL and one-use execution path. The wire returns HMAC references,
never live approval or execution handles. Recovery approvals remain in protected
server memory and are consumed through the original governance resume ceremony.

## CLI and local dashboard

All live commands require an explicit host, port, CA and operator certificate/key:

```bash
ordin swarm status --host localhost --port 9443 --ca ca.pem --cert operator.pem --key operator-key.pem --json
ordin swarm graph --host localhost --port 9443 --ca ca.pem --cert operator.pem --key operator-key.pem --json
ordin swarm export --host localhost --port 9443 --ca ca.pem --cert operator.pem --key operator-key.pem --output audit.json --json
```

Use `--scope-ref hmac:...` when the endpoint exposes multiple scopes. `explain`
requires `--action-ref hmac:...`. `pause`/`revoke` require `--scope-kind
agent --actor-ref hmac:...` or the explicitly authorized task/swarm scope.
`approve`/`deny` require the queue's `--request-ref` and a bounded
`--idempotency-key`. The client never retries effects automatically.

`status --report snapshot.json` and `dashboard --report snapshot.json --output
console.html` read a previously exported snapshot. Offline reports explicitly
clear live-source/online claims and cannot authorize controls. The dashboard is
static escaped HTML/SVG with no script, network service, forms or control stream.
Its downloadable incident snapshot remains diagnostic data, never a permit.

Convert a redacted audit bundle locally with an explicit format:

```bash
ordin swarm export --report audit.json --format ocsf --output findings.json --json
ordin swarm export --report audit.json --format otel --output spans.json --json
ordin swarm audit verify --report audit.json --checkpoint checkpoint.json --json
```

OTel uses a private, non-global provider and an explicitly supplied exporter.
The CLI's exporter only captures bounded JSON locally. It does not install a
global provider, read environment resource attributes, discover exporters or
send traffic. The SDK API `export_swarm_spans(bundle, exporter)` sends only to
the exporter the host explicitly supplied. Treat all exported spans and OCSF
findings as diagnostic data. Capture spans are zero-duration timestamps, not
measured action durations. Actor/task/session/action/tool/message/policy
references are tenant-domain HMACs; no raw actions, prompts, messages,
credentials, proprietary paths or URLs enter default output. Tool metadata is
derived from the original reviewed action's kind, operation, adapter and declared
tool identifiers, excluding arguments and payloads. OTel JSON is a
local capture format, not a claim of OTLP delivery or enforcement evidence.

## Integrity, loss and retention

`journal.checkpoint(operator=bootstrap)` returns a tail checkpoint. Store it
independently under a trusted operator's custody before relying on it to detect
subsequent edits, truncation or reordering. Hash-chain verification proves
consistency with the supplied checkpoint under those custody assumptions.
A journal owner with the privacy key can forge an unanchored local history; a
checkpoint supplied by the same attacker supplies no independent trust. An
anchor older than retained history is explicitly unverifiable. Verification
never proves that every execution path was instrumented or that an effect was
successful. Legacy audit/trace imports remain diagnostic even if their chains
and separately retained checkpoints verify.

The writer queue is bounded (at most 256 records); it performs no journal I/O
under enforcement locks. It commits ordered batches of at most 32 records,
validating the existing chain once per atomic batch and every new event before
commit. A failed batch leaves no partial journal tail. Overflow, unavailable storage and pending flushes are
explicit gaps in operator snapshots and capture status in API audit exports.
Transport-limited exports retain a verifiable suffix and explicitly flag the
truncated export window; keep independently held earlier bundles/checkpoints.
A valid chain can coexist with missing capture. Failures never create approvals,
erase uncertain outcomes or turn a core denial into an allow. Recovery after a
sink failure requires explicit host action and fresh collection; lost events
cannot be reconstructed from a clean tail. `record_risk` requires the protected
host source and remains data-only diagnostic input, with no optional risk plugin
dependency and no control or approval authority.

`SwarmAuditPolicy` bounds retained event count, age and distinct pseudonyms;
cardinality pressure trims the oldest prefix while preserving the base anchor,
monotonic sequence and tail. `sweep --maximum-resources 256` requires retention
RBAC and journals a durable artifact-retention intent before backing cleanup.
Cleanup is scoped to the exact tenant/swarm/task and preserves replay IDs,
label floors, version high-water marks and tombstones. Partial cleanup or a lost
acknowledgement retains a durable pending hold for explicit reconciliation.
It does not restore authority or claim secure erasure of backing storage,
backups, caches or previously exported files. See [artifact boundaries](artifacts.md)
and [coverage limitations](support-matrix.md).
