# Swarm epic acceptance and evidence map

> Draft for the final, separate #255 evidence PR. This is a review structure,
> not a declaration that unfinished issues or future CI have passed. Replace
> pending entries only after verifying their final PR, head, checks and closure.
> Generate final acceptance reports after this PR merges; do not commit a report
> naming its own resulting HEAD.

The implementation is an opt-in safety control plane around existing agents.
It preserves deterministic local core review and keeps review, host mediation,
actual runtime observations, and inference distinct. A report, compiler result,
transport response or model claim never constitutes an execution permit.

## Five engineering gates

| Gate | Implementation and concrete verification | Evidence boundary |
| --- | --- | --- |
| 1 — Interception: SWARM-01–05,08 | Protected registry and original host channels; authenticated event sources; `SwarmGate`; gateway and maintained MCP/hook adapters; running-session attachment with original dispatcher verification. `tests/test_swarm_identity.py`, `test_swarm_events.py`, `test_swarm_gate.py`, `test_swarm_gateway.py`, `test_swarm_gateway_adapters.py`, `test_swarm_attach.py`. | Host/runtime sessions exist before attachment. The fixture verifies future mediated calls, not arbitrary process injection or retroactive history/confinement. Direct tools, sockets, credentials and executors remain explicit gaps. |
| 2 — Collective prevention: SWARM-06,07,09,11 | Protected causal graph and exact-byte source-flow handles; sensitivity joins and operator declassification; authenticated message grants, send/receive joins and temporal patterns. `test_swarm_graph.py`, `test_swarm_source_flow.py`, `test_swarm_messages.py`, `test_swarm_temporal.py`; installed two-agent custom fixture. | Secret-read → authenticated handoff → unauthorized final egress is refused at the mediated boundary; public controls remain available. Mere shared resources, timestamps, caller hypotheses or arbitrary transformed text do not prove data flow or successful exploitation. |
| 3 — Strong effects: SWARM-10,12–15 | Versioned artifact ACL/CAS/high-water labels; atomic ancestor/scoped budgets; original delegated rights/current mTLS; exact one-use broker binding; finite policy maxima and approved epoch reload. `test_swarm_memory.py`, `test_swarm_budgets.py`, `test_swarm_delegation*.py`, `test_swarm_broker.py`, `test_swarm_linux_executor.py`, `test_swarm_policy*.py`. | Actual kernel evidence covers the fresh owned Linux read-file worker only. Admission accounting is not a physical cap on opaque external billing. Unsupported request/prover/runtime domains refuse; policy apply/readback does not prove callback execution. |
| 4 — Multi-host operations: SWARM-16–20 | Actual PostgreSQL two-host quota/tenant tests, owner leases/fences, restart/partition/gaps; original owned-job cancellation and scoped recovery; exact human-credential approval/quorum; pinned SDK adapters and privacy-safe operator/audit surfaces. `test_swarm_coordinator*.py`, `test_swarm_containment*.py`, `test_swarm_operator_auth.py`, `test_operator_approval.py`, `test_swarm_approval.py`, `test_swarm_adapters*.py`, `test_swarm_operator*.py`. | One protected central service plus PostgreSQL transactions, not active-active consensus. SQLite is single-host/dev. Unknown in-flight effects retain holds and cannot resume from text/JSON. TLS establishes possession of enrolled credentials, not biometric presence. |
| 5 — Release evidence: SWARM-21,22 | Frozen verifier-grounded adversarial/benign controls, independent oracles, generated/fault cases, required kernel lane and bounded overhead/capacity measurement; strict installed wheel/code/resource parity; offline quickstart and separate owned runtime demo; versioned data-only release manifest, conformance matrix and operator runbook. | Labels and metrics retain their declared provenance, whole-corpus denominator, misses, unknowns, unsupported and uncovered states. Synthetic callbacks are not physical enforcement. Reference workflows/pins are not evidence that an external lane ran. Actual production expansion requires separate current operator authorization. |

Gate 4's adapter and observability implementations have merged through PR298
with their applicable CI green. The final combined-HEAD evidence audit remains
pending. The corpus implementation has merged through PR300 and release
readiness through PR301, completing Gate 5's implementation delivery. Final
combined-HEAD acceptance and the two post-epic local reports remain pending;
these merges do not themselves certify unmeasured external conformance. CrewAI is now
security-blocked by the separate PR299; no positive current CrewAI SDK coverage
or claim of two active maintained framework integrations is made.
SWARM-23 is optional for v1 enforcement; it is still part of this user's requested
issue queue and must receive its own verified PR before closing this task.

## All 23 implementation children

| Workstream / issue | Delivery | Main implementation / verification anchor | Current delivery evidence |
| --- | --- | --- | --- |
| 01 / #256 | Threat model, invariants, architecture | `docs/swarm/threat-model.md`, `architecture.md`, ADR and support matrix | [PR279](https://github.com/LatentOps/ordin/pull/279), merged; closure verified |
| 02 / #257 | Host-verified identity and registry | `ordin/swarm/models.py`, `registry.py`; `test_swarm_identity.py` | [PR280](https://github.com/LatentOps/ordin/pull/280), merged; closure verified |
| 03 / #258 | Authenticated events and ingestion | `events.py`, `ingest.py`, `journal.py`; `test_swarm_events.py` | [PR281](https://github.com/LatentOps/ordin/pull/281), merged; closure verified |
| 04 / #259 | Pure restrictive gate composition | `gate.py`, `facts.py`, `policy.py`; `test_swarm_gate.py` | [PR282](https://github.com/LatentOps/ordin/pull/282), merged; closure verified |
| 05 / #260 | MCP/hooks/SDK interception | `gateway.py`, optional MCP/hook adapters; gateway tests | [PR283](https://github.com/LatentOps/ordin/pull/283), merged; closure verified |
| 06 / #261 | Protected cross-agent causal graph | `causal_graph.py`; `test_swarm_graph.py` | [PR284](https://github.com/LatentOps/ordin/pull/284), merged; closure verified |
| 07 / #262 | Sensitive lineage and egress | `source_flow.py`; `test_swarm_source_flow.py` | [PR285](https://github.com/LatentOps/ordin/pull/285), merged; closure verified |
| 08 / #263 | Late attach and coverage | `attach.py`; `test_swarm_attach.py` | [PR286](https://github.com/LatentOps/ordin/pull/286), merged; closure verified |
| 09 / #264 | Inter-agent message gateway | `messages.py`; `test_swarm_messages.py` | [PR287](https://github.com/LatentOps/ordin/pull/287), merged; closure verified |
| 10 / #265 | Managed artifacts and memory | `memory.py`, `artifact_store.py`; `test_swarm_memory.py` | [PR288](https://github.com/LatentOps/ordin/pull/288), merged; closure verified |
| 11 / #266 | Causal temporal rules | `temporal.py`, `temporal_policy.py`; `test_swarm_temporal.py` | [PR289](https://github.com/LatentOps/ordin/pull/289), merged; closure verified |
| 12 / #267 | Transactional scoped budgets | `budgets.py`, `budget_store.py`; `test_swarm_budgets.py` | [PR290](https://github.com/LatentOps/ordin/pull/290), merged; closure verified |
| 13 / #268 | Online delegation and credentials | `workload_auth.py`, `delegation.py`, `credential_broker.py`; delegation tests | [PR291](https://github.com/LatentOps/ordin/pull/291), merged; closure verified |
| 14 / #269 | Exact-action enforcing broker | `authorization.py`, `broker.py`, `linux_backend.py`, `_file_worker.py`, lazy OpenShell bridge | [PR292](https://github.com/LatentOps/ordin/pull/292), merged; closure verified |
| 15 / #270 | Data-only policy and epoch reload | `policy_set.py`, `policy_compiler.py`, `policy_runtime.py`; policy/factory tests | [PR293](https://github.com/LatentOps/ordin/pull/293), merged; closure verified |
| 16 / #271 | Durable multi-host coordinator | `coordinator.py`, `coordinator_store.py`, `coordinator_rpc.py`; real PG/restart/fault tests | [PR294](https://github.com/LatentOps/ordin/pull/294), merged; closure verified |
| 17 / #272 | Scoped containment and recovery | `incident.py`, `containment.py`, exact actor/action fence and owned-stop tests | [PR295](https://github.com/LatentOps/ordin/pull/295), merged; closure verified |
| 18 / #273 | Human-credential approval and governance | `ordin/approval.py`, swarm approval service/operator auth/CLI; original live-witness/kernel tests | [PR296](https://github.com/LatentOps/ordin/pull/296), merged; closure verified |
| 19 / #274 | Maintained framework adapters | optional `sdk.py`, adapters, typed data bridge; installed actual SDK fixtures and packaging | [PR297](https://github.com/LatentOps/ordin/pull/297), merged as `f83a0a8882e7d7c50bdb131bc1bdfc0ea3f4201f`; all 40 required and all 61 observed statuses green; closure verified. Current CrewAI availability is superseded by PR299 quarantine. |
| 20 / #275 | Audit/operator API/observability | `audit.py`, `diagnostics.py`, `operator_api.py`, `operator_cli.py`; protected privacy/governance/export tests | [PR298](https://github.com/LatentOps/ordin/pull/298), merged as `b88161669f940e5cb1a111c1d4ad3b3d644756cc`; all 40 required and all 61 observed statuses green; closure verified. |
| 21 / #276 | Corpus, oracles, properties and overhead | `benchmark.py`, `corpus_controls.py`, `corpus_kernel.py`, `overhead_benchmark.py`; corpus/fault/property/oracle tests | [PR300](https://github.com/LatentOps/ordin/pull/300), merged as `85e5b458871b92a27065ea0284d13e6bbaef133c`; 41 unique successful jobs, 61 successful observed check runs and only two not-applicable tag skips out of 63 total; closure verified. |
| 22 / #277 | Packaging, conformance and release evidence | optional `quickstart.py`, `owned_demo.py`, release-evidence producer/runner, schemas, workflows/runbook | [PR301](https://github.com/LatentOps/ordin/pull/301), merged as `5c29527d697ea28a30a445c19b6e00c81547d66c`; 43 unique successful jobs, 65 successful observed check runs and only two not-applicable tag skips out of 67 total; closure verified. |
| 23 / #278 | Optional semantic risk signals | Pending #278 source checkpoint: risk-signal provider and semantic adapter with default-off/privacy/calibration/timeout/currentness/approval-join tests; intentionally absent from the verified #277 checkout | Pending separate final PR/CI/merge; not a v1 enforcement dependency |

Use the final ledger for exact merge SHA and all check URLs. The initial PRs
were guarded by the then-applicable complete matrix; later matrices add actual
PostgreSQL, installed SDK, corpus and release lanes. Do not retrospectively claim
that a newer lane ran on an older implementation commit.

Read-only anchor verification against the integrated #277 checkout at
`454caab0822558ec07049153801d7e83bcaad5b7` found all 72 current implementation,
test and documentation anchors. The future optional #278 source is deliberately
not used as an existing #277 anchor. The five workstream ranges above match the
epic's exact engineering-gate map. This path-presence check is not a test result
or a final-HEAD acceptance claim; repeat/update it after #278 and the epic PR.

### Subsequent dependency security quarantine

[PR299](https://github.com/LatentOps/ordin/pull/299) merged as
`e0178728597b7f08a5b5ed259083ed1ecbc897b1` after all 40 required checks and
all 61 observed statuses passed. It removes the active CrewAI extra, lock and
provisioning path and blocks adapter construction, installation, setup and demo
before SDK imports, including matching externally installed versions. Its
mandatory negative installed lane reports `security_blocked`, false compatibility
and no covered paths. Existing old loaded code requires operator fencing/draining
and restart; a package update is not retroactive process control.

The required ChromaDB dependency had four new critical/high advisories and no
published patched release. This change removes Ordin's active exposure; it does
not patch ChromaDB or convert a negative refusal test into positive CrewAI
conformance. The post-merge dependency refresh returned zero open alerts without
any dismissals. Refresh again at final delivery; do not reuse this point-in-time
result as a promise about future advisories. Active maintained SDK claims cover
LangGraph; AutoGen remains explicitly archived-version compatibility. Historical
CrewAI workflow passes remain evidence for their original revision only.

## Epic definition-of-done audit

- [ ] Verify running-session enrollment/coverage and future-call denial from the
  final installed candidate; retain prior-history and raw-path gaps.
- [ ] Verify private lineage → handoff → refused final egress and matched benign
  controls with actual original sources, separately from inference.
- [ ] Verify concurrent quota and exact action/actor/generation/epoch/one-use
  fences; retain ambiguous holds and reject copied/caller-constructed receipts.
- [ ] Verify sibling cannot impersonate workload/operator/collector credentials
  or turn model `approved`/`completed` into authority or host observation.
- [ ] Verify observer limitations, supported original broker/kernel result and
  separately successful uncovered bypass; show unsupported/restart-required paths.
- [ ] Record per-class false allows, false blocks, approvals, coverage, revocation
  and overhead with declared denominators/environments; unknown is not success.
- [ ] Verify all 23 child issues closed by the intended separate merged PRs and
  every applicable final-head CI check passed before each squash merge.
- [ ] Verify no open task-scoped issues/PRs or unresolved Dependabot alerts remain;
  distinguish superseded dependency PR closure from a successful merged upgrade.

## Evidence record and report generation

For each final gate, record: implementation commit and Git tree, exact installed
wheel SHA-256s and code/resource parity, immutable dependency pins/lock hashes,
OS/kernel/Python/SDK versions, test command/result, expected versus observed
boundary, report artifact digest, and limitations. An identical-tree ancestry
rebase may cite its original tested commit plus both verified tree hashes; a
runtime-code change requires affected checks rerun. Skips need explicit reasons.

After this epic PR merges, create two NEW durable local artifacts against the
exact final main HEAD: implementation/coverage acceptance and verification/CI
evidence. Use a clean final checkout, not the user's dirty working branch.
Never overwrite existing user reports or commit those final-HEAD reports and
change HEAD again. Reports should link this evidence map and actual CI artifacts.

Record synthetic review, simulated/host callback mediation, original physical
runtime results, and optional model calibration as separate categories. Keep
nonzero calibration errors, optional unmeasured cases, unknown histories and
uncovered paths visible. Local gate success does not certify all external
conformance lanes or general production enforcement.

## Explicit operating limits

- No orchestrator replacement, automatic process takeover, retroactive clean
  history, blanket OS enforcement or hosted collector by default.
- Actual finite enforcing route is the owned fresh Linux read-file worker;
  existing unwrapped processes, credentials, sockets and handles remain outside it.
- Applied policy/compilation/readback is not evidence an arbitrary tool executed.
  Unsupported request/prover/runtime projections never widen into raw TCP.
- One central PostgreSQL authority is not active-active consensus; SQLite is
  development/single-host. Outage, stale leases and lost original evidence remain
  closed/unknown rather than restoring grants from persisted report data.
- No atomic undo, automatic non-idempotent replay or uncapped external billing
  guarantee. Recovery requires current operator standing, fresh fences and actual
  original outcome reconciliation; old approvals and grants remain invalid.
- SDK claims name tested versions/paths only; AutoGen is explicitly legacy
  compatibility. CrewAI is security-blocked pending a verified patched dependency
  closure and new positive conformance checks. The mandatory quarantine lane is
  negative evidence, not an available second maintained framework. Async, direct,
  injected and unwrapped paths stay reported gaps.
- Optional inference can only tighten under operator policy. Default-off must
  preserve core output and configuration digests; scores never issue identity,
  approval, completion or causal facts. Calibration is limited, independently
  reported and not a claim of general prompt-injection prevention.

The final owner must replace this draft's pending statuses and unchecked boxes
using actual evidence before issuing the epic completion PR or closing #255.
