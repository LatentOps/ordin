# Swarm safety v1 acceptance and evidence

All 23 implementation issues #256–#278 have been delivered through separate
merged PRs. This document records their engineering gates, verification scope
and operating limits. Epic #255 completion also requires the dependency
publication check below and the post-merge delivery steps.

The implementation is an opt-in safety control plane around existing agents.
Deterministic core review, host mediation, authenticated runtime observations
and optional inference retain separate authority. Reports and model output
cannot grant identity, approval, execution permission or completion evidence.

## Engineering gates

| Gate | Implementation and concrete verification | Evidence boundary |
| --- | --- | --- |
| 1 — Interception: SWARM-01–05,08 | Protected registry and original host channels; authenticated event sources; `SwarmGate`; gateway and maintained MCP/hook adapters; running-session attachment with original dispatcher verification. `tests/test_swarm_identity.py`, `test_swarm_events.py`, `test_swarm_gate.py`, `test_swarm_gateway.py`, `test_swarm_gateway_adapters.py`, `test_swarm_attach.py`. | Host/runtime sessions exist before attachment. The fixture verifies future mediated calls, not arbitrary process injection or retroactive history/confinement. Direct tools, sockets, credentials and executors remain explicit gaps. |
| 2 — Collective prevention: SWARM-06,07,09,11 | Protected causal graph and exact-byte source-flow handles; sensitivity joins and operator declassification; authenticated message grants, send/receive joins and temporal patterns. `test_swarm_graph.py`, `test_swarm_source_flow.py`, `test_swarm_messages.py`, `test_swarm_temporal.py`; installed two-agent custom fixture. | Secret-read → authenticated handoff → unauthorized final egress is refused at the mediated boundary; public controls remain available. Mere shared resources, timestamps, caller hypotheses or arbitrary transformed text do not prove data flow or successful exploitation. |
| 3 — Strong effects: SWARM-10,12–15 | Versioned artifact ACL/CAS/high-water labels; atomic ancestor/scoped budgets; original delegated rights/current mTLS; exact one-use broker binding; finite policy maxima and approved epoch reload. `test_swarm_memory.py`, `test_swarm_budgets.py`, `test_swarm_delegation*.py`, `test_swarm_broker.py`, `test_swarm_linux_executor.py`, `test_swarm_policy*.py`. | Actual kernel evidence covers the fresh owned Linux read-file worker only. Admission accounting is not a physical cap on opaque external billing. Unsupported request/prover/runtime domains refuse; policy apply/readback does not prove callback execution. |
| 4 — Multi-host operations: SWARM-16–20 | Actual PostgreSQL two-host quota/tenant tests, owner leases/fences, restart/partition/gaps; original owned-job cancellation and scoped recovery; exact human-credential approval/quorum; pinned SDK adapters and privacy-safe operator/audit surfaces. `test_swarm_coordinator*.py`, `test_swarm_containment*.py`, `test_swarm_operator_auth.py`, `test_operator_approval.py`, `test_swarm_approval.py`, `test_swarm_adapters*.py`, `test_swarm_operator*.py`. | One protected central service plus PostgreSQL transactions, not active-active consensus. SQLite is single-host/dev. Unknown in-flight effects retain holds and cannot resume from text/JSON. TLS establishes possession of enrolled credentials, not biometric presence. |
| 5 — Release evidence: SWARM-21,22 | Frozen verifier-grounded adversarial/benign controls, independent oracles, generated/fault cases, required kernel lane and bounded overhead/capacity measurement; strict installed wheel/code/resource parity; offline quickstart and separate owned runtime demo; versioned data-only release manifest, conformance matrix and operator runbook. | Labels and metrics retain their declared provenance, whole-corpus denominator, misses, unknowns, unsupported and uncovered states. Synthetic callbacks are not physical enforcement. Reference workflows/pins are not evidence that an external lane ran. Actual production expansion requires separate current operator authorization. |

These gates cover the documented finite implementation and fixtures. Current
maintained framework coverage includes LangGraph. AutoGen is archived legacy
compatibility; CrewAI is security-blocked. No claim of two currently available
maintained framework integrations is made. Optional SWARM-23 is delivered, while
v1 enforcement remains independent of inference.

## Implementation deliveries

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
| 19 / #274 | Maintained framework adapters | optional `sdk.py`, adapters, typed data bridge; installed actual SDK fixtures and packaging | [PR297](https://github.com/LatentOps/ordin/pull/297), merged as `f83a0a8882e7d7c50bdb131bc1bdfc0ea3f4201f`; 40 unique successful jobs, 59 observed successful checks and two inapplicable tag-only skips out of 61 total; closure verified. Current CrewAI availability is superseded by PR299 quarantine. |
| 20 / #275 | Audit/operator API/observability | `audit.py`, `diagnostics.py`, `operator_api.py`, `operator_cli.py`; protected privacy/governance/export tests | [PR298](https://github.com/LatentOps/ordin/pull/298), merged as `b88161669f940e5cb1a111c1d4ad3b3d644756cc`; 40 unique successful jobs, 59 observed successful checks and two inapplicable tag-only skips out of 61 total; closure verified. |
| 21 / #276 | Corpus, oracles, properties and overhead | `benchmark.py`, `corpus_controls.py`, `corpus_kernel.py`, `overhead_benchmark.py`; corpus/fault/property/oracle tests | [PR300](https://github.com/LatentOps/ordin/pull/300), merged as `85e5b458871b92a27065ea0284d13e6bbaef133c`; 41 unique successful jobs, 61 successful observed check runs and only two not-applicable tag skips out of 63 total; closure verified. |
| 22 / #277 | Packaging, conformance and release evidence | optional `quickstart.py`, `owned_demo.py`, release-evidence producer/runner, schemas, workflows/runbook | [PR301](https://github.com/LatentOps/ordin/pull/301), merged as `5c29527d697ea28a30a445c19b6e00c81547d66c`; 43 unique successful jobs, 65 successful observed check runs and only two not-applicable tag skips out of 67 total; closure verified. |
| 23 / #278 | Optional semantic risk signals | `ordin/swarm/risk_signals.py`, optional `semantic_signals.py`, `docs/swarm/risk-signals.md`; `test_swarm_risk_signals.py`, `test_swarm_risk_approval_join.py`, `test_swarm_risk_corpus_contract.py`, `test_swarm_risk_diagnostics.py` | [PR313](https://github.com/LatentOps/ordin/pull/313), merged as `9639378571fcab450df8e610c36fa69192e832f9`; 43 unique successful jobs, 65 successful observed check runs and only two not-applicable tag skips out of 67 total; closure verified. Default-off inference can tighten only; not a v1 enforcement dependency. |

Each implementation PR passed its applicable complete CI matrix before squash
merge. The matrix grew as PostgreSQL, real SDK, corpus and installed release
lanes were introduced. Later lanes are not attributed to earlier commits.
Successful observed checks and inapplicable tag-only skips are distinguished
in the receipts.

## Dependency and compatibility deliveries

CodeQL [PR302](https://github.com/LatentOps/ordin/pull/302) merged as
`025db68b11ef4ccb6493ad5e3ff53513887fd66d` after all 43 unique applicable jobs
and 43 observed successful check runs passed, with only the two inapplicable
tag-only skips out of 45 total. Exact release validation was run 42199682108.
Development-tool [PR305](https://github.com/LatentOps/ordin/pull/305) merged as
`c265203a9d77472b4fe3da4775de2f1e82464853` after 43 unique and 43 observed
successful jobs, with only two inapplicable tag skips out of 45 total. The guard
also inspected 48 exact-head check runs and successful dispatched release
42202656328. Main's exact versions were verified: pytest 9.2.0, filelock 4.2.7,
Ruff 0.17.3, pluggy 1.7.0 and nodeenv 1.12.0. PR306/PR310/PR311/PR312 were closed
as superseded after their requested upgrades were verified in this merge;
those proposals were not themselves merged or ignored.

Solver [PR308](https://github.com/LatentOps/ordin/pull/308) merged as
`cde1103d3e83a563355684890d2ad8bf4b58bc75` after 43 unique and 43 observed
successful jobs, with only two inapplicable tag skips out of 45 total. The guard
also inspected 48 exact-head check runs and successful dispatched release
42204540750. The four finite solver lanes and both decision-model acceptance
lanes ran the new Z3 5.3.3.0; the old acceptance workflow pin and current prose
were synchronized, while historical artifact records were preserved.

Paired Pydantic/core [PR307](https://github.com/LatentOps/ordin/pull/307) merged as
`7ba08e4551faae6add296d28129f98f69342f522` after all 43 required jobs and the
additional Dependabot configuration check passed: 44 observed successful check
runs plus two inapplicable tag skips out of 46 total, with 49 exact-head checks
and successful dispatched release 42207507412. Both merged SDK locks were
verified to contain Pydantic 2.14.2 and core 2.50.2. PR303/PR309 were closed as
superseded only after the coupled update merged; those proposals were not
themselves merged or ignored.

**AutoGen compatibility boundary** ([PR304](https://github.com/LatentOps/ordin/pull/304)) merged as
`a6c2272d78275db36e9818f4a1b2f6e7b0791fff` after all 43 required jobs and every additional observed check passed: 43 observed successful checks and two inapplicable tag-only skips out of 45 total, with 48 exact-head checks and successful dispatched release 42209840656. Retains protobuf 5.29.6 under the real archived SDK constraint, with explicit upstream EOL and no maintained/patched-closure claim. This is a compatibility correction, not a major-version upgrade or security patch.

**Tools and updater consolidation** ([PR315](https://github.com/LatentOps/ordin/pull/315)) merged as
`6b288cfd2269585dc0fa5de081ab7703455a00c6` after all 43 required jobs and every additional observed check passed: 44 observed successful checks and two inapplicable tag-only skips out of 46 total, with 49 exact-head checks and successful dispatched release 42214395148. Delivers Mypy 2.4.1, virtualenv 21.15.2, python-discovery 1.9.2 and certifi 2026.10.23. One pip updater retains both prior scan directories and cadence; the inseparable Pydantic group precedes generic per-dependency version grouping. Live GitHub configuration validation passed.

**LangGraph UUID compatibility boundary** ([PR314](https://github.com/LatentOps/ordin/pull/314)) merged as
`4a3fb967ce6434bfccdad452e4e51d72e24d3aed` after all 43 required jobs and every additional observed check passed: 44 observed successful checks and two inapplicable tag-only skips out of 46 total, with 49 exact-head checks and successful dispatched release 42216020279. Retains UUID Utils 0.19.0 under current LangSmith's required range. Normal extra resolution, actual LangGraph controls, lock regeneration and a rejected 1.2.0 dry-run verify the boundary; this does not claim a 1.2.0 upgrade.

**Interpreter-compatible parser update** ([PR323](https://github.com/LatentOps/ordin/pull/323)) merged as
`35aea7dae341dd8a6e8fcb8781c4d2d957941c19` after all 43 required jobs and every additional observed check passed: 43 observed successful checks and two inapplicable tag-only skips out of 45 total, with 48 exact-head checks and successful dispatched release 42220398229. The original Linux/implementation exclusions remain unchanged. Hash-pinned pycparser 3.11 serves Python 3.10; 3.12 serves Python 3.11+. Both actual Linux interpreter lanes passed resolution and CFFI controls, with all hooks and the full current-tool suite passing on Python 3.12.

PR316/PR319/PR321 were superseded only after their exact versions were verified in merged PR315. Duplicate tracking PRs317/318/320 remained linked to their primary work, and repeated grouped proposals322/324 were answered by the already-merged compatibility boundaries. These closures are distinct from merged upgrades and grant no CI credit. No ignore rule, advisory dismissal, scan-path removal or gate waiver is used.

The complete dependency publication inventory at 2026-11-06T13:01:57.512541+00:00 records only epic255 still open, no open PRs and zero open Dependabot alerts. The implementation source is `35aea7dae341dd8a6e8fcb8781c4d2d957941c19`, tree `2beea40fc56b91479f74068a468a0407b8e12608`; this evidence document adds only documentation. Final reports bind the post-epic main commit separately.

### CrewAI quarantine and legacy AutoGen

[PR299](https://github.com/LatentOps/ordin/pull/299) merged as
`e0178728597b7f08a5b5ed259083ed1ecbc897b1` after all 40 then-required job names and 59 observed successful checks passed,
with only two inapplicable tag-only skips out of 61 total. It removes the active CrewAI extra,
dependency lock and provisioning path. Construction, installation, setup and
demos refuse before SDK import, including matching externally installed
versions. The mandatory quarantine lane reports `security_blocked`, false
compatibility and no covered paths.

CrewAI's required ChromaDB dependency had four unresolved critical/high
advisories and no published patched closure at review. Quarantine removes
Ordin's active installation and adapter exposure. It supplies no upstream patch.
Historical positive CrewAI fixtures do not establish current availability.
Already loaded code requires original operator fencing, draining and restart.
Updating a package cannot retroactively control an old process.

AutoGen Core 0.7.5 is explicitly archived compatibility. Its
[upstream dependency metadata](https://pypi.org/pypi/autogen-core/0.7.5/json)
requires `protobuf~=5.29.3`, which admits the retained 5.29.6 lock and excludes
protobuf 7.x. Protobuf Python 5.x
[reached upstream end of support on 31 March 2026](https://protobuf.dev/support/version-support/#python).
The legacy fixture, hashes and compatible installation do not
establish upstream maintenance, a patched dependency closure or security
clearance. The release manifest keeps `dependency_security_clearance` at
`not_established`.

## Acceptance criteria

The implementation fixtures and installed gates establish the following
bounded criteria:

- [x] Original host enrollment, coverage inventory and future-call denial;
  pre-attachment history and unmediated routes remain explicit gaps.
- [x] Protected private lineage, authenticated handoff and refused final egress,
  with matched benign controls and exact original sources.
- [x] Concurrent quota accounting and exact action, actor, generation, epoch
  and one-use fences; uncertain effects retain their holds.
- [x] Workload/operator/collector impersonation controls and refusal of copied
  or model-produced authority and completion claims.
- [x] Observer limitations, original supported broker/kernel completion and
  independently successful uncovered bypass controls.
- [x] Declared metric denominators, false allows/blocks, approvals, coverage,
  revocation and overhead, retaining unknown and unsupported outcomes.
- [x] All 23 child issues closed through their intended separate merged PRs
  after the applicable complete CI passed.
- [x] At publication, verify all child issues and task-scoped dependency/fix
  PRs are closed or merged, with no unresolved Dependabot alerts. This check
  excludes #255 and its still-open epic review PR. Record superseded closures
  separately from successful merged upgrades.

The current tools/CA tuple and interpreter-compatible parser have fresh hash-locked
validation. The actual Linux Python 3.10 lane selects pycparser 3.11 and passes
its CFFI controls and 16 core/schema/onboarding/quarantine tests. Python 3.12
selects pycparser 3.12, passes all seven quality hooks and the full suite:
2,902 passed with 53 expected skips and Z3 5.3.3.0 available. Unchanged application
and calibration bytes retain their independently recorded source hashes. Individual real
SDK, PostgreSQL, kernel, corpus and packaging gates
retain their own source, environment and result records. The final epic
candidate must match the verified implementation tree and pass its applicable
branch, dispatched release and PR gates before squash merge.

## Post-merge delivery

After the epic PR merges and #255 closes:

1. Refresh all task-scoped issues, PRs and dependency alerts, including the
   epic itself, and record the resulting state.
2. From a clean checkout of the exact final main commit, generate two new
   durable local reports: implementation/coverage acceptance and
   verification/CI evidence.
3. Record the final commit and Git tree, wheel SHA-256s, installed code/resource
   parity, dependency pins and lock hashes, OS/kernel/Python/SDK versions,
   commands/results, artifact digests, CI/run links and material limits.

These reports are generated after the last merge and are not committed.
Existing user reports are preserved. Report generation and the final zero-open
refresh are separate delivery steps; an open epic PR does not claim them
complete. Identical implementation trees may cite the tested source and the
verified equivalence, while changed runtime code requires affected checks
again. Expected skips keep explicit reasons.

Synthetic review, caller-owned callback mediation, original physical runtime
results and optional model calibration remain separate evidence categories.
Nonzero calibration errors, unmeasured optional lanes, unknown histories and
uncovered routes stay visible. A local gate does not establish unrun external
conformance or general production enforcement.

## Operating limits

- Existing agents and orchestrators remain caller-owned. There is no automatic
  process takeover, blanket OS enforcement or hosted collector by default.
- The finite physical executor is the owned fresh Linux read-file worker.
  Existing unwrapped processes, credentials, sockets and handles remain
  outside that boundary.
- Compilation, policy apply and readback do not establish arbitrary execution.
  Unsupported request/prover/runtime projections cannot widen into raw TCP.
- The durable coordinator uses one central PostgreSQL authority; SQLite is for
  single-host development. Outages, stale leases and missing original evidence
  retain closed or unknown outcomes. Persisted reports cannot restore grants.
- Recovery requires current operator authority, fresh fences and original
  outcome reconciliation. It cannot guarantee atomic undo, safe replay of
  non-idempotent effects or a physical cap on uncapped external billing.
- SDK claims name exact tested versions and routes. CrewAI remains blocked;
  AutoGen remains legacy with the documented EOL dependency. Async, injected,
  direct and unwrapped routes retain their declared gaps.
- Optional inference can only tighten under operator policy. Default-off
  preserves core output and configuration digests. Scores cannot issue
  identity, approval, completion or causal facts. Calibration remains limited
  and does not establish general prompt-injection prevention.

Implementation contracts and operational procedures are in
`docs/swarm/support-matrix.md`, `docs/swarm/conformance.md`,
`docs/swarm/framework-adapters.md`, `docs/swarm/operator-runbook.md` and
`docs/swarm/release-evidence.md`.
