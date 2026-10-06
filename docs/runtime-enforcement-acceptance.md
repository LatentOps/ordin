# Runtime enforcement implementation acceptance

This audit covers the full runtime-enforcement plan, including core contracts,
the optional OpenShell adapter, evidence return, proposals, shadow evaluation,
explicit apply, documentation, adversaries, performance, and packaging. A unit
fixture is not recorded as actual kernel enforcement.

The original pre-`#199` gate below is historical evidence for implementation
source `8dc27db112af6347a42f8184d2a4468324f8a4c8`, validated from working-file snapshot
`9dca50a6c212f33716d3536094b221d234b07641202225b44fb76900fd0c5c67`.
It does not establish current-HEAD validation. The [acceptance JSON](reports/runtime-enforcement-acceptance.json)
records the source revision of its results; regenerate the report pair after
the final source commit to bind current validation to that exact HEAD.
Core version remains `0.4.0.dev0`, with zero required runtime dependencies;
the separately packaged integration is `0.1.0`.

## Requirements and evidence

| Plan phase / requirements | Implementation and verification |
| --- | --- |
| Constraints and inspection (1–4) | [Design](design/runtime-enforcement-integration.md), unchanged legacy v1 contracts and frozen v0.3 inventory; no required dependencies, hosted inference, telemetry, credential discovery, or runtime lifecycle in core. Optional runtime management has a separate package. Full regression, privacy, namespace, and workflow-security checks passed. |
| 1: versioned capability contract (5–9) | [Contract and derivation](../ordin/runtime_contract.py), root/package schema parity, immutable nested values, canonical action binding, explicit missing/malformed/unknown semantics. [Contract tests](../tests/test_runtime_contract.py) exercise deterministic/no-I/O derivation, typed effects/resources, credentials, bounds, round trips, and old execution-profile behavior. Explicit [deployment requirements](../ordin/runtime_requirements.py) retain host-supplied startup facts and session identity without replacing semantic effects or decisions. |
| 2: runtime evidence (10–15) | [Observation contract](../ordin/runtime_observation.py), [additive reasoning](../ordin/runtime_reasoning.py), retained original contracts and reset/session identity in [sessions](../ordin/session.py). [Tests](../tests/test_runtime_observation.py) cover all trust levels, mismatch/replay, persistence, denied secret reads, repeated exact-target denials, privileged alternatives, preserved prediction, and provenance. Ordinary JSON cannot restore strong labels. |
| 3: generic backend protocol (16–17) | [Protocol/models](../ordin/enforcement_backend.py) expose compile/validate only. [Tests](../tests/test_enforcement_backend.py) cover plan identity, immutable data, diagnostic/non-executable cases and unsupported fields. There is no action-execution/apply method in the core protocol. |
| 4: optional compiler/package (18–21) | [Separate package](../integrations/openshell/pyproject.toml), [compiler](../integrations/openshell/ordin_openshell/compiler.py), structured JSON/optional safe YAML, explicit UID/GID/binary bindings, no wider base-policy merge. [Golden and negative tests](../integrations/openshell/tests/test_compiler.py) check semantic mappings, unsupported rights/protocols/tools, private-address expansion, missing identities, wildcards, credentials and secret-bearing operator configuration. |
| 5: two boundary layers (22–26) | [Core boundary](../ordin/runtime_boundary.py), documented access lattice and explicit lexical/runtime filesystem assertions. [Core tests](../tests/test_runtime_boundary.py) cover every domain and all four states. [Prover adapter](../integrations/openshell/ordin_openshell/prover.py) preserves JSON state/coverage/counterexamples and binds snapshot bytes. [Real and parser tests](../integrations/openshell/tests/test_prover.py) cover within/exceeds/unsupported/error, inconclusive JSON and compatibility failures. |
| 6: narrow denial proposals (27–33) | [Core proposal](../ordin/capability_delta.py), [backend candidate verifier](../integrations/openshell/ordin_openshell/deltas.py), [core tests](../tests/test_capability_delta.py), [integration tests](../integrations/openshell/tests/test_deltas.py). Every proposal requires approval; unmodeled, stale, weak, out-of-boundary, unrepresentable or failed-proof requirements cannot grant authority. The narrow requested permission is separate from the full reviewed startup candidate. No apply/retry occurs in core. |
| 7: structured ingestion (34–36) | [OCSF parser](../integrations/openshell/ordin_openshell/observations.py), [private correlation store](../integrations/openshell/ordin_openshell/correlation.py), [event tests](../integrations/openshell/tests/test_observations.py), [storage tests](../integrations/openshell/tests/test_correlation.py). Exact event/action/contract/session/sandbox/policy binding, bounded SQLite transactions, expiry, duplicate consumption and POSIX mode checks. Uncorrelated events retain a typed backend result and stay outside trajectories. |
| 8: shadow rollout (37–40) | [Pure shadow evaluation](../integrations/openshell/ordin_openshell/shadow.py), versioned root/package report schema and [tests](../integrations/openshell/tests/test_shadow.py). Required local metrics/mismatch codes, incomplete identity/coverage, no mutation, and [manual promotion gates](openshell-integration.md#shadow-evaluation-and-promotion). Shadow does not switch itself to enforce. |
| 9: credential scope (41–42) | Opaque contract bindings, independent core boundary checks, exact trusted provider/host/port/method/path configuration, approval requirements and privacy adversaries. Missing credential proof coverage refuses prover-verified application. Runtime/provider ownership of secret values is explicit. |
| 10: OCSF (43–45) | Structured OCSF 1.8.0 ingest retains source version and event digests alongside unchanged Ordin audit. The optional [OCSF 1.8 Detection Finding exporter](ocsf-export.md) uses explicit bounded timestamps, fixed categories, and digest identities. It omits raw commands, arguments, credentials, and payloads, rejects malformed correlation artifacts, and cannot authorize runtime evidence. |
| 11: CLI (46–47) | [Core read-only commands](../ordin/runtime_cli.py): derive/validate/verify/propose and observation validation. [Optional CLI](../integrations/openshell/ordin_openshell/cli.py) additionally provides derive-requests/compile-requests/verify-requests/export-ocsf beside compile/compile-contract/validate/prove/ingest-event/shadow-report/doctor/apply. CLI tests cover JSON/error conventions, privacy, protected inputs and separate explicit management. |
| 12: audit/provenance (48–49) | Digest-linked contract/plan/verification/evidence identifiers, default redaction and bounded hash chains. [Apply receipts](../integrations/openshell/ordin_openshell/apply_audit.py) link the original unchanged review. [Actual apply report](reports/openshell-runtime-apply.json) verifies two receipts, named loaded revision/admission, and no workload action executed by apply. |
| 13: threat model (50) | [Threat model](threat-model.md) addresses compiler widening, evidence spoofing, stale contracts/TOCTOU, effective policy drift, runtime compromise, credential confusion, cross-session contamination, local storage ownership and non-atomic management. No remote-attestation claim. |
| 14: all test categories (51) | Pure core, compiler golden/negative, installed real prover, structured event/correlation, regression/security and package checks. [Actual VM demo](openshell-runtime-demo.md) establishes exact GET success, POST denial, unrelated-host denial, read-only filesystem positive/negative controls, and evidence returned to later reviews. |
| 15: adversarial corpus (52) | [13 versioned cases](../benchmarks/runtime_enforcement.json), [evaluator](../integrations/openshell/ordin_openshell/corpus.py), [report](reports/runtime-enforcement-corpus.json). Every named scenario checks a decision/non-success state and specific evidence; no implementation rule is tuned to an ID. |
| 16: documentation (53–54) | Required capability/evidence/boundary/backend/proposal/OpenShell docs, architecture, threat model, audit, README and docs index updated. Real runtime evidence is linked separately from unit fixtures. |
| 17: compatibility (55) | Ten additive root exports; all old names and v1 contracts remain. [Frozen-inventory tests](../tests/test_contract_audit.py) preserve the original manifest and explicitly enumerate only additive exports. Runtime deployment profile is an optional final configuration field. |
| 18: files/schemas/package (56–58) | New core modules and separate integration package follow the planned boundary. Nine additive schemas have root/package parity: capability, observation, observation history, runtime session, boundary, delta proposal, shadow report, runtime request contract and runtime request boundary. Current doctor checks 38 total schemas. |
| 19: release-blocking invariants (59) | Explicit invariant mapping below; exercised by the full passing suite and actual readback/apply controls. |
| 20: examples (60–62) | [Reproducible non-secret fixtures](../examples/runtime-enforcement/prepare.py) and caller-owned [demo](../scripts/run_openshell_runtime_demo.py). Literal `gh issue view` uses GraphQL and cannot truthfully derive the plan's assumed REST GET; it stays unsupported. The same issue-inspection intent is implemented using an exact public REST request. Modeled versus unmodeled denial paths are tested independently. |
| 21: performance (63) | [Benchmark](runtime-capability-benchmark.md) measures review/context, review plus derivation and boundary verification, with 120 samples per stage and percentiles. Core derivation is deterministic, bounded and free of subprocess/filesystem/DNS/network calls. No backend execution-latency claim. |
| 22: errors (64) | [Stable reason codes](runtime-reason-codes.md), typed non-success/coverage and machine JSON. Prose changes do not authorize permissions. |
| 23: compatibility doctor (65) | Pinned OpenShell/prover `0.1.2`, policy/JSON schema 1, integration `0.1.0`; [doctor](../integrations/openshell/ordin_openshell/doctor.py) performs version/schema-only probes, no sandbox mutation. Missing installations preserve core usability. |
| 24–25: scope and differentiation (66–67) | No new gateway, vault, fleet manager, kernel component, remote attestation or inference service. Existing intent, graph/resources, caller policies, tool identity, trajectories and provenance remain in the review plane. |
| 26: milestones (68–70) | Core, integration and explicit-enforcement milestone artifacts are present and verified by the checks above. Successful compilation alone is not approval or runtime enforcement; named apply checks actual effective policy, loaded revision and admission. |
| 27: process/report (71–76) | Design and phased implementation retained in focused commits on `feat/runtime-capability-enforcement`; no version bump or unrelated rewrite. Final report uses the prescribed 15 sections and states observed counts/limits. |

## Exact safety invariants

| Invariant | Release evidence |
| --- | --- |
| A: no compiler widening | Compiler golden/negative tests, broader-base-policy rejection, independent validation and actual compiled/readback authority comparison. |
| B: unsupported fields retained | Contract unknowns, compilation non-success/fields, boundary/prover coverage tests, shadow unsupported metrics. |
| C: block cannot grant | Contract diagnostic grant state, core boundary blocked-decision test, compiler block test, apply non-executable test. |
| D: ask requires host approval | Contract approval state and exact request-bound apply tests; actual unapproved call returned `requires_approval`. |
| E: no credential values | Contract/observation URL and metadata rejection, compiler operator-secret adversaries, redacted audit, proposals and shadow reports. Runtime-owned credentials never enter Ordin artifacts. |
| F: action digest mismatch rejects evidence | Core correlation, integration event binding, cross-session/reset, mismatch corpus and persistent-storage tests. |
| G: REST never becomes raw TCP | Core protocol comparison and compiler parameterized negative tests; exact REST rules in the real VM policy. |
| H: unknown tool names cannot grant | Exact registered semantics and identity tests; unknown generic tools and unmodeled request constraints cannot compile. Scoped MCP needs a protected logical-server/endpoint binding and an exact supported tool/method/version. |
| I: evidence cannot erase predicted danger | Additive observation normalization and denied-secret/legacy evidence tests preserve predicted effects and strengthen later trajectories. |
| J: runtime cannot weaken caller policy | Existing ask/block preservation tests, original-review guards, no policy override in derivation, apply or provenance. |

## Historical pre-`#199` verification commands

On Python 3.12.3, native WSL Linux, from the checksum-verified source snapshot:

```sh
python -m pytest -q
python -m ordin doctor
python -m pre_commit run --all-files --show-diff-on-failure
```

Results: **1,086 passed, 11 skipped in 172.11 seconds**; doctor **36 schemas,
zero errors**; all seven hooks passed (lint, format, typed boundaries, compile,
doctor, namespace and workflow security). The 11 shell skips comprise nine
unavailable Zsh fixtures and two ZLE cases intentionally inapplicable to Bash;
`python -m pytest -q tests/test_shell_integration.py -rs` separately reported
11 passed/11 skipped and confirmed those reasons. The real prover test ran.

The caller-owned VM test and corpus commands were:

```sh
python scripts/run_openshell_runtime_demo.py \
    --openshell /var/tmp/ordin-openshell-runtime-0.1.2/openshell \
    --gateway-endpoint http://127.0.0.1:18780 \
    --sandbox ordin-vm-get-corr --filesystem-sandbox ordin-vm-fs-corr \
    --correlation-db /var/tmp/ordin-openshell-vm-e2e-20261006/state/final-demo-correlation.db \
    --json-out runtime-demo.json
python scripts/run_runtime_enforcement_corpus.py --json-out runtime-enforcement-corpus.json
```

The six runtime assertions and all 13 corpus cases passed. Network events used
actual runtime-owned OCSF logs and exact protected local bindings. The backend
report records a separate backend-observed GET allowance and backend-enforced
denial for each POST/unrelated-host probe; a generic failed connection alone
does not satisfy the enforcement assertions. The backend
lacks a native filesystem OCSF class; the explicit host-controlled filesystem
probe is accurately labeled `backend_observed`, with later-review provenance.
Its exact Python invocation is reviewed before execution and receives the
observation; it is never attached to the separate `cat` baseline. Arbitrary
Python code semantics remain unknown rather than claiming a read-only contract
describes the write probe.

The VM's guest kernel was **6.12.76**, with pinned OpenShell CLI/gateway/driver/
supervisor/prover **0.1.2**. The WSL host kernel **5.15.167.4** failed Docker
startup closed for missing required Landlock rights. That failed attempt was
not counted as positive enforcement and its hard requirements were not relaxed.

## Historical installed distributions and release gates

The original gate recorded the implementation revision, source digest,
distribution SHA256 values and actual installed-workload results for the
historical source above. These are not current-HEAD packaging results. Both core and optional wheels/source
distributions built with `python -m build --no-isolation --outdir ...`; all four
passed `python -m twine check ...`. A fresh environment installed the core wheel
using `python -m pip install --no-index --no-deps ...` and imported Ordin with
neither YAML nor the integration present. The optional wheel then imported with
YAML absent. Missing-runtime doctor returned the expected non-success exit 2;
the installed pinned-runtime doctor returned exit 0, without sandbox mutation.

The native validation root was
`/var/tmp/ordin-validation/9dca50a6c212f33716d3536094b221d234b07641202225b44fb76900fd0c5c67`.
With `artifact_root` set to
`/var/tmp/ordin-runtime-artifacts/9dca50a6c212f33716d3536094b221d234b07641202225b44fb76900fd0c5c67`,
the installed artifact gate ran:

```sh
python scripts/run_release_candidate.py \
    --wheel-python "$artifact_root/wheel-environment/bin/python" \
    --output "$artifact_root/candidate" \
    --revision 8dc27db112af6347a42f8184d2a4468324f8a4c8
python scripts/release_integrity.py create --dist "$artifact_root/core" \
    --revision 8dc27db112af6347a42f8184d2a4468324f8a4c8 \
    --tag runtime-validation-8dc27db112af
python scripts/release_integrity.py verify --dist "$artifact_root/core" \
    --revision 8dc27db112af6347a42f8184d2a4468324f8a4c8 \
    --tag runtime-validation-8dc27db112af
```

All eight candidate workloads passed: safety 34/34, trajectories 11/11 with
21/21 decision steps, failure regressions 9/9, extended regressions 4/4,
conformance 37/37, integration 17 workloads with zero errors, runtime 17/17,
and 14 quickstart checks. Integrity creation and verification passed. The
validation tag is local report identity; nothing was published.

Task-owned test sandboxes, gateways, image daemon and private containerd were
stopped after identity checks. Fixture state and evidence were retained; the
final process inspection found no remaining task-owned runtime services.

## Practical limits

The compiler supports exact public IPv4 REST method/path rules, exact binaries,
explicit non-root identities and representable filesystem rights. A separate
action-bound [request contract and boundary](runtime-requests.md) supports named
flat GraphQL query/mutation operations with exact root fields and scoped MCP
endpoint/logical-server/method/tool/version permissions. Per-protocol verification
preserves REST, GraphQL and MCP authority independently; raw HTTP cannot borrow
high-level permissions after transport projection. Opaque boundary identities
remain unsupported.

GraphQL variables, arguments, aliases, directives, fragments, nested selections,
subscriptions and batches remain unmodeled. Nonempty MCP arguments requiring
finer authorization are unsupported, as are wildcard tools/servers, arbitrary
TCP, unmodeled protocols, ambiguous/encoded paths, private destinations, wildcard
authority, missing identities and unknown semantics. The pinned standalone
OpenShell 0.1.2 prover covers TCP/REST, not GraphQL/MCP; configured proof refuses
unmodeled protocol coverage. Provider references stay separate from credential
values, and missing credential proof coverage refuses configured verification.

The adapter/runtime and protected host inputs remain trust roots. Hash chains
do not resist a fully compromised owner; read-before/read-after management is
not atomic compare-and-swap. A loaded permission is not completed execution.
Finite fixtures do not prove universal safety, and this local gate does not
replace the maintained multi-OS/Python GitHub CI matrix for a published release.
