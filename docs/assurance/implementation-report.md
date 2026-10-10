# Ordin Assurance implementation report

- Baseline SHA: `9f2568f70c677f607d631e252f609207f6a2cd60`.
- Feature branch: `feat/ordin-assurance`.
- Contract foundation SHA: `3773f23b08f1cd9b78a7b8aa041f952bd52d47cc`.
- Repository/profile implementation SHA: `bec1037d64fd0c52e043343c3ea1c960819ecb58`.
- Invariant-gate functional implementation SHA: `aa5345d6fa18ed9d6f9f6ff62995f1c9eec6dd38`.
- Policy-simulator functional implementation SHA: `3d757a3d1f2a389d526f921c3a45ab3827e4202d`.
- Finite-challenger functional implementation SHA: `699b5f8185e42693b47e8263c4e5c51ef4ca09ef`.
- Expanded-property implementation SHA: `9c472242f566c5eb4f9cc00ee005eef58a5537d7`.
- Host-source handle implementation SHA: `7a9804cc897bcdf4bd4733ec1af2279615e5aa87`.
- Attack-path/source-flow implementation SHA: `763b73161cd2ed7bb3657d3b9d20795d43ef049e`.
- Delegation implementation SHA: `edd661204ae8426aa4d491e8df1cd3dd31c69b3b`.
- Offline Codex importer SHA: `7fa6d65c646619986d4e96043a3209ea8ad44e81`.
- Full implementation SHA: pending; M3 release gates, M4 final integration scenarios and M5–M12 remain open.
- Environment: Windows 11 10.0.26200, Python 3.13.12.
- Preexisting untracked items: specification, `.worktrees/`, `video/`; preserved.
- Optional providers/scanners: none installed or invoked for this work.

| Milestone | Status | Evidence / next gate |
| --- | --- | --- |
| M0 | baseline_captured_with_failures | Frozen inventory, doctor, isolated baseline wheel and nine corpus cases pass; original suite: 1359 passed, 16 failed, 39 skipped; installed baseline recheck: 11 passed, 5 failed |
| M1 | contract_foundation_verified | Ten immutable artifact contracts and schema pairs; 61 hostile/round-trip tests; source/schema/security/API gate 90 passed, 1 platform skip; agent/policy/entrypoint compatibility gate 108 passed; installed wheel and metadata gates pass |
| M2 | implemented_offline_verified | Scoped read-only inventory, four frozen source-backed drafts, protected profile loader/compiler; 162 passed / 2 POSIX skips; final installed wheel, metadata and SDK example pass |
| M3 | functional_sdk_verified_gates_open | Pure evaluator/gate and sealed host facts; 240 passed / 1 POSIX skip; wheel/SDK pass; full run 1135 passed / 5 failed / 27 skipped; two audit gaps fixed with 14-test recheck; end-to-end latency still failed |
| M4 | functional_sdk_cli_verified_final_scenarios_open | Independent frozen replay, advisory change guard, local CLI, 22 synthetic cases; final source gate 168 passed / 1 POSIX skip; core compatibility 60 passed / 1 POSIX skip; final committed-source wheel/doctor/CLI/metadata pass; SDK/CLI parity captured |
| M5 | expanded_challengers_verified_dependent_gates_open | Ten-property suite, 320 generated fixtures, 244 assessed / 76 unresolved; 172 seeded failures / 80 minimized replayed records; final source gate 200 passed / 1 POSIX skip; protocol compatibility 98 passed, broader core compatibility 79 passed; pinned wheel/doctor/metadata and SDK/CLI parity pass; dependent/optional gates remain open |
| M6 | graph_flow_sdk_verified_cross_agent_added | Bounded graph/source-flow SDK; original gate 230 passed / 1 POSIX skip; authenticated M7 cross-agent composition added; combined gate 258 passed / 1 POSIX skip; new wheel pending |
| M7 | sdk_lifecycle_verified_release_gates_open | Full-domain containment, private issuance/revocation, current use tickets, per-child sessions and cross-agent graphs; source gate 258 passed / 1 POSIX skip; core compatibility 140 passed / 1 skip; pinned example/graph/wheel/doctor/metadata pass; external enforcement/release gates remain open |
| M8 | offline_import_verified_live_wrapper_pending | Pinned JSON/SARIF, claims/coverage/integrity, source-backed draft conversion and redacted CLI; source gate 294 passed / 1 POSIX skip; core/parity gate 19 passed; core/adapter wheel/doctor/metadata checks pass; scanner/diff/CI slice pending |
| M9 | not_started | Optional mock/TypeSafe/Laya evidence |
| M10 | not_started | Finding validation and patch-risk verification |
| M11 | not_started | Complete CLI/API/docs/examples |
| M12 | not_started | Complete acceptance, corpus, CI and release gates |

## Verified contract preservation

The frozen [inventory](evidence/baseline-inventory.json) records the original
exports, schemas, entrypoints, representative decisions and wheel bytes.
No review/runtime/OpenShell behavior has been modified. The schema registry
adds ten independent contracts, and package enumeration now includes
`ordin.assurance`; existing exports, console scripts and schema registrations
remain unchanged. The installed [wheel check](evidence/m1-wheel-check.json)
passes with all 50 schemas, source-independent imports, no mandatory dependency,
no socket construction during import/review, and preserved safe/block decisions.
Full candidate regression/release preservation remains unproven.

## Evaluation plan

Before implementing the runtime wrapper, the development budget is **5 ms p95
added deterministic assurance latency** on local fixtures, measured separately
from core, adapters, providers and scanners. Record p50/p95/p99, warmup/sample
counts and host environment. This provisional engineering budget is not a
production latency guarantee. Preserve every existing security threshold.
Freeze development and held-out families independently before choosing optional
model thresholds. No effectiveness claims from nine compatibility cases.

## Commands actually run on 2026-10-09

All shell invocations use the required RTK prefix.

| Command (after RTK prefix) | Result |
| --- | --- |
| `git status --short`, `git log -6 --oneline`, `git worktree list` | Baseline main at expected SHA; preexisting files preserved |
| `git switch -c feat/ordin-assurance` | Pass |
| `python -m pip install -e '.[dev]'` | Failed: build isolation cannot reach PyPI (`WinError 10051`) |
| `python -m ordin doctor` | Pass; 40 schemas, no errors |
| `python -m pytest -q --basetemp=.assurance-baseline-tests` | Exit 1: 1359 passed, 16 failed, 39 skipped, 2 cache-permission warnings; 1149.73 seconds |
| `python -m build --no-isolation --outdir .assurance-work/baseline-dist` | Pass; wheel and sdist built; existing license deprecation warnings |
| `python scripts/capture_assurance_baseline.py --wheel .assurance-work/baseline-dist/ordin-0.4.0.dev0-py3-none-any.whl --output docs/assurance/evidence/baseline-inventory.json` | Pass after sandbox generated-file access escalation; 301 inspected source/doc/test/workflow files |
| `python scripts/run_agent_safety_corpus.py ...` | Failed: module import requires installed editable package or module invocation |
| `python -m scripts.run_agent_safety_corpus --revision 9f2568f70c677f607d631e252f609207f6a2cd60 --output .assurance-work/baseline-safety-corpus` | Pass; all 9 cases, no errors |
| `python -m venv --without-pip .assurance-work/baseline-venv` | Pass |
| `python -m pip --python .assurance-work/baseline-venv/Scripts/python.exe install --no-index --no-deps .assurance-work/baseline-dist/ordin-0.4.0.dev0-py3-none-any.whl` | Pass after generated-wheel access escalation; installs only in workspace venv |
| `python -m scripts.run_safety_benchmark --repetitions 20 --json-out .assurance-work/baseline-safety.json --format text` | Exit 1: 34/34 expected decisions; zero false allows, critical misses, false blocks, semantic misses, policy/fuzz errors; latency gate fails |
| `python -m scripts.run_integration_evaluation --revision 9f2568f70c677f607d631e252f609207f6a2cd60 --repetitions 20 --json-out .assurance-work/baseline-integration.json --markdown-out .assurance-work/baseline-integration.md` | Exit 1: zero decision/conformance/session failures; two latency errors |
| `python -m pytest -q tests/assurance/test_models.py -p no:cacheprovider` | Pass: 61 tests in 2.30 seconds |
| `python -m ruff check ordin/assurance scripts/capture_assurance_baseline.py scripts/generate_assurance_schemas.py scripts/check_assurance_wheel.py tests/assurance` | Pass |
| `python -m mypy ordin/assurance` | Exit 1: six existing Windows-stub errors for POSIX `os.geteuid`/`os.fchmod` in imported core files; no new Assurance diagnostics |
| `python -m mypy --platform linux ordin/assurance` | Pass: four source files |
| `python -m scripts.generate_assurance_schemas` | Pass: ten root/package schema pairs |
| `python -m pytest -q tests/assurance tests/test_schemas.py tests/test_public_api.py tests/test_security_integrity.py tests/test_namespace_guard.py -p no:cacheprovider --basetemp=.assurance-work/contracts-tests` | Pass: 90 passed, 1 skipped in 12.36 seconds |
| `python -m pytest -q tests/assurance tests/test_agent.py tests/test_action_policy.py tests/test_policy.py tests/test_entrypoint.py -p no:cacheprovider --basetemp=.assurance-work/m1-compatibility --junitxml=.assurance-work/m1-compatibility.xml` | Pass: 108 tests in 9.97 seconds |
| `python -m ordin doctor` after schema registration | Pass: 50 schemas; no schema/resource/graph errors |
| `python -m build --no-isolation --outdir .assurance-work/m1-dist` | Pass: candidate wheel/sdist built |
| `python -m twine check .assurance-work/m1-dist/ordin-0.4.0.dev0-py3-none-any.whl .assurance-work/m1-dist/ordin-0.4.0.dev0.tar.gz` | Pass for both artifacts |
| `python scripts/check_assurance_wheel.py --wheel .assurance-work/m1-dist/ordin-0.4.0.dev0-py3-none-any.whl --venv .assurance-work/m1-wheel-venv --report docs/assurance/evidence/m1-wheel-check.json` | First smoke harness failed: replacing the socket class with a function broke SSL import; no package defect indicated |
| Same wheel command with corrected socket subclass and fresh `.assurance-work/m1-wheel-venv-2` | Pass; isolated installed wheel with 50 schemas and 23 Assurance exports; evidence contains exact wheel SHA-256 |
| `python scripts/recheck_assurance_baseline.py --python .assurance-work/baseline-recheck-venv/Scripts/python.exe --output .assurance-work/baseline-recheck-1` | Exit 1: 11 passed, 5 failed in 383.57 seconds against the frozen 40-schema installed baseline; no skips |
| `python -m ruff format --check` for all new Python files; `git diff --check` | Pass |

## M2 actual verification on 2026-10-09

The runtime/core/OpenShell implementations remain unchanged. M2 adds
`inventory.py`, `inventory_models.py`, `profiles.py` and scoped read-only
`_files.py`, plus three new versioned contracts (53 total registered schemas).
The static model always remains a hypothesis/draft; approved handles require
host-owned selection, exact raw-file/content digests, repository/version and
active-policy identity. Compiler plans reconstruct their restrictions from
approved content and reject omitted/tampered constraints. No `allow` rules are
generated. All nine invariant kinds remain represented; host/evidence checks
are explicitly deferred to the M3 wrapper rather than dropped.

| Command (after RTK prefix) | Actual result |
| --- | --- |
| `python -m pytest -q tests/assurance/test_inventory.py ...` initial run | 12 failed / 1 passed: cached Windows enumeration omitted link counts; fixed by checking actual opened handle before reading, plus a test-helper argument correction |
| Inventory recheck with fresh basetemp | 13 passed; four repositories, references, injection, sensitive files, malformed/large inputs, links and snapshot drift |
| Profile loader/compiler initial runs | Constructor source-schema mismatch corrected; legacy literal-prefix behavior exposed `/prod2` false match and was corrected in new-profile projection without changing old v1 semantics |
| `python -m pytest -q tests/assurance tests/test_schemas.py tests/test_action_policy.py tests/test_public_api.py ...` | 126 passed before the additional hardening cases |
| Windows directory path-pinning negative test | Initially failed because metadata-only handles did not block rename; read handles now pin directory names; 15 inventory tests pass |
| Final source gate: `python -m pytest -q tests/assurance tests/test_schemas.py tests/test_public_api.py tests/test_action_policy.py tests/test_agent.py tests/test_policy.py tests/test_entrypoint.py tests/test_security_integrity.py tests/test_docs_links.py -p no:cacheprovider --basetemp=.assurance-work/m2-verified-tests --junitxml=.assurance-work/m2-verified-tests.xml` | 162 passed, 2 skipped in 23.06 seconds; skipped ownership/mode checks require POSIX |
| `python -m mypy --platform linux ordin/assurance` | Pass: eight source files |
| `python -m ruff check` and `ruff format --check` on changed Python files | Pass |
| `python -m ordin doctor` | Pass: 53 schemas; no errors or resource differences |
| `python -m scripts.freeze_assurance_inventories --output docs/assurance/evidence/m2-inventories` | Pass: documentation/payment/MCP/monorepo snapshots, verified citations, hypotheses, counterevidence, manifests |
| `python -m examples.assurance.profile_inventory --repository-root tests/assurance/fixtures/repositories/payment --repository-id fixture/payment --revision fixture-v1 --virtual-root /fixture/payment --output .assurance-work/m2-sdk-example` | Pass: four inspected files, ten facts, one compiled restriction; draft non-authoritative, no actions executed, synthetic host protection explicitly labeled |
| Initial candidate wheel/sdist build and twine check | Pass; wheel imported independently with 53 schemas and no socket creation |
| Final build after fixing directory-handle access: `python -m build --no-isolation --outdir .assurance-work/m2-final-dist` | Pass; output retained in `.assurance-work/m2-final-build.log` |
| `python scripts/check_assurance_wheel.py --wheel .assurance-work/m2-final-dist/ordin-0.4.0.dev0-py3-none-any.whl --venv .assurance-work/m2-final-wheel-venv --report docs/assurance/evidence/m2-wheel-check.json` | Pass: source-independent imports/inventory, 53 schemas, 37 Assurance exports, no socket construction; exact wheel SHA-256 retained |
| `python -m twine check` for the final wheel and sdist | Pass for both artifacts |
| Final installed wheel interpreter with `-I examples/assurance/profile_inventory.py` and the documented synthetic payment arguments | Pass: same snapshot digest, four files/ten facts, one restriction; no execution |
| Frozen fixture hash and original public export/schema registration comparisons | Pass; original API, schema names/filenames and synthetic source bytes unchanged |

The frozen [M2 inventory manifest](evidence/m2-inventories/manifest.json) records
exact synthetic source bytes. Static completeness means selected files were
inspected, not complete deployment/security coverage. Threat-model drafts retain
open questions even for harmless fixtures. No arbitrary repository code was
executed, no model/scanner invoked and no real runtime protection installed.
The final [source gate](evidence/m2-source-gate.json) and
[installed wheel gate](evidence/m2-wheel-check.json) are current. The earlier
`m2-wheel-check-before-directory-fix.json` is historical and does not verify the
final directory-handle implementation. POSIX/multi-version CI remains required;
this milestone has been exercised locally only on Windows/Python 3.13.

## M3 actual implementation and verification

`gate.py`, `invariants.py` and `host.py` add pure conservative composition with
the original `AgentGate`. All nine invariant kinds have typed behavior; dynamic
flow/delegation checks consume authenticated host assessments and remain
inconclusive without them. M6/M7 must provide actual verification integration;
the M3 source does not itself prove causal flow or issue child grants.
Credential routing is an exact host-bound opaque requirement and checks its
destination independently. Its private credential-only verifier question is
not an executable contract or full protocol/process authorization claim.

Five additional v1 audit contracts are registered/packaged (58 schemas total).
They never authenticate ordinary JSON. Decisions retain the full private core
review, export a redacted separate report, and bind action, baseline/assurance
configuration, profile, host policy/session/epoch/context and history. Changing
the required-profile configuration invalidates old decisions. Changed review
inputs during evaluation deny; baseline hard blocks skip added evidence.

| Command / gate | Actual result |
| --- | --- |
| Initial invariant tests | 31 passed, 2 failed; one incorrect test assertion rejected a safe deny, and credential checking needed an explicitly scoped independent domain rather than unsupported GraphQL capability projection |
| Corrected invariant tests | 33 passed; then 35 passed with required-configuration and review-time mutation cases |
| Host/JSON/binding tests after immutable digest caching | 96 passed; finite/bounded/duplicate-key/origin protections retained |
| Final source compatibility gate: `python -m pytest -q tests/assurance tests/test_schemas.py tests/test_public_api.py tests/test_policy.py tests/test_agent.py tests/test_action_policy.py tests/test_runtime_boundary.py tests/test_request_authority.py tests/test_docs_links.py -p no:cacheprovider --basetemp=.assurance-work/m3-final-source-tests --junitxml=.assurance-work/m3-final-source-tests.xml` | 240 passed, 1 skipped in 43.74 seconds; [source evidence](evidence/m3-source-gate.json) |
| `python -m mypy --platform linux ordin/assurance` | Pass: 11 files |
| Ruff lint/format and `git diff --check` | Pass |
| `python -m ordin doctor` | Pass: 58 schemas; no parity/schema/graph errors |
| `python -m examples.assurance.gate_review --output .assurance-work/m3-gate-example` | Pass: escalate before approval, execute after exact host receipt, deny protected mutation; no reviewed action executed |
| `python -m build --no-isolation --outdir .assurance-work/m3-dist` | Pass; log `.assurance-work/m3-build.log` |
| Final installed wheel and twine metadata checks | Pass; [wheel evidence](evidence/m3-wheel-check.json) includes exact wheel hash, 58 schemas, source-independent import/inventory and no socket creation |
| Installed wheel interpreter with `-I examples/assurance/gate_review.py --output .assurance-work/m3-wheel-gate-example` | Pass; same synthetic disposition sequence and binding check |
| `python scripts/run_assurance_full_regression.py --python .assurance-work/m3-regression-venv/Scripts/python.exe --output .assurance-work/m3-full-regression --revision uncommitted-m3-installed-wheel` | Exit 1: 1135 passed, 5 failed, 27 skipped in 530.787 seconds; thresholds/tests preserved |
| `python -m pytest -q tests/test_contract_audit.py tests/assurance/test_contract_coverage.py -p no:cacheprovider --basetemp=.assurance-work/m3-canonical-examples` | 14 passed: canonical examples added for all 18 new schemas; frozen legacy inventory retained |

The full regression process **38260 is terminal**, exit 1. Its
[sanitized summary](evidence/m3-full-regression-summary.json) records every
failed/skipped case and the private JUnit hash. Two failures were newly added
schema coverage/inventory assertions; canonical runtime/data examples and an
explicit additive-schema audit corrected them without changing the legacy
manifest. The focused audit recheck passes. Remaining full-run failures are two
existing Windows latency tests and the existing quickstart's absent POSIX `sh`.
Private stdout/JUnit/state stay under `.assurance-work/m3-full-regression`.
No background evaluation, model or scanner process remains running.

### M3 performance gate remains open

The predeclared 5 ms p95 additional-layer budget was preserved. Profiling found
four repeated effect-catalog scans per decision, plus redundant text validation
and immutable record hashing. The report whitelist is now captured once,
text checks use a bounded fixed regular expression, and immutable artifact/
host-context digests are cached. No input limits or authority checks were removed.

Actual [observed latency results](evidence/m3-latency-observed-summary.json):
added p95 fell from 142.1518 ms to 50.2829 ms on this host. The isolated-layer
measurement is 2.5064/4.9858/6.3382 ms p50/p95/p99, but end-to-end matched
latency remains failed. Intrinsic success does not replace that required gate.
All runs have zero disposition mismatches. These are synthetic, partly
contention-affected, uncommitted-source measurements; exact-SHA release metrics
and production effectiveness are unproven.

Raw report reads failed with `PermissionError` even under workspace-scoped
escalation. The tracked summary transcribes complete metrics observed directly
in the actual tool output and explicitly records that limitation; it does not
claim a hash of inaccessible original bytes. All four failed end-to-end outcomes
remain visible.

## M4 policy replay and advisory CLI

Frozen policies/cases/corpora use detached bounded JSON and content/version
manifests. Independent existing `IntegrationSession` instances preserve proposal
ordering, refused proposals, bounded observations, principals and epochs. The
report retains core/final outcomes, effect/temporal/capability differences,
profile/selection/policy/corpus/action digests, fixture misses/friction, coverage
by action kind and separate local core/wrapper latency. Arbitrary changed policy
algebra remains `unknown`; exact domain comparison reuses the existing full
capability verifier and preserves protocol request/grant identities.

The additive `ordin-assure` CLI validates profile content without approval,
simulates local frozen JSON inputs, and diffs same-corpus reports. No output file
is created without `--report`; existing files are refused. Exit codes distinguish
complete/pass (0), regression (1), and malformed/partial/unproved (2). No actions,
providers, scanners, approvals, runtime receipts or delegation grants are issued.

Actual checks:

| Command | Result |
| --- | --- |
| `python -m pytest -q tests/assurance tests/test_contract_audit.py -p no:cacheprovider --basetemp=.assurance-work/m4-final-source-gate` | 168 passed, 1 POSIX skip, 22.07 s |
| `python -m pytest -q tests/test_public_api.py tests/test_agent.py tests/test_schemas.py tests/test_action_policy.py tests/test_session.py -p no:cacheprovider --basetemp=.assurance-work/m4-core-compatibility` | 60 passed, 1 POSIX skip, 75.52 s |
| `python -m mypy --platform linux ordin/assurance scripts/freeze_assurance_simulation.py` | 14 source files clean; typing target only, no POSIX execution implied |
| `python -m ruff check ordin/assurance scripts/check_assurance_wheel.py scripts/freeze_assurance_simulation.py tests/assurance examples/assurance/policy_simulation.py` | Passed |
| `python -m scripts.generate_assurance_schemas` | 18 source/package schema pairs regenerated identically |
| `python -m scripts.freeze_assurance_simulation` | 22 synthetic cases, 11 families; corpus digest `161f1c05003fa0c51761200e8a9b4bb2eac8e73e4098fc5322616d824400a978` |
| `python -m examples.assurance.policy_simulation` | Detected newly executable unknown MCP tool after removed approval threshold; guard false, authority widened, coverage partial |
| `python -m build --no-isolation --outdir .assurance-work/m4-build` and `python -m twine check ...` | Wheel/sdist built; metadata checks passed |
| `python -m scripts.check_assurance_wheel --wheel .assurance-work/m4-build/ordin-0.4.0.dev0-py3-none-any.whl --venv .assurance-work/m4-wheel-venv --report .assurance-work/m4-wheel-check.json` | Fresh isolated wheel, simulator, CLI entrypoint, doctor, no-network smoke passed; 58 schemas, 18 assurance schemas |

The final model guard additionally rejects contradictory changes, weakened core
outcomes and inconsistent passing summaries. One existing assertion initially
failed because the strengthened validation used a different error message; the
original `incomplete` diagnostic was retained and the entire final source gate
passed. Earlier invocation errors (incorrect test filename, uninstalled direct
example execution, inaccessible generated wheel) were corrected; no passing
result is inferred from those attempts. Workspace-scoped escalation was needed
to read the generated wheel; ACLs were not changed.

The golden replay catches production and protected-policy mutations as two new
denials, with three benign escalations and no declared critical misses. It stays
partial: untrusted MCP semantics, delegation lifecycle (M7), and optional model
uncertainty (M9) are not fabricated. A separate actual principal/maxima test
produces `deny` and `execute` for two principals proposing the same read. M4's
full integrated golden scenarios remain open until those later verifiers exist.
The 22 cases are a simulator smoke corpus, not the required later 200-case
effectiveness benchmark.

The [final pinned capture](evidence/m4-simulation.json) records source revision
`3d757a3d1f2a389d526f921c3a45ab3827e4202d`, actual native CLI exit **2**, SDK/CLI
decision parity, the final wheel hash and byte equality of **248** packaged
Python/JSON files with the committed package source. Eight assessable critical
fixtures were caught, zero declared critical fixtures missed, and unresolved
fixtures remain explicit. Final wheel/doctor/no-network smoke and twine checks
passed under `.assurance-work/m4-final-*` after the report-validation changes.
The doctor's private multiline output is represented by a hash rather than
weakening public contract limits. One automatic permission review timed out;
normal access still could not read the generated wheel. The permitted single
retry succeeded. No ACL was changed and no pending approval remains.

## M5 initial finite challenger

`challenge_authority_subset` uses seeded standard-library generation and a
faithful finite read/path oracle, compared to the existing full capability
verifier. A closed `seeded_prefix_bug` fixture deliberately accepts lexical
neighbors of `/fixture`; no target plugin or arbitrary code can be selected.
Bounded deletion shrinking retains the exact property, fixed maximum/access,
variant and mismatch signature. Original/minimized captures are rechecked
before immutable counterexample records are emitted. The CLI requires explicit
seed/revision and supports independent replay. A closed immutable run contract
and source/package schema reject inconsistent counts/status and host-enforcement
claims. Schema registration has 59 entries, including 19 Assurance contracts.

Seed 14 / 16 fixtures: four seeded failures shrink to two distinct counterexamples,
four benign controls remain valid, and six unsupported path-precondition cases
remain unresolved. The actual verifier has no disagreement in ten supported
cases; the report stays inconclusive for the six unsupported cases. These are
fixture-harness results, not confirmed Ordin vulnerabilities or live enforcement.

Actual checks:

| Command | Result |
| --- | --- |
| `python -m pytest -q tests/assurance/test_challenge.py tests/assurance/test_simulation.py -p no:cacheprovider --basetemp=.assurance-work/m5-pure-environment` | 29 passed, 17.33 s |
| `python -m pytest -q tests/assurance tests/test_contract_audit.py -p no:cacheprovider --basetemp=.assurance-work/m5-finite-source-gate` | 183 passed, 1 POSIX skip, 36.14 s |
| `python -m mypy --platform linux ordin/assurance` | 15 source files clean |
| `python -m ruff check ordin/assurance tests/assurance/test_challenge.py` | Passed |

The privacy assertion exposed Windows `platform.system/release` occasionally
launching `ver`. Both simulation and challenger now read environment metadata
from Python/system APIs with no subprocess fallback. The failed assertion was
retained as evidence and passes after this correction. Initial schema coverage
failed because the new run schema was not yet registered in the core registry;
explicit additive registration corrected it and the complete source/audit gate
passes. The wheel smoke now also rejects subprocess execution inside the
installed default SDK and exercises discovery/shrink/replay; the final run
passed. No fixture command, network endpoint, external scanner/model, permission
grant or host boundary was exercised.

M5 remains open: the [property inventory](challengers.md) lists generated
monotonicity, exact request/protocol, tool, history, trust-origin, delegation and
provider failure checks, broader differential/adversarial generation, optional
solver encoding and safe reviewed promotion still required. M4's archived
evidence remains pinned to its earlier source SHA; the subprocess-free metadata
correction is part of this later source revision.

The [pinned finite-challenger evidence](evidence/m5-finite-challenge.json) records
implementation revision `699b5f8185e42693b47e8263c4e5c51ef4ca09ef`, four seeded
failures, two independently replayed minimized records, ten supported actual
verifier cases and six unresolved cases. The final local wheel has **251**
packaged Python/JSON files byte-matched to that source. Its installed smoke
rejects both socket construction and subprocess creation while exercising core
reviews, simulation, seeded challenge/minimization/replay, schema parity and CLI
registration; the separate installed doctor also passed. Wheel and sdist metadata
checks passed. No host security boundary was exercised. Supplementary core
API/agent/schema tests: **18 passed** in 8.37 seconds. Capture helpers also pass
Linux-target mypy; this is type checking, not POSIX runtime evidence. All local
test/build/capture processes for this checkpoint are terminal.

## M5 expanded property challengers and protocol isolation

The SDK/CLI now generate and concretely check monotonicity, exact request
commitments, protocol separation, tool identity/discovery, history/observations,
trust origin and review-to-use binding. Shell flags/quoting/nesting/compound and
unsupported-syntax fixtures, URL authority/path/method/port changes, GraphQL
variables/aliases/fragments/batches, RPC ID controls, tool semantics/schema drift,
32-entry queue eviction, stale epoch/source/policy/sandbox correlation, denied
reformulation and secret-read/upload controls run against the actual core APIs.
Untrusted README/model/scan-style instruction text remains inert fixture data.

`ChallengeSuite` retains all ten required property names. Runs retain every
missing declared scenario and cannot declare passing coverage for a short,
skipped or timed-out selection. At seed 14 / 32 trials per property the actual
suite generates **320** cases, assesses **244** with zero disagreement and
keeps **76** unresolved: ambiguous finite path preconditions and the M7/M9
integrations. The suite is inconclusive. This is property-test coverage, not the
later required 100-adversarial/100-benign effectiveness corpus. Counterexample
captures retain action/authority-material and policy digests; shrinking cannot
change them, the property, scenario, assumptions or failure signature.

The differential check identified the existing core's intentional REST-within-
broader-TCP rule. New Assurance request/capability wrappers verify every existing
constraint first, then require a separate exact protocol maximum. They are
wired into approved resource/request invariants. Legacy APIs remain unchanged;
the difference is recorded as `expected_policy_difference`, not an invented
runtime vulnerability. Existing files, credentials, processes, tools and exact
body constraints cannot be dropped by the internal additional projection.

Actual checks:

| Command | Result |
| --- | --- |
| `python -m pytest -q tests/assurance tests/test_contract_audit.py -p no:cacheprovider --basetemp=.assurance-work/m5-expanded-final-source-gate` | 200 passed, 1 POSIX skip, 65.54 s |
| `python -m pytest -q tests/assurance/test_request_protocols.py tests/assurance/test_invariants.py tests/test_request_authority.py tests/test_runtime_boundary.py -p no:cacheprovider --basetemp=.assurance-work/m5-protocol-isolation` | 98 passed, 14.19 s |
| `python -m pytest -q tests/assurance/test_property_challenge.py::test_generators_preserve_every_declared_scenario_and_seed_digest -p no:cacheprovider --basetemp=.assurance-work/m5-all-declared-scenarios` | 7 passed, 8.77 s |
| `python -m pytest -q tests/assurance/test_property_challenge.py::test_cli_property_selection_and_general_counterexample_replay tests/assurance/test_property_challenge.py::test_seeded_defects_shrink_replay_and_preserve_action_and_policy -p no:cacheprovider --basetemp=.assurance-work/m5-bounded-seeded-completion` | 2 passed, 23.11 s |
| `python -m mypy --platform linux ordin/assurance` | 18 source files clean |
| `python -m ruff check ordin/assurance tests/assurance/test_property_challenge.py tests/assurance/test_request_protocols.py` | Passed |

The first expanded full source gate had one CLI coverage failure (199 passed,
1 failed, 1 skip): a 16-trial selection omitted the new semantics-drift scenario.
The test now requests complete 32-trial coverage. An isolated seeded-suite
recheck also exposed legitimate 30-second budget exhaustion before later
properties. Duplicate minimization was moved after signature deduplication,
and decorative noise removal relies on the closed input contract while both
captures still get independent concrete replay. The observed complete seeded
suite then took **14,419 ms** with the unchanged 30-second budget. No timeout
was relabeled success and no resource limit was raised. Z3 and Hypothesis are
absent; no dependency installation or solver result is claimed.

Expanded schema/source/package pairs now total 20 Assurance contracts and
60 registered schemas. The [pinned expanded-property evidence](evidence/m5-expanded-properties.json)
records revision `9c472242f566c5eb4f9cc00ee005eef58a5537d7`, actual SDK/CLI manifest
parity and native CLI exit **2** for incomplete coverage. The seeded synthetic
checker run detects **172** failures and independently replays **80** distinct
minimized records. Those are deliberate fixture defects, not reported Ordin
vulnerabilities. **255** packaged Python/JSON files are byte-matched to the source.

The fresh expanded wheel smoke passes with **60 schemas / 20 Assurance schemas**,
exact request-property discovery/shrink/replay and subprocess/socket rejection
inside the SDK. The installed doctor and wheel/sdist metadata checks also pass.
Supplementary existing core public API/agent/schema/request/boundary checks:
**79 passed** in 7.14 seconds. Evidence capture retains a hash of private doctor
output and omits raw source paths. No provider/scanner, dependency download, real
host boundary, publication or policy installation occurred. All checkpoint
test/build/capture handles are terminal; the tracked package tree is clean.

## M6 host origin/source-use foundation

Private host-issued `InstructionOrigin` and `SourceUse` handles bind principal,
repository, session, epoch, policy selection, source content/span digests and
exact proposed-action bytes. Arbitrary role/trust words, JSON imports, changed
handles and another host scope cannot supply authority. The functions retain
no source bytes, perform no file/network/target operation and grant no
execution or policy rights. UTF-8 bytes are matched exactly without Unicode
normalization. Provided repository references must match the declared version
and complete content digest. See [instruction/data origins](instruction-origins.md).

Actual focused gate: `python -m pytest -q tests/assurance/test_origins.py
tests/assurance/test_contract_coverage.py tests/test_contract_audit.py
-p no:cacheprovider --basetemp=.assurance-work/m6-source-handles`: **24 passed**,
7.04 seconds. `python -m mypy --platform linux ordin/assurance`: **19 source
files clean**; ruff and diff checks pass. Two new source/package schema pairs
bring the registry to **62 schemas / 22 Assurance schemas**. This source-handle
feature is functional; the bounded attack-path builder, source-flow invariant
assessment and cross-agent path verification remain pending. M6 is not complete.

The broader `tests/assurance tests/test_contract_audit.py` gate at
`.assurance-work/m6-origins-source-gate` passed **210 tests / 1 POSIX skip** in
61.37 seconds. The [pinned source-handle wheel evidence](evidence/m6-source-handles-wheel.json)
records source SHA `7a9804cc897bcdf4bd4733ec1af2279615e5aa87`, **258** packaged
Python/JSON files byte-matched to that source, and a successful fresh isolated
install with **62 schemas / 22 Assurance schemas**. Source creation, exact byte
correlation and verification run inside the SDK smoke with subprocess and
socket construction rejected. The separate installed doctor and wheel/sdist
metadata checks pass. Private doctor output is retained as a hash. No target
operation, scanner/model, permission grant, upload, release or deployment occurred.
All checkpoint handles are terminal.

## Baseline failures and measurements (original source, continued)

## M6 same-host attack-path builder and source-flow guards

`ReviewedAction` checks the current gate result, baseline-review seal and exact
host context. `build_attack_path` accepts at most 32 same-principal/session/epoch
reviews, correlates runtime history through the existing core verifier, and
rejects changed reviews, foreign sources and completed observations after an
Assurance denial. Immutable graphs retain separate evidence kinds, correlations,
proof gaps, exposure, permission state, reachability and possible impact. Node,
edge and per-review detail truncation is explicit; a bounded nonrecursive DAG
walk rejects cycles/depth overflow. Reordered/out-of-window histories do not
claim authenticated chronology. Confidence cannot promote the evidence origin.

The graph reuses actual temporal policy signals, preserves denials/failures and
protected policy matches as counterevidence, distinguishes generic code
execution from a download/permission/execute hypothesis, and requires matching
completed effects before establishing sink reachability. An unrelated completed
event cannot establish upload. Missing approval evidence after escalation remains
an explicit gap. Sensitive source bytes establish only host-declared inclusion;
untrusted instruction influence stays hypothetical. Tool prose cannot become
`secret.read`. Private arguments, identities, endpoints and paths remain digests;
the Mermaid renderer also uses a fixed vocabulary.

`SourceProvenance` explicitly binds the host collector's completeness declaration
to the exact action/source/use set. Unknown/transformed inputs remain partial.
`assess_source_flow` produces a scope-bound profile assessment from a sealed
review and exact byte/collection checks. Sensitive egress or untrusted instruction
context violates the guard; absent/partial/unknown provenance cannot satisfy it.
A fresh exact-action gate review consumes the assessment. Neither the receipt
nor the earlier escalation grants execution. Graph test suggestions remain
non-authoritative `SecurityProfileDraft` objects; no policy activation or finding
confirmation is performed. See [attack paths](attack-paths.md).

Actual checks:

| Command / artifact | Result |
| --- | --- |
| `tests/assurance/test_attack_paths.py tests/assurance/test_source_flow.py tests/assurance/test_models.py tests/assurance/test_contract_coverage.py tests/test_contract_audit.py`, `.assurance-work/m6-evidence-origin-gate` | 92 passed, 5.69 s |
| Attack/source-flow focused gate, `.assurance-work/m6-impact-distinction` | 19 passed, 4.63 s |
| Matching sink-effect/approval focused gate, `.assurance-work/m6-sink-reachability` | 20 passed, 6.05 s |
| Graph/flow/schema/audit focused gate, `.assurance-work/m6-counterevidence-scope` | 34 passed, 6.29 s |
| Existing public API/agent/runtime-observation/schema compatibility, `.assurance-work/m6-core-evidence-compatibility` | 68 passed, 52.96 s |
| Earlier broader source gate, `.assurance-work/m6-final-graph-source-gate` | 229 passed, 1 POSIX skip, 125.31 s; final post-review gate running |
| `python -m mypy --platform linux ordin/assurance` | 21 source files clean |
| `python -m ruff check ...` and `git diff --check` | Passed |
| `python -m examples.assurance.attack_path` | Hypothesized sensitive exposure, blocked upload reachability, explicit missing causal/completed evidence |

Initial secret-path expectation and benign-install labeling assertions exposed
overstatement risks; the builder now preserves temporal hypotheses separately
from observed effects and generic execution separately from untrusted execution.
Those cases pass after correction. No limit or trust check was weakened.
Source/package schema parity is regenerated for **23 Assurance contracts / 63
registered schemas**. Cross-agent path construction is explicitly refused until
M7 provides current authenticated delegation/correlation. Live kernel/remote
execution, finding closure and full release gates remain unverified.

Final post-review source gate: `.assurance-work/m6-final-reviewed-source-gate`,
**230 passed / 1 POSIX skip** in 107.43 seconds. Final targeted sink/counterevidence
gate: **34 passed** in 6.29 seconds. The installed-wheel smoke now exercises the
graph and source-provenance APIs with socket/subprocess creation rejected; its
fresh run and pinned graph capture follow.

The [pinned graph capture](evidence/m6-attack-paths.json) records source revision
`763b73161cd2ed7bb3657d3b9d20795d43ef049e` and three actual SDK scenarios:
predicted secret exposure remains **hypothesis**, an authenticated completed
read establishes the scoped read exposure while upload completion remains
unproven, and an authenticated denial reports **blocked** reachability. Those
are synthetic protected-channel fixtures, not physical secret access or runtime
exploitation. Raw source/argument values are omitted.

The [final graph/source-flow wheel evidence](evidence/m6-graph-wheel.json)
byte-matches **261** packaged Python/JSON files to that source. A fresh isolated
install exercises graph construction and provenance handles with network and
subprocess creation rejected inside the SDK smoke; **63 schemas / 23 Assurance
schemas**, installed doctor and wheel/sdist metadata checks pass. Private doctor
output is retained only by hash. All checkpoint handles are terminal.

The original suite failed before any package or schema registration changed.
Additive unregistered Assurance files/docs were created while the suite ran;
existing core/runtime source and original schema bytes remained unchanged.

- Missing installed-package/CLI setup: three integration example tests,
  runtime integration evaluation, and six installed-hook smoke tests.
- Latency gates: two integration evaluation tests, safety benchmark, and
  promoted-regression replay. The separately recorded benchmark runs executed
  concurrently with the original suite; these measurements include contention.
- A five-second MCP malformed-output shutdown test timed out in the first run;
  it passes in the installed-baseline recheck.
- Concurrent session-store transactions fail in both runs with SQLite
  `database is locked` at `BEGIN IMMEDIATE`. This is confirmed on the original
  installed wheel, independently of the new Assurance modules.
- Skip reasons were not printed by the initial `-q` command; the 39 skips are
  recorded as unverified platform coverage, not counted as passes.

The original safety benchmark p50/p95/p99 was
930.1453/3309.7194/3968.4999 ms. The original integration evaluation reported
core 0.5730/688.0097/1585.8152 ms and adapter boundary
5.7577/2537.4690/4689.0379 ms. These are host/contention measurements, not
evidence that Assurance adds those costs: Assurance was disabled and unregistered.
No latency limits have been relaxed.
Exact baseline benchmark JSON and report digests are retained in
[benchmark context](evidence/baseline-benchmark-context.json),
[safety report](evidence/baseline-safety.json) and
[integration report](evidence/baseline-integration.json).

The [installed baseline recheck](evidence/baseline-failed-case-recheck.json)
confirms 11 previously failing tests pass with correct package installation and
workspace-scoped escalation, including installed hook/runtime smoke tests and
promoted regression replay. The five remaining failures are two integration
latency tests, one safety latency test, SQLite concurrent-session contention,
and the existing quickstart's missing `sh` executable on Windows. Private raw
test/JUnit output remains in `.assurance-work/baseline-recheck-1`; the tracked
summary omits the machine hostname and retains exact case IDs and hashes.

## M7 delegation containment, lifecycle and child integration

`DelegationAuthority` is data only. The pure verifier retains filesystem,
network/protocol/method/path/exact request, tool, process/privilege/credential and
approval rights, checking the child against parent/operator/task maxima. Accepted
rights are the requested subset of their intersection; broader proposals refuse
issuance. Unrepresentable child wildcard languages and any-executable rights
remain unsupported rather than dropped. A protected host issuer checks current
ancestry, policy/profile/source identity, lifetime/depth/cycles/duplicate IDs and
quotas before creating a private immutable `IssuedDelegation`. JSON artifacts
cannot restore current authority.

Revocation invalidates descendants and pending/cached uses. Clock rollback and
host configuration changes fail closed. Per-child `IntegrationSession` state
retains denied proposals and is isolated across concurrent siblings. The wrapper
preserves core/profile requirements and checks complete derived operation
requirements, supplies current delegated-profile assessments through a fresh
review, and reserves bounded use tickets only for executable results. Final use
binding is rechecked under the issuer lock and consumed once. No credential/OS
permission or atomic kernel execution is minted; the external broker must enforce
rights and exact bytes when forwarding.

Cross-agent graphs require current private parent/child relationships and sealed
delegated child results. Node identities include host scope; local IDs/tool names
cannot collapse siblings. Delegation denials remain counterevidence. Explicit
source lineage references retained parent actions and exact child bytes; causation
and completed transfer remain unproven. Typed collectors reject JSON/fabricated/
sibling backend observations. See [delegation](delegation.md).

Actual checks:

| Gate | Result |
| --- | --- |
| Pure subset/lifecycle, `.assurance-work/m7-lifecycle-recheck` | 8 passed, 1.01 s |
| Child gate/issuer/schema, `.assurance-work/m7-child-gate` | 17 passed, 3.96 s |
| Commit/configuration races, `.assurance-work/m7-use-binding-races` | 19 passed, 2.96 s |
| Exact MCP args, collector identity, normal test controls, `.assurance-work/m7-runtime-identity` | 3 passed, 1.18 s |
| Cross-agent and existing graph tests, `.assurance-work/m7-cross-agent-evidence` | 18 passed, 8.08 s |
| Integrated delegation/property gate, `.assurance-work/m7-integrated-delegation` | 43 passed, 81.45 s |
| Full assurance/audit, `.assurance-work/m7-full-source-gate` | 258 passed, 1 POSIX skip, 100.29 s |
| Existing public API/agent/session/boundary/request/runtime-observation compatibility, `.assurance-work/m7-core-session-compatibility` | 140 passed, 1 POSIX skip, 92.72 s |
| Linux-target mypy | 24 source files clean; no POSIX runtime result implied |
| Ruff and diff checks | Passed |

The first cycle assertion received the conservative ambiguous-parent rejection;
self/cycle detection now precedes that check and the lifecycle recheck passes.
Concurrent reviews and commit-time mutation tests inspect actual issuer/session
state. M5's delegation generator now assesses 32 all-domain cases with zero
disagreement and detects 24 failures in the explicit synthetic overlap checker.
The full suite now assesses **276/320** with **44** ambiguous-path/provider cases
unresolved. Earlier pinned M5 evidence remains unchanged at its original SHA.
Parity totals **25 Assurance contracts / 65 registered schemas**. New wheel,
example and pinned evidence checks follow; full release/latency, scanner/model
and final acceptance gates remain open.

The [pinned delegation evidence](evidence/m7-delegation.json) records source
`edd661204ae8426aa4d491e8df1cd3dd31c69b3b`: an exact source read is executable,
an `.env` read is denied, the authenticated cross-agent path retains blocked
reachability, and parent revocation invalidates both parent/child and the pending
use. The actual delegation challenger assesses 32 cases with zero disagreement;
its explicit synthetic checker reports 24 reproduced failures. The runnable
`python -m examples.assurance.delegation --output .assurance-work/m7-sdk-example`
exercises those current state changes and reports no action execution.

The [final delegation wheel evidence](evidence/m7-wheel.json) matches **266**
packaged Python/JSON files to that source. A fresh local wheel install checks
private issuance/child review/pending revocation with socket/subprocess calls
rejected inside the SDK. **65 schemas / 25 Assurance schemas**, installed doctor
and wheel/sdist metadata checks pass. Capture/example mypy also passes. No live
credentials, OS permission grant, physical execution boundary, scanner/model,
publication or deployment occurred. All checkpoint handles are terminal.

## M8 offline Codex Security importer

Official OpenAI documentation was searched and opened first using the OpenAI Docs
skill. The referenced repository commit
`6f4c62875baa310c6f18608035309e77bc8e808b` was then fetched read-only: SDK package
version `0.2.0`, exact native schemas/examples and Apache-2.0 license. Individual
schema Git blobs are pinned and checked at load; upstream code is never imported
or executed. The pinned repository supports both positional export directories
and `--scan`, policy and threat-model exports; the online reference describes the
positional export shape. These are distinct inspected contracts, not guessed CLI
flags. No scanner, Node install, API key or provider call occurred.

The normal wheel includes the zero-dependency data-only API at
`ordin.assurance.codex_security`; the requested adapter path
`integrations/codex_security/ordin_codex_security/importer.py` reexports it in a
separate optional namespace. Native documents and sealed byte hashes are checked
under a bounded, unlinked authorized output root. JSON duplicate/nonfinite/
depth/unsafe-control/unknown-field checks, reference/link validation, scan identity,
source revision and coverage checks refuse malformed or conflicting artifacts.
SARIF 2.1.0 uses a bounded claim-only subset with no external URI/property loads.
Lossless private captures retain severity/confidence/scores, all occurrences and
duplicates, code/locations, validation/counterevidence, attack paths, remediation,
links and metadata. Public summaries omit raw narrative, paths, vendor IDs and
threat-model instructions. Imported findings remain `imported`/`imported_claim`
with no independent verification; a vendor `confirmed` field cannot close one.

`ordin-assure codex import` runs without scanner/credentials/network. Complete
valid import is exit 0; partial/unknown/malformed is 2. An explicit reported
severity threshold can return 1 for complete imports without claiming Ordin
confirmation. Missing/renamed source references and failed/partial/unknown scans
never imply complete coverage. Source-validated conversion yields only draft
restriction suggestions; untrusted Markdown cannot select policy or execute code.

Actual checks:

| Gate | Result |
| --- | --- |
| Native JSON focused recheck, `.assurance-work/m8-preserved-byte-text` | 17 passed, 0.92 s |
| JSON/SARIF, `.assurance-work/m8-json-sarif-import` | 27 passed, 2.58 s |
| Import/schema/audit, `.assurance-work/m8-import-contract-gate` | 41 passed, 5.82 s |
| CLI/hostile import gate, `.assurance-work/m8-cli-hostile-import` | 50 passed, 5.10 s |
| Source-backed draft conversion, `.assurance-work/m8-source-draft-conversion` | 26 passed, 2.28 s |
| Pinned-schema hash recheck, `.assurance-work/m8-pinned-schema-integrity` | 36 passed, 4.32 s |
| Full assurance/audit, `.assurance-work/m8-importer-source-gate` | 294 passed, 1 POSIX skip, 124.09 s |
| Core API/agent/schema/package compatibility, `.assurance-work/m8-source-resource-parity` | 19 passed, 7.55 s |
| Linux-target mypy importer/CLI | 6 source files clean |
| Ruff/diff checks | Passed |
| `python -m examples.assurance.codex_import --output .assurance-work/m8-offline-example` | Zero findings with partial coverage remains partial/unconfirmed |

Initial native mapping exposed that the finding schema lacked the explicitly
required `imported` status; it was added while confirmation remains private-host
gated. The Markdown comparison initially differed due to Windows CRLF writes;
the test now compares the exact bytes supplied, without text normalization.
Core resource parity initially found three extra packaged vendor schemas; exact
source copies were added under `data/codex_security` and the core gate rechecked
green. No validation limit was relaxed or failure hidden. Current parity totals
**27 Assurance contracts / 67 registered schemas**. The live optional wrapper,
offline diff triage, optional CI example and final M8 acceptance remain pending.
See [the integration contract](codex-security-integration.md).

The [pinned offline import capture](evidence/m8-offline-import.json) records source
`7fa6d65c646619986d4e96043a3209ea8ad44e81`. Zero-finding partial native artifacts
remain **partial**, a complete matched synthetic native scope imports as complete
without finding confirmation, and zero-result SARIF remains **unknown**.
No actual security scan occurred. The [core importer wheel evidence](evidence/m8-import-wheel.json)
byte-matches **276** packaged Python/JSON files to that source and verifies
**67 schemas / 27 Assurance schemas**, installed doctor and offline JSON/SARIF
import with socket/subprocess construction rejected in the SDK smoke.

The [separate adapter wheel check](evidence/m8-adapter-wheel.json) installs only
the local core and `ordin-codex-security` wheels with `--no-index --no-deps`, then
imports `ordin_codex_security` under `-I` outside the checkout. The namespace and
pinned schema load succeed with subprocess/network calls rejected; no scanner
or model package is loaded. Both wheel/sdist pairs pass twine metadata checks.
Capture/check helpers pass Linux-target mypy. All checkpoint handles are terminal;
the optional live wrapper/diff/CI work remains M8 scope, not claimed complete.

## Outstanding limitations

- The artifact/profile/gate foundation is functional; it is not a complete
  Assurance system. M3 acceptance gates remain open; M4 simulator is functional;
  M5 has expanded generated properties, M6 has graph/source-flow SDKs and M7
  has delegation/lifecycle integration. Dependent provider/optional proof work
  and remaining M8–M12 work is incomplete. All AT-01–AT-35 require
  integrated implementation and current evidence before overall completion.
- `ApprovedSecurityProfile` now has a protected selection loader/compiler.
  Host-declared filesystem guarantees/mappings still require actual external
  enforcement. Graph/finding/delegation/model records do not implement their later analysis/issuance/provider
  workflows. No feature milestone is complete merely because its record exists.
- Installed tooling differs from requested development minimums: pytest 9.0.3,
  mypy 1.20.2, ruff 0.15.11, twine 6.2.0; build 1.5.0 is available. CI must test
  declared versions. Dependency installation failure must not be reported as
  successful setup.
- Only Windows/Python 3.13 is locally available. POSIX/multi-version checks need
  CI evidence.
- Protected host configuration, authenticated runtime channels and OS capability
  enforcement remain external host responsibilities.
- No remote provider/scanner evaluation, weights, credentials, publication,
  policy mutation, release, merge or real attack has occurred.

## Operator-review items

The final implementation needs ordinary code review before integration. This
work does not authorize scanner uploads, hosted inference, remediation
installation, publication or deployment.

## Next implementation actions

Retain the completed full-suite failures/skips and verify the audit fixes at the
next full release gate. Resolve end-to-end latency without weakening the declared budget. The next
independent feature is M6 bounded evidence/attack-path reconstruction and source
flow assessment, followed by M7–M12. Same-host graph/source-flow SDK work is now
verified; M7 containment/lifecycle and authenticated cross-agent graphs are now
implemented. The next independent feature is M8 strict offline Codex Security
JSON/SARIF import before any optional scanner wrapper. Keep dependent M5 provider checks,
optional finite solver/promotion work and the release gates open; expanded
generated checks are not proof of the full objective.
Carry the existing Windows shell/latency/SQLite failures into the compatibility
audit; they must be resolved or explicitly verified on supported platforms
before any full completion claim. No background evaluation remains running.
