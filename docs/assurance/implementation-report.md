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
- Scanner/diff/optional CI implementation SHA: `4d3fb8d8879c230b7c9e6c2970b91cecafd5dc4f`.
- Optional semantic protocol/routing/TypeSafe SHA: `ea3d4778c3ad83ed20bb660a6a96232f9f30d3dc`.
- Local model worker/evaluation SDK SHA: `26297fcc98d0a9cfdb4c61fbe343685fe0ffbeee`.
- Async measurement/frozen workload SHA: `261685d28e0de3fb9e0ff500e8aa4964c44610f5`.
- Scoped finding/policy-fix SDK SHA: `d24ccd4978a8ff6bb41dbe160425eca5cff21068`.
- Vetted synthetic broker/source-fix SDK SHA: `4da87e3d4ba0f500133febedc96cf54095a97410`; capture-summary correction: `e55dd9acd31c24c53a3e187a529504227741e9aa`.
- Offline external workflow claim SDK/CLI SHA: `17423386c9662cfc85a0ed1a4dbb66ba85e9572c`.
- Offline CLI/API/quickstart and adapter composition SHA: `74e41a2cbf92561c4ea097f9f661f23243bb1ea1`.
- Offline acceptance plan/CI SHA: `604f8db5bf0ea5a83053ddd941a131cc55a62781`.
- Installed-fixture correction SHA: `36e6392010eb2f3b2e014697bf2c43a90c7d6f1e`.
- M12 measured candidate / portable quickstart SHA: `cba13c975b0b780de2fdbf67e995f47952e2f5d9`.
- Review-scoped catalog snapshot / current measured candidate SHA: `04f40d05d85aeab244c149757a6a0a0e655ad060`.
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
| M8 | offline_sdk_mock_diff_verified_live_boundary_unverified | Pinned importer, explicit scanner selection/configuration/consent/isolation, fake-process tests, offline source/authority diff and optional private CI example; source gate 335 passed / 1 POSIX skip; core compatibility 47 passed / 2 skips; pinned core/adapter wheel/doctor/metadata checks pass; real scanner/host isolation/CI unverified |
| M9 | provider_sdk_async_measurements_provisional_workload_verified_real_acceptance_pending | Protected protocol/routing, TypeSafe and pinned local worker, measured threshold provenance, sync/async replay and 24-case provisional sample; source gate 432 passed / 1 skip; actual model/hardware and independently labeled effectiveness acceptance remain unverified |
| M10 | vetted_source_fix_external_claim_import_verified_physical_broker_broader_lifecycle_pending | Vetted source/policy proof plus offline validation/patch/fix/risk claims, manifest scope and separate reported verdicts; 510 passed / 1 skip; physical isolation, generic predicates and integrated lifecycle remain open |
| M11 | offline_cli_api_quickstart_adapter_composition_verified_platform_acceptance_open | Fresh wheel, six diagnostic contracts, typed host composition and five-minute offline quickstart; 525 passed / 1 skip; affected host source suite 198 passed / 1 environment failure / 3 skips; installed process evaluation 17/17; OpenShell 363 passed / 13 unavailable-prover skips |
| M12 | current_full_suite_integration_pass_catalog_snapshot_verified_remaining_latency_acceptance_open | 35 mapped fixture scenarios / 89 tests pass, six partial scopes; authored Linux/Windows 3.10–3.13 offline CI; current installed all-suite 1904 passed / 40 skips / zero failures; integration and functional corpus/process gates pass; standalone safety p95 and added-overhead latency remain failed |

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
green. No validation limit was relaxed or failure hidden. That importer checkpoint
had **27 Assurance contracts / 67 registered schemas**. The subsequent scanner/
diff/CI slice is recorded below; its external live boundary remains unverified.
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

## M8 scanner wrapper, deterministic diff and optional private CI

The optional scanner SDK pins native runtime/entrypoint/helper locations and
hashes, inspects the actual version/help/metadata, requires immutable base/target
Git objects, rejects unreviewed or changed configuration, and binds upload consent
and actual protected host isolation assessment to that exact action. The broker
must enforce read-only target, immutable installation/configuration, private
state, credential routing, executable/MCP/hook restrictions and approved service
egress. Those receipts cannot be restored from JSON; the SDK creates no physical
sandbox or credentials. The current live command contract is pinned to 0.2.0.

Fixed subprocess arrays use `shell=False`, isolated environment, bounded output/
deadlines and cancellation. Windows starts suspended, joins a kill-on-close job
and then resumes; POSIX uses a process session, with no POSIX execution result on
this host. Ordinary descendants end after timeout/cancel/overflow and normal
completion. Native exit 1 with a complete matched import remains severity
violation. Partial/unknown/malformed exports never become success. Routine
reports retain actual exit states and hashes/counts without raw source/tokens.
The separate adapter exposes this API as `ordin_codex_security.provider`.

Offline `triage_source_diff`/`source diff` compare authorized bounded snapshots,
profiles and optional typed policy/authority. Protected surfaces, new subprocess/
network/tool syntax, enforcement/MCP/host boundary and dependency changes require
review. Authority deltas reuse the existing full-domain comparator; unsupported
algebra and inspection gaps remain partial. Documentation-only and policy-only
fixtures are distinct. These finite heuristics can miss aliases/dynamic dispatch
and prove neither reachability nor exploitation. Profiles remain inspection
data. `codex mock` preserves 0/1/2/130/143 without launching a process.

The private CI example remains outside active workflows. It permits only an
explicitly approved manual source upload on private protected main/environment,
with a separately installed pinned scanner/Ordin and ephemeral isolated runner.
It retains redacted advisory JSON with three-day private retention and propagates
severity/incomplete/interrupted/timeout states after import. The local workflow
guard passes; no remote workflow/scanner/upload was enabled or run.

Actual checks:

| Gate | Result |
| --- | --- |
| Fake-process consent/isolation recheck, `.assurance-work/m8-scanner-receipt-recheck` | 21 passed, 13.51 s |
| Final scanner/diff/contract focus, `.assurance-work/m8-scanner-diff-reviewed-gate` | 42 passed, 23.35 s |
| Diff/inventory/contract recheck, `.assurance-work/m8-diff-valid-network-recheck` | 30 passed, 5.59 s |
| Full Assurance/audit, `.assurance-work/m8-final-scanner-diff-source-gate` | 335 passed, 1 POSIX skip, 142.05 s |
| Existing API/agent/schema/security/Codex compatibility, `.assurance-work/m8-scanner-core-compatibility` | 47 passed, 2 skips, 13.35 s |
| Linux-target mypy, Assurance/adapter/example/wheel helper | 35 files clean; capture helper also clean |
| Ruff/diff/workflow checks | Passed |
| Synthetic `examples.assurance.source_diff` | Documentation edit and new subprocess sink separately flagged; no target execution |
| Actual `codex mock --exit-code 1` CLI | Exit 1, advisory severity-violation JSON, no process/network |

The initial sandbox run could not pin Windows user/runtime ancestors (20 setup
errors); authorized local tests with Windows handle access reached the cases.
The wrong fixture assessment kind was replaced by an explicit scanner-isolation
kind. A widening fixture initially supplied unknown protocol/access and correctly
returned unsupported; it now supplies supported TCP/write rights, while unknown
rights remain unsupported/partial. No validator/resource limit was weakened.
Parity totals **29 Assurance contracts / 69 registered schemas**. The fresh core
wheel/doctor passes with SDK socket/subprocess creation rejected; both core and
adapter wheel/sdist pairs pass twine. The adapter's new smoke initially used an
incorrect loader name; its corrected fresh environment passes namespace/provider,
mock and pinned-schema imports with network/process creation rejected. Eight
adapter package files match source bytes.

The [pinned scanner/diff capture](evidence/m8-scanner-diff.json) retains actual
source-gate cases and synthetic offline state/triage results at source revision
`4d3fb8d8879c230b7c9e6c2970b91cecafd5dc4f`.
The [fresh core wheel evidence](evidence/m8-scanner-diff-wheel.json) byte-matches
281 packaged Python/JSON files, passes installed doctor, and exercises the new
mock/diff APIs with socket/subprocess creation rejected inside the SDK.
The [fresh optional adapter check](evidence/m8-provider-adapter-wheel.json)
matches eight package files and verifies namespace/provider/pinned-schema/mock
imports under `-I` with only local wheels and no index/dependencies.
All checkpoint handles are terminal. No real scanner, model, account, upload,
execution grant, publication, deployment or remote runner was used.
See [the integration contract](codex-security-integration.md).

## M9 protocol, privacy, routing and TypeSafe contract

The separate `ordin-decision-models` namespace has no heavy base dependency.
Ordinary Ordin import/construction/commands never load or call it. Protocol input
contains only bounded immutable state and fixed versioned yes/no questions, never
tools or host issuance objects. Protected task origins and exact source/use bytes
are checked against the current action/profile/history/context review; snippets
are selected explicitly. Credentials are omitted and private/unknown classification
refuses hosted use. Object representations and routine summaries hide selected
private text; `as_dict()` remains explicit private model input for host review.

Host-authenticated exact-action inspection triggers cover ambiguity, unclear
effects, proximity to a boundary and cross-agent work. Ordinary low-risk actions
with no question skip inference. Default mode is disabled; shadow preserves
disposition, and enforced mode can add escalation, retain core asks, or refuse
stale configuration. A hard deterministic denial makes zero provider calls.
Mandatory classes fail closed for missing context, outage, malformed/uncertain
answers and exhausted budgets. Sync timeouts retain concurrency leases until the
actual worker finishes; async cancellation propagates. This does not terminate
arbitrary native model code or provide a physical sandbox.

The public TypeSafe schema was inspected read-only at `api.typesafe.ai/openapi.json`
(0.2.0). The adapter is async-only and explicitly discovers model names, pins the
expected response version, batches fixed `noul` questions and validates names,
finite probabilities, schema/usage and byte/deadline limits. It fixes HTTPS host/
port, pins operator-selected CA bytes, ignores proxy environment, refuses redirects
and unsupported framing, and performs no retry. Discovery and inference enforce
their own deadline even for custom transports. No live account/TLS API was tested.

Actual host disclosure approval and conclusive credential/egress/spend assessment
bind the exact input/question/model/configuration, source/profile, short lifetime
and bounded request count. Only a primitive receipt reaches the provider. The API
offers no per-request currency cap; actual account/gateway spend enforcement must
be verified by the host, not inferred from token counts. JSON consent/role text
cannot authenticate these controls. Provider outputs remain predictions and cannot
grant permission, close a finding or become a backend observation.

Laya 0.4.1 source tag resolves to `1adc59f7e371deb601fcfa18a14e25db238addcc`;
individual source blobs and the model-card license/revision are recorded read-only
under integration resources. Its default Router downloads checkpoints and its
loader can modify tokenizer configuration; none was imported or executed here.
Local checkpoint/worker implementation and held-out security metrics remain M9
work. Upstream generic accuracy/calibration/performance is not Ordin evidence.

Actual checks:

| Gate | Result |
| --- | --- |
| Initial routing/model contract recheck, `.assurance-work/m9-routing-unknown-risk-gate` | 83 passed, 8.81 s |
| Bound inspection trigger recheck, `.assurance-work/m9-bound-triggers-gate` | 83 passed, 9.69 s |
| TypeSafe/routing/contracts, `.assurance-work/m9-typesafe-first-gate` | 47 passed, 13.96 s |
| Actual HTTP parser over simulated streams plus API/routing, `.assurance-work/m9-https-routing-gate` | 57 passed, 15.26 s |
| Direct client/deadline gate, `.assurance-work/m9-direct-client-deadline-gate` | 59 passed, 12.47 s |
| Strong actual core-ask test, `.assurance-work/m9-explicit-core-ask-gate` | 21 passed, 5.55 s |
| Earlier combined source gate, `.assurance-work/m9-reviewed-routing-typesafe-source-gate` | 394 passed, 1 POSIX skip, 113.99 s; final post-review source gate follows |
| Final post-review source gate, `.assurance-work/m9-final-ask-binding-source-gate` | 394 passed, 1 POSIX skip, 110.44 s |
| Core API/agent/schema/security/Codex compatibility, `.assurance-work/m9-routing-typesafe-core-compatibility` | 47 passed, 2 platform skips, 10.28 s |
| Linux-target mypy, optional package/capture/wheel helper | 10 files clean |
| Ruff/diff | Passed |
| Fresh core wheel/doctor | 74 schemas / 34 Assurance schemas; SDK socket/subprocess construction rejected |
| Fresh optional wheel smoke | Default zero provider calls; isolated offline demo; no actions, weights, heavy model imports or SDK network/process creation |
| Core/optional wheel and sdist twine metadata | All four passed |

Initial schema helper/name errors were corrected before runtime validation.
Unknown core risk initially failed the new state schema and is now retained as
unknown. The first optional wheel spy replaced `Popen` with a function, preventing
Windows asyncio's subclass definition; a class now rejects process construction
while allowing normal library import. The permissive-core-ask fixture was made
explicit with an actual core policy rule so a low model score cannot silently
execute it. No validator, privacy guard, time budget or baseline restriction was
weakened. Model effectiveness has not been evaluated and M9 is not complete.

The [pinned protocol/TypeSafe evidence](evidence/m9-protocol-typesafe.json) records
source `ea3d4778c3ad83ed20bb660a6a96232f9f30d3dc`, actual final test cases and
the fresh optional package smoke. Nine packaged optional Python/JSON files match
source; the offline example has zero default calls, shadow parity and enforced
escalation, with SDK socket/process creation rejected and heavy model imports
absent. The [fresh core wheel evidence](evidence/m9-protocol-core-wheel.json)
matches 286 packaged Python/JSON files to that source and checks installed doctor
with **74 schemas / 34 Assurance schemas**. Core dependencies remain empty.
All checkpoint handles are terminal. No real model, credential, source upload,
scanner, execution grant, remote runner, publication or deployment was used.
See [decision models](decision-models.md).

## M9 local checkpoint/worker and evaluation SDK

`LocalCheckpoint` pins an explicit complete local artifact set, revision label,
device, token and byte budgets. Bounded readonly readers reject linked/hardlinked/
special files, unexpected executable artifacts, duplicate/nonfinite JSON, changed
hashes and custom remote-code config. Tokenizer vocabularies have separate bounded
file/structure limits; ordinary advisory JSON limits are unchanged. Tokenizer
config requiring upstream mutation refuses; the host prepares/reviews/pins it
separately. Published checkpoint metadata URLs were attempted read-only but were
inaccessible to the web tool; no missing bytes/hashes were invented or downloaded.

`LocalModelRuntime` selects pinned native Python and fixed worker, trusted cwd,
fresh private home, reviewed transitive installation and target exclusions. Local
setup requires actual protected approval plus conclusive broker assessment of
no-egress/read-only/credential/resource isolation. The primitive setup receipt is
one-use, expires and grants no tools/host issuance interface. Paths outside target
and enclosing Git roots are required. Offline child environment excludes ambient
keys and model Hub downloads; those flags do not create physical isolation.

Explicit initialization verifies version/device/hash handshake and starts a
persistent worker. Only that worker imports Laya/torch and loads selected files.
Bounded JSON requests/replies bind IDs, input/questions/checkpoint. Truncation or
collapsed options refuse support. Runtime configuration drift, quota/expiry,
malformed/oversized output, setup/call timeout and cancellation stop the worker
and ordinary descendants. Windows uses its existing Job Object management; POSIX
execution remains unverified. Routine diagnostics remain hashes/counts. No actual
ML package or weight file was loaded in the tests; the worker fixtures are trusted
synthetic Python programs and their claims are not real inference evidence.

Semantic providers now receive selected semantic content without opaque audit
hashes consuming model context. The complete sanitized record/digests still bind
the current review and hosted disclosure. Real-provider API recipes default to
disabled and require externally obtained current scope/provider/inputs.

`evaluation.py` has frozen synthetic corpus partitions, content duplicate/overlap
checks independent of renamed IDs, development-only threshold selection and
provider/threshold drift refusal. Independent precision/recall, tie-aware ROC,
step PR average precision, ECE/Brier and Wilson rate intervals retain undefined
empty/one-class metrics. Per-model metrics omit unsupported scores while aggregate
coverage retains hard deterministic blocks, abstentions, ambiguous cases, critical
misses and friction. Timing includes input review/routing; families retain coverage
and miss counts. These are harness capabilities, not an independently labeled
frozen security corpus or effectiveness result. Actual frozen workloads, async
held-out driver, hardware/resource metrics and acceptance remain open.

Actual checks:

| Gate | Result |
| --- | --- |
| Synthetic local worker first gate, `.assurance-work/m9-laya-worker-first-gate` | 16 passed, 14.33 s |
| Pin/configuration/quota/cancel gate, `.assurance-work/m9-laya-binding-gate` | 21 passed, 11.82 s |
| Hand-calculated metrics, `.assurance-work/m9-semantic-evaluation-first-gate` | 6 passed, 3.59 s |
| Semantic provider projection/API/routing, `.assurance-work/m9-minimal-provider-context-gate` | 54 passed, 8.13 s |
| Local worker/evaluation/contracts, `.assurance-work/m9-local-worker-evaluation-gate` | 88 passed, 31.89 s |
| Full Assurance/audit/providers, `.assurance-work/m9-laya-evaluation-source-gate` | 424 passed, 1 POSIX skip, 159.46 s |
| Core API/agent/schema/security/Codex compatibility, `.assurance-work/m9-laya-core-compatibility` | 47 passed, 2 skips, 13.77 s |
| Linux-target mypy, Assurance/optional provider package | 45 files clean; capture/wheel helpers also clean |
| Ruff/diff | Passed |
| Fresh core and optional wheel smoke | Passed with socket/process creation rejected, zero default calls, no heavy model imports/weights/actions |
| Core/optional wheel/sdist twine | All four passed |

Initial type annotations and metric accumulator naming were corrected; no validator
was weakened. Input writes gained deadline management, setup receipts became
one-use, expiry/configuration changes stop the worker, and precanceled setup
refuses before launch. A broader tokenizer parser was necessary for actual-sized
vocabularies; its limits are explicit and do not relax advisory records. This
checkpoint proves local SDK/fake IPC and metric behavior only. M9 acceptance is
incomplete, and no real model efficacy/calibration claim is made.

The [pinned local worker/evaluation capture](evidence/m9-laya-evaluation.json)
records source `26297fcc98d0a9cfdb4c61fbe343685fe0ffbeee`, actual source-gate cases
and the isolated optional install smoke. Fourteen optional Python/JSON package
files match source; default calls remain zero and heavy packages/weights/actions
remain absent. The [fresh core wheel evidence](evidence/m9-laya-core-wheel.json)
matches 286 package Python/JSON files to that source, verifies installed doctor
and **74 schemas / 34 Assurance schemas**, with SDK sockets/process creation
rejected. All checkpoint handles are terminal. No actual checkpoint, credential,
source upload, execution grant, remote runner, release or deployment was used.

## M9 async measurements and frozen provisional workload

Source `261685d28e0de3fb9e0ff500e8aa4964c44610f5` adds synchronous and
asynchronous development collection in shadow mode. Immutable collector receipts
bind actual case/evidence/state digests, provider and inspection configuration.
Measured threshold fitting requires all unambiguous controls; refusals, timeouts,
deterministic skips and exhausted budgets cannot disappear from calibration.
Measured thresholds require an actual selection receipt; imported JSON or edited
copies cannot attest a run. Lower-level supplied-score fitting remains explicitly
identified as caller-supplied provenance. Mid-run routing/provider changes refuse
collection, and held-out replay checks the frozen inspection selection.

`evaluate_corpus_async` shares reporting with synchronous replay and retains
router deadlines, cancellation, privacy and call limits. A host-side
`AsyncProviderSessions` factory prepares a fresh actual disclosure receipt only
after routing selects a call. It receives selected state/questions rather than
case labels, host issuance objects or tool execution. Tests exercise two separate
TypeSafe disclosures over fake HTTPS, wrong provider selection, factory timeout,
cancellation and zero factory calls on deterministic denials.

The frozen sample under `benchmarks/assurance/v1/semantic/` has **24 cases**:
eight per development/held-out/shift partition, each with three harmful, three
benign and two ambiguous labels. These are distinct authored task/control
situations. Content/family overlap is rejected even after renaming labels/family
IDs. The manifest binds bytes, schemas, provenance, source permissions, label
protocol and supported coverage. Corpus-local Git attributes preserve LF hash
bytes on Windows checkouts. Label adjudication is **not independent**, and the
manifest explicitly refuses acceptance eligibility. This sample does not meet
the full 100 harmful/100 benign acceptance corpus requirement.

The installed mock-only driver ran both sync and async paths on the same frozen
sample. Each had six mode/partition arms and 38 calls including development.
Both fit threshold 1.0 from fixed mock scores; final dispositions matched.
Held-out harmful executable count stayed **2/3** in disabled, shadow and enforced
modes. Shift harmful executable count stayed **0/3** because deterministic rules
already restricted those cases. New benign escalation rate was zero. These
results demonstrate accounting without any semantic effectiveness improvement.
Observed full harness p95 ranged from **358.67 to 1157.18 ms** across these single
arms, including input preparation, repeated review and collection checks. They
are not production provider latency measurements or matched repeated acceptance
runs. The existing failed M3 added-latency budget is unchanged.

Actual gates:

| Gate | Result |
| --- | --- |
| Focused async/measurement/consent/freeze tests | 16 passed, 10.60 s; final selection-receipt check 16 passed, 9.69 s |
| Final complete Assurance/audit/provider gate | 432 passed, 1 POSIX skip, 181.41 s |
| Core API/agent/schema/security/Codex compatibility | 47 passed, 2 skips, 11.40 s; restricted pytest cache write warning |
| Linux-target mypy | 51 source/helper files clean |
| Ruff and Git diff checks | Passed |
| Optional wheel/sdist build and twine | Passed |
| Fresh offline optional wheel install | 17 packaged Python/JSON files matched; import/default/mock/frozen workflow passed with sockets/process creation rejected |
| Installed frozen-workload CLI | Sync and async completed; disposition parity; no actions, weights, real model or network |

The initial restricted full gate had **389 passed, 20 failed, 23 fixture errors,
1 skipped**, because external temporary fixture ancestor handles were denied
and a dependent challenger produced no cases. The final complete local fixture
run passed with the needed access. No ACL was changed. A hosted test's nonexistent
action digest property was corrected before the final source gate. The first
adapter build preceded the selection-receipt hardening and was replaced by a
fresh final build; only the final wheel is captured.

[Pinned evaluation evidence](evidence/m9-frozen-evaluation.json) records the exact
implementation revision, source-gate cases, wheel smoke, manifest and both
redacted mock runs. Core code/schema/package configuration is unchanged from the
previous local-worker source; the existing core wheel was reused for this fresh
optional install. Real provider/hardware/memory/cost, independent labels,
predeclared held-out benefit/friction/latency acceptance and M9 completion remain
unverified. No background handles remain live.

## M10 scoped finding validation and policy-fix SDK

Source `d24ccd4978a8ff6bb41dbe160425eca5cff21068` adds explicit rubric,
source-review, validation, remediation and fix receipts. Reviews retain the
original candidate digest, actor/control/permission declarations, invariant and
expected authority, source-to-sink references, existing controls, preconditions,
changes and unknowns. Source byte/revision/symbol checks are read-only; declared
whole-repository snapshot pins are also enforced. Static control references are
counterevidence candidates rather than proof that a guard stops a path.

Static validation remains inconclusive about reproduction. The currently vetted
replay predicate is **gate_authority_subset**: an actual Assurance gate permits
a proposed contract beyond the explicit tested bound. Bounded exact JSON fixture
bytes become inert proposals; no target module or reviewed command runs. Missing
references, changed fixtures, unresolved preconditions/mappings and unregistered
vulnerability classes remain inconclusive. The resulting finding is about this
finite gate/configuration property, not source-code reachability or a real
repository exploit.

Host observation validation preserves exact action/contract/session/policy
correlation. Generic completion/allowance cannot establish an entire grant.
A protected `HostContractAuthorization` receipt is required for successful grant
closure, with exact event/contract/source binding; protected host code may issue
it only after actual whole-grant verification. SDK tests use synthetic channels
and do not independently establish physical backend enforcement. Denial can
refute the tested attempt; failure/unknown execution stays inconclusive.

Closed `SecurityFinding` records retain the validation digest and tested scope,
without transferring the original imported confidence. The original imported
record remains separate and unchanged. Source and test bytes are rechecked at
closure. JSON cannot recreate strong review/grant/validation/fix handles.
Duplicate grouping retains distinct occurrence-record digests, including when
caller IDs match; it never selects the strongest verdict or merges proof.

Remediation APIs return inert invariant drafts, detached policy proposals and
exact bounded single-file diff artifacts. No patch is applied or policy activated.
Private code/configuration review interfaces are explicit; public summaries
replace source, repository, invariant, action-kind and reproducer metadata with
digests as appropriate. Secret-looking synthetic metadata is absent from public
review/validation output.

`verify_fix` repeats the original failure first, then the candidate, preserved
benign counterparts, supplied alternatives and actual affected policy simulation.
Changed/deleted tests, missing provenance, widening/unknown containment, benign
regressions and unresolved predicates prevent a verified result. Surviving paths
produce `still-vulnerable`; a narrower policy plus preserved supported controls
can produce `fixed-verified` within **policy_replay**. Source patches remain
inconclusive because target code was not exercised. Reports retain measured
latency samples and explicitly exclude matched performance/release acceptance.
The existing M3 deterministic latency budget is unchanged and still failed.

Actual gates:

| Gate | Result |
| --- | --- |
| Pure validation predicate/source tests | 15 passed, 1.99 s |
| Finding/fix adversarial cases | 25 passed, 6.25 s |
| Final snapshot/closure/schema/audit focused gate | 45 passed, 12.25 s |
| Initial complete Assurance/audit/provider gate | 460 passed, 1 POSIX skip, 160.60 s |
| Final complete gate after snapshot-pin guard | 461 passed, 1 POSIX skip, 166.61 s |
| Core API/agent/schema/security/Codex compatibility | 47 passed, 2 skips, 13.48 s |
| Linux-target mypy | 55 source/helper files clean |
| Ruff/diff checks | Passed |
| Final core wheel/sdist build and twine | Passed |
| Fresh offline core wheel install/doctor | 298 Python/JSON package files matched; 81 schemas / 41 Assurance schemas; synthetic finding/fix SDK example passed with sockets/process creation rejected |

Initial fixture errors used the wrong tool capability argument order and an
incorrect action-policy class name. They were corrected against actual core
signatures; no policy/test bound was weakened. A default-threshold assertion was
corrected to the existing `warn` value. An attempted generic backend metadata
extension was rejected by the existing schema; the separate protected entire-
grant receipt implements the needed optional fact without changing that runtime
schema. Source/fixture closure provenance and explicit repository snapshot pins
were tightened before the final gate/build. Only final artifacts are captured.

[Pinned finding/replay evidence](evidence/m10-validation-replay.json) records the
implementation revision, all final source-gate cases, fresh wheel/doctor output
and the redacted installed example. It confirms a synthetic gate configuration
violation and a narrow policy fix with preserved benign behavior; no target code,
live exploit, scanner/model network, credentials, applied patch or publication
was used. Every process/test/build handle is terminal.

M10 remains incomplete: vetted sandboxed target-code tests, broader finding/fix
predicates, independently exercised host setup, optional external Codex
validate/patch/verify-fix claim reports and integrated lifecycle CLI are open.
The actual finite proof scope is retained instead of treating a green suite,
source patch, imported verdict or compiled profile as complete security proof.

## M10 vetted synthetic broker and measured source fixes

Source `4da87e3d4ba0f500133febedc96cf54095a97410` adds an explicit
`VettedSandboxRuntime`, one-use protected setup scopes, bounded worker protocol,
synthetic source validation and code-fix verification. Capture-summary source
`e55dd9acd31c24c53a3e187a529504227741e9aa` clarifies that vetted synthetic code
executed while unvetted target code did not. No ordinary gate/import starts a
test, downloads code or selects a broker.

The host selects a pinned native broker, fixed installed `_sandbox_worker.py`,
complete argument allowlist, installation digest, private directories, target
exclusions and resource/output/deadline limits outside target/enclosing Git
roots. Actual protected approval plus a satisfied `validation_isolation` /
`validation.sandbox` assessment must bind the exact setup. The host must verify
real egress, credential, mount, installation and CPU/memory/process isolation;
environment stripping and Windows Job/POSIX group cleanup do not establish it.
Local tests use a **fake approved broker**, so physical isolation remains
unverified. No live scanner/model or privileged exploit was exercised.

The worker executes only a vetted `within_root(path, root)` function with one
return expression. Its bounded AST allows string inputs, slash/empty constants,
equality, boolean composition, addition, `startswith` and `rstrip`. Imports,
arbitrary calls/names, loops, decorators, annotations, dunder access and embedded
secret literals are rejected before launch. Comments/private source text are
stripped from the private code payload; original and normalized byte digests
remain separate. Audit JSON control-character limits are unchanged; the fixed
private transport explicitly carries vetted multiline code.

Pinned suite bytes contain unique canonical `/synthetic` path/root cases and
both benign and boundary controls. Expected behavior is independently computed,
with no imported labels or worker verdict. Worker replies must contain exact
request/source/suite bindings and ordered boolean results. Scope reuse/expiry,
source/installation drift, malformed or partial results, output overflow,
timeout and cancellation prevent closure. Output/diagnostics are retained as
hashes/counts. A spawned inherited-pipe descendant was measured terminated after
timeout; the result is not merely an inferred cleanup status.

`validate_finding_sandboxed` supports only the explicit
`synthetic_path_boundary` property. Findings retain the actual sandbox test
digest and exact source/test/runtime scope. `verify_source_fix` repeats original
execution before candidate execution, requires exact proposed file bytes and
unchanged fixture bytes, and compares host actor, runtime policy and protected
profile content. It distinguishes a correct canonical narrow fix, an ineffective
patch and a patch breaking benign behavior. Unknown changed semantics cannot
claim a non-widening proof. The known prefix-bug/canonical-fix relation applies
to all supported canonical lexical inputs, with broader/physical paths outside
coverage. No proposed patch is applied or integrated.

Actual gates:

| Gate | Result |
| --- | --- |
| Broker execution/protocol/lifetime gate | 17 passed, 6.17 s |
| Measured source fix and preserved fixtures | 5 passed, 7.28 s |
| Integrated source/finding/schema/audit gate | 67 passed, 23.89 s |
| Final expiry/source/descendant/fix gate | 24 passed, 18.56 s |
| Complete Assurance/audit/providers | 485 passed, 1 POSIX skip, 213.97 s |
| Core API/agent/schema/security/Codex compatibility | 47 passed, 2 skips, 14.86 s |
| Linux-target mypy | 60 source/helper files clean |
| Ruff/diff | Passed |
| Core wheel/sdist build and twine | Passed |
| Fresh offline installed wheel/doctor | 307 Python/JSON package files matched; 85 schemas / 45 Assurance schemas; network/process spies active; unapproved precanceled source test launched no broker |

Initial private transport reused audit JSON's newline ban and was replaced by a
separate bounded typed code transport without weakening audit validation. Windows
startup caused short parser/overflow fixture deadlines to report timeout; those
fixtures now have a separate 2-second allowance, while the timeout fixture keeps
300 ms. Descendant cleanup uses a measured child PID and its own 2-second limit.
Candidate fixture writing initially translated LF into CRLF, and exact patch
digest verification correctly refused it; writing the proposed bytes exactly
resolved the fixture error. The first installed smoke had missing `Path`/`sys`
imports in the smoke script; corrected fresh installation passed. No original
release or M3 latency threshold was changed.

[Pinned vetted-source evidence](evidence/m10-vetted-source.json) records the
candidate revision, actual final cases and installed-wheel smoke. Parameter IDs
derived from source text are replaced with correlation hashes in public evidence;
private source/comment fixture values are absent. All known process/test/build
handles are terminal and the tracked worktree is clean after checkpoint commits.

M10 remains incomplete: real broker controls, broader source/finding predicates,
external Codex validate/patch/verify-fix claim imports and integrated lifecycle
CLI still need implementation or verification. M9 real-model/independent-workload
acceptance, M11/M12 and the original full release/performance gates remain open.

## M10 offline external workflow claims and CLI

Source `17423386c9662cfc85a0ed1a4dbb66ba85e9572c` adds saved external
validation, patch, fix-verification and patch-risk import through the core SDK,
optional adapter facade and `ordin-assure codex import-workflow`. It starts no
scanner, model, exploit, reported command, patch, PR or upload. Native labels
including `reportable`, `verified`, `fixed`, `merge` and `auto_merge_candidate`
remain imported claims, with `closure=not_performed` and `authority_change=none`.

Primary contracts were inspected at the existing external pin
`6f4c62875baa310c6f18608035309e77bc8e808b`, not inferred from command names:
SDK validation disposition/report plus optional outputDir/threadId; CLI
repository/scan/result fix-verification; saved and supplied patch summaries;
and structured patch-risk schema. CLI validation prose is preserved without
inferring a verdict from headings. Supplied patch file changes do not establish
a verified fix. Unsupported embedded risk prose is retained privately with a gap.
The [contract guide](external-workflow-claims.md) links exact pinned sources.

The risk schema's exact Git blob is
`b89b932582bd31e3f0dcf7ddaff3b9366157b579`; source data, packaged and optional
copies match, under the retained Apache license. Source pin metadata also records
CLI/API/verification-contract blobs. The external schema parser now enforces
JSON const/enum numeric-type distinction, unique collections and property-count
limits. Artifact references never fetch alternative schemas or files.

An operator-saved companion capture records declared workflow, repository/revision,
tool/version, scan identity where applicable, native repository mapping, ordered
finding IDs, original artifact SHA-256, terminal status/exit and patch SHA where
needed. Missing/mismatched bytes, scope/version/scan/patch, incomplete or repeated
coverage and cancellation retain partial/unknown capture. A matching manifest is
internally consistent imported metadata, not runtime attestation or permission.
Fix-verification exit 0/1/2 is checked against reported fixed/vulnerable/inconclusive
results. Inconclusive results remain explicit claims rather than disappearing.

Private payload fragments preserve complete native evidence, multiline report,
code/path/instruction text and original metadata. Routine summaries hash identifiers,
scope, version and scan values and omit raw payloads. Altered payload/summary or
terminal-failure-to-complete relabeling is rejected. Duplicate occurrences keep
separate record identities. Explicit `--include-details` remains a private export;
no imported severity, result or risk recommendation activates policy or proves an
Ordin finding/fix.

Actual gates:

| Gate | Result |
| --- | --- |
| Native workflow + prior Codex/SARIF importer focus | 56 passed, 4.31 s; bound-summary rerun 56 passed, 3.75 s |
| CLI/schema/contract focus | 65 passed, 10.84 s |
| Prose/native/schema/audit focus | 76 passed, 6.42 s |
| Final workflow terminal/capture behavior | 25 passed, 1.77 s |
| Complete Assurance/audit/providers | 510 passed, 1 POSIX skip, 203.50 s |
| Core compatibility after parity repair | 47 passed, 2 skips, 10.15 s |
| Linux-target mypy | 66 source/helper files clean |
| Ruff/diff checks | Passed |
| Core and optional wheel/sdist builds + twine | All four artifacts passed |
| Fresh core wheel/doctor/import CLI | 312 Python/JSON package files matched; 88 schemas / 48 Assurance schemas; SDK/CLI claims remain imported under network/process spies |
| Fresh optional adapter wheel | 10 source files matched; workflow facade/pinned schema import passed with network/process rejection; no real scanner/model |

The initial compatibility run had **45 passed, 2 failed, 2 skips** because the
new risk schema was packaged without its matching `data/codex_security` source
copy. The source copy repaired parity and the unchanged compatibility assertions
passed. The core sdist contains the packaged schema; its source `data/` tree is
excluded by the existing packaging layout, as with previous resources. No rule,
label, mandatory check or original release/performance budget was weakened.

[Pinned workflow evidence](evidence/m10-external-workflow.json) captures the
candidate/source gate and fresh core smoke. [Optional adapter evidence](evidence/m10-workflow-adapter-wheel.json)
pins both wheel hashes and its namespace/facade checks. Synthetic private fixture
values and source-derived parameter strings are absent from public evidence.
No live external workflow, credentials, uploads, model weights, policy activation,
patch application or publication occurred. All process handles are terminal.

M10 still needs physical broker acceptance, broader finding/source-fix predicates
and integrated lifecycle CLI/examples. Saved external claims are now supported;
actual external workflow exercise remains opt-in and unverified. M9 effectiveness,
M11/M12 and the full original release/latency gates remain open.

## M11 offline developer workflow and adapter composition

The independent CLI now exposes profile inspection, invariant preview, challenge
catalog/replay, imported attack-path analysis, declared delegation comparison,
static source finding review and corpus-bound report comparison. Bounded stdin,
explicit JSON and exclusive output aliases preserve the existing strict parser.
Six diagnostic schemas bring the registry to **94 total / 54 Assurance**.
Content validation cannot activate a profile. Static finding/graph data retain
inconclusive/imported status; declared subsets do not issue grants or establish
physical enforcement. Unmodeled effects and host-dependent checks stay unknown.

`AssuranceAdapterGate` composes the existing Claude/Codex/Cursor/MCP adapters
without duplicating transports. Actual typed host facts and immutable context
are supplied through the protected SDK. The wrapper preserves core hard denies,
Claude's approval UI, Codex/Cursor pre-tool refusal and MCP approval refusal.
The optional closed session binding prevents history restoration under changed
Assurance profile/source/context; default core configuration digests are unchanged.
No inference/provider callback is accepted by the synchronous bridge.

The installed `python -I -m ordin.assurance.quickstart` exercises owned synthetic
protected selection, intrinsic preview, policy replay, minimized counterexamples,
graph evidence, declared child containment and offline vulnerability/fix-claim
imports. It executes no proposed action and calls no scanner/model. The injected
checker defect is explicitly synthetic, rather than an asserted Ordin vulnerability.
The [CLI/API reference](cli-and-api.md), [adapter composition](adapter-composition.md),
[quickstart](../../examples/assurance/README.md) and [trust diagram](security-and-privacy.md)
document approval, optional providers, private evidence and disclosure limits.

| Actual gate | Result |
| --- | --- |
| Complete Assurance/audit/optional-provider source gate | 525 passed, 1 POSIX ownership/mode skip, 177.22 s |
| Affected session/Claude/Codex/Cursor/MCP source regression gate | 198 passed, 1 failed, 3 POSIX skips, 120.28 s |
| OpenShell regression gate | 363 passed, 13 skips for the unavailable standalone prover, 55.08 s |
| Fresh installed-wheel process evaluation, exact implementation revision | 17/17 protocol cases, no errors; one repetition, synthetic hook/MCP/loopback fixtures |
| Linux-target mypy | 65 source/helper files clean |
| Ruff, format, diff and documentation links | Passed; one test-file formatting repair applied |
| Core wheel/sdist build and twine metadata | Both distributions passed |
| Fresh installed wheel/doctor/SDK quickstart | 321 Python/JSON package files matched; 94 schemas / 54 Assurance; network/process spies reject unintended calls |

The failed source regression is
`test_runtime_integration_evaluation_exercises_process_boundaries`: its real
`python -I -m ordin...` child processes cannot import Ordin from the source-only
interpreter. A direct isolated import returned `ModuleNotFoundError`. The fresh
installed wheel passes all 17 cases without removing `-I` or weakening protocol
assertions. The failed source gate is retained alongside the separately passing
installed evaluation in [pinned M11 evidence](evidence/m11-developer-experience.json).
One repetition verifies protocol behavior; it is not latency acceptance.

Local verification is still Windows/Python 3.13 only. Broader profile/provider/
broker/lifecycle acceptance, the original full suite, requested tooling versions,
independently labeled effectiveness and multi-platform CI remain open. The
original **5 ms added deterministic p95 budget remains unchanged and failed**;
these tests and the quickstart do not supersede it. No credentials, live scanner,
real inference, policy activation, patch application or publication occurred.

## M12 minimum fixtures, offline CI and exact-candidate release evidence

The [fixed acceptance plan](../../benchmarks/assurance/v1/acceptance-plan.json)
executes actual existing assertions, supplemented by exact protected deployment
file and inert README controls. All **35 mapped scenarios / 89 test cases** pass,
with no skips or observer errors. Observed calls retain action/context/profile/
configuration digests, baseline/final dispositions, reasons, invariant results,
containment results and grant-use outcomes. Artifact-only fixtures explicitly
report that no runtime review was observed.

This is authored synthetic regression coverage, not an independently labeled
effectiveness corpus. AT-07, AT-15, AT-16, AT-26, AT-28 and AT-29 remain partial:
native REST/body commitments, real solver replay, native database integration,
physical authorization/broker receipts, general target-code fixes and all-example
release audits are not established by these tests. The current unregistered
`http.request` remains unsupported; changed GraphQL bodies are checked separately.
The report retains `overall_acceptance=incomplete`. Its actual source revision
is `604f8db...`; all 321 installed core and 17 optional protocol Python/JSON files
were compared to source. Core/library bytes are unchanged through the subsequent
fixture/example-only candidate `cba13c9...` and are checked by the evidence capture.

The [offline CI definition](../../.github/workflows/assurance.yml) adds eight
Linux/Windows Python 3.10–3.13 jobs and four separate optional Python 3.10/3.13
jobs. It uses the existing hashed development baseline, pinned Actions,
read-only permissions and checkout without persisted credentials. Optional jobs
use saved artifacts, fake scanner processes and predetermined model values;
they install no Laya extra and need no key. YAML/matrix and workflow-security
checks pass locally. No workflow was dispatched; remote CI remains unverified.

The initial installed **root-only** suite had **1411 passed, 19 failed, 27 skipped**.
Fifteen new failures came from the synthetic broker fixture selecting its test
venv interpreter inside the excluded Git worktree. The SDK correctly refused it.
The fixture now selects the external base interpreter, pins its real bytes and
retains the target/Git exclusion. A negative fixture ensures an interpreter under
the excluded target still cannot launch. The optional fake model worker uses the
same external selection. No isolation check was weakened. The explicit development
entrypoint comparison now recognizes `ordin-assure`; the frozen v0.3 inventory and
all its entries remain unchanged. Installed broker/entrypoint and model rechecks
pass **26** and **22** tests respectively.

The regression driver now includes root, OpenShell and decision-model trees by
default, checks the exact clean source revision, rejects source imports and
records terminal failure/timeout metadata. The next all-suite run had **1890
passed, 1 failed, 40 skipped**: the existing quickstart required unavailable `sh`.
It now reviews and executes the exact fixed `git ls-files -- README.md` arguments
without a shell, preserving output and observation assertions. The installed
example/doc recheck passes five tests with the venv console scripts in `PATH`.
An earlier focused invocation without that PATH setup failed the JSON example;
that environment result is retained rather than treated as a product fix.

| Exact candidate gate | Actual result |
| --- | --- |
| Final installed root + OpenShell + decision-model suites at `cba13c9...` | **1890 passed, 1 failed, 40 skipped**; the sole failure is safety-fixture p95 **271.82 ms > 250 ms** |
| Maintained safety benchmark, 20 repetitions | **34/34 exact decisions**, zero false allows/critical misses/false blocks/semantic/policy/fuzz errors; p50/p95/p99 **277.2207 / 521.9402 / 599.7864 ms**; original 250/500 ms limits fail |
| Maintained trajectory corpus | **11/11 trajectories, 21/21 decisions**, no errors |
| Maintained regression replay | **9/9**, zero critical misses/errors |
| Agent Safety Corpus from installed wheel | **9/9**, no errors; finite compatibility cases, not broad effectiveness |
| Integration evaluation, 20 repetitions | Zero false allows/blocks/critical misses/unnecessary escalations, 18 live-session checks and 36 conformance checks without failures; original safety-fixture p95 **338.3048 ms > 250 ms** |
| Process runtime evaluation, five repetitions | **17/17 cases**, 85 subprocess samples, 5 local HTTP checks and 7/7 applicable observations linked, no errors; subprocess p50/p95/p99 **993.2135 / 1404.5386 / 1519.2991 ms** |
| Build/twine/fresh wheel/doctor | Both core distributions pass; 321 Python/JSON files match source; **94 schemas / 54 Assurance**; no unintended network/process creation in smoke |
| Full Ruff, changed-helper mypy, formatting, workflow and diff checks | Passed with available local versions; no requested-version CI claim |

All original thresholds remain unchanged. Three sequential quiet overhead runs
use the same four synthetic actions, ten warmup rounds and 100 repetitions
(400 samples per series), with no suite/build alongside them:

| Run | Added paired p50 / p95 / p99 ms | Intrinsic layer p50 / p95 / p99 ms | 5 ms added-p95 gate |
| --- | --- | --- | --- |
| 1 | 3.8666 / 37.5750 / 65.4365 | 3.4686 / 5.6013 / 7.1463 | Failed |
| 2 | 3.2839 / 33.3257 / 70.3508 | 4.1673 / 6.7429 / 11.3493 | Failed |
| 3 | 2.1637 / 22.5067 / 38.2222 | 4.0330 / 7.3006 / 11.3765 | Failed |

Each run has zero disposition mismatches. Intrinsic measurements also fail
5 ms p95 and do not replace paired acceptance. A separate ten-review diagnostic
profile records 90 pack-discovery calls and 1620 JSON loads; repeated discovery
is a substantial core cost, motivating a future optimization with explicit
freshness/mutation/parity checks. No global cache or latency waiver was installed.

[M12 evidence](evidence/m12-release-gates.json) retains all three full-suite
histories, source/wheel digests, fixture limits and actual failed metrics.
The three overhead reports were copied byte-for-byte through a permitted read;
their original hashes match. Some direct reads of private output were denied,
including an escalated attempt, without an approval-review rejection or ACL
change. The Agent Safety Corpus result uses [completed tool stdout](evidence/m12-observed-tool-results.json)
when its raw report is unreadable and explicitly claims no raw-file hash.

The test venv imports an installed local core wheel while sharing the preexisting
system pytest tooling; this is recorded separately from the fresh dependency-free
wheel smoke. Requested tool versions, remote platform CI, actual providers,
physical brokers, independent labels and broader scenario acceptance remain open.
All local process handles are terminal. No upload, live exploit, real inference,
scanner, policy activation, patch installation, push or publication occurred.

## Fresh catalog snapshot and current candidate verification

Candidate `04f40d05d85aeab244c149757a6a0a0e655ad060` adds a bounded
`_catalog_snapshot.py` scope to deterministic risk, command and action reviews.
It reuses raw catalog bytes only within that review, returns independently
decoded data and rechecks each retained byte stream before returning. Directory
membership, missing-file selections, `ORDIN_PACKS`/`ORDIN_INDEX`, cwd and loader
roots are checked as well. Changed source raises a coarse `ValueError`, which
the existing host adapters refuse. Success/error cleanup clears retained state;
thread and async-task owners cannot reuse another review's snapshot. Up to 256
files / 4 MiB / 512 KiB per file are retained; extra data follows the original
fresh-read behavior. No global persistent cache or mtime-only shortcut is used.

Thirteen added tests exercise equal-size/equal-mtime changes, removal/expansion,
new manifests/files, environment/root changes, returned-value mutation,
exception cleanup, limits, copied thread/task contexts and a real review whose
configuration changes during analysis. All 34 safety fixtures, including generic
actions and history, have exact cached/uncached review/disposition parity.
The first test loader incorrectly assumed every fixture was a shell command;
the corrected loader covers the complete corpus. Initial deep-copy reuse was
replaced by independent JSON decoding from retained bytes after profiling showed
copy cost. The final broad source focus passes **484 tests / 2 platform skips**;
Linux-target mypy passes **52 source files** and full Ruff is clean.

The first fresh-wheel smoke failed because eagerly importing `asyncio` on Windows
tried to subclass the harness's deliberately replaced `subprocess.Popen`.
Ordinary imports now consult `asyncio` only if already loaded; a running task
necessarily supplies that module. Task isolation is preserved without importing
event-loop machinery for plain reviews. The corrected import/API/namespace
focus passes **21 tests**, and the new fresh wheel passes the original network/
process refusal spies, quickstart and doctor. Wheel and sdist metadata pass;
there are **322 Python/JSON package files** and the same **94 total / 54 Assurance
schemas**, with empty core dependencies and unchanged public exports/entrypoints.

| Current installed candidate gate | Actual result |
| --- | --- |
| Complete root + Assurance + OpenShell + decision-model suites | **1904 passed, 40 skipped, zero failures**; all original assertions and latency limits preserved |
| Maintained safety benchmark, 20 repetitions | **34/34 decisions**, zero false allows/critical misses/false blocks/semantic/policy/fuzz errors; p50/p95/p99 **124.1612 / 354.8028 / 359.6124 ms**; original p95 250 ms limit still fails, p99 500 ms passes |
| Maintained integration evaluation, 20 repetitions | **No errors**, zero false allows/blocks/critical misses/unnecessary escalations; 18 live-session and 36 conformance checks pass; core p50/p95/p99 **0.3417 / 111.7797 / 137.6177 ms**, integration boundary **2.3987 / 160.9246 / 449.9257 ms** |
| Trajectory / regression / Agent Safety Corpus | **11/11 trajectories, 21/21 decisions; 9/9 regressions; 9/9 corpus cases**, no errors |
| Runtime process evaluation, five repetitions | **17/17 cases**, 85 subprocess samples, 7/7 applicable observations linked, no errors; p50/p95/p99 **605.2403 / 919.2874 / 1061.0867 ms** |

Three sequential quiet repeats use the same four actions, ten warmup rounds and
100 repetitions (400 samples per series), preserving the original 5 ms budget:

| Run | Core p50 / p95 / p99 ms | Added paired p50 / p95 / p99 ms | Intrinsic p50 / p95 / p99 ms |
| --- | --- | --- | --- |
| 1 | 54.9632 / 100.0906 / 122.2729 | 2.3754 / 20.7309 / 52.7010 | 1.9922 / 3.8321 / 5.1545 |
| 2 | 51.3863 / 95.0715 / 121.2738 | 2.1989 / 17.5003 / 47.7272 | 1.8415 / 3.1956 / 4.1406 |
| 3 | 46.7359 / 78.5264 / 102.5097 | 2.0026 / 13.3919 / 33.4418 | 3.2436 / 5.1329 / 6.9335 |

Each has zero disposition mismatches. **All paired 5 ms p95 gates still fail**;
the first two intrinsic p95 passes do not replace that acceptance, and the third
intrinsic p95 also fails. Local distributions vary across runs and do not prove
universal latency or independent effectiveness. Historical failed candidates are
preserved; the latest full-suite pass does not erase their failures.

[Current catalog evidence](evidence/catalog-snapshot.json) pins the actual source,
wheel and JUnit/report hashes, current passing suites and failed metrics. Exact
overhead files were copied byte-for-byte. The Agent Safety Corpus entry retains
the actual completed tool stdout and claims no unread raw-report hash. Only
Windows/Python 3.13 and existing local tooling are exercised; remote CI and six
partial acceptance scenarios remain open. All local handles are terminal. No
provider/scanner, physical broker, credentials, upload, policy installation,
patch application, push or publication occurred.

## Outstanding limitations

- The artifact/profile/gate foundation is functional; it is not a complete
  Assurance system. M3 acceptance gates remain open; M4 simulator is functional;
  M5 has expanded generated properties, M6 has graph/source-flow SDKs and M7
  has delegation/lifecycle integration. Dependent provider/optional proof work
  and remaining M9–M12/release work is incomplete. M8 live scanner/host isolation
  remains unverified. All AT-01–AT-35 require
  integrated implementation and current evidence before overall completion.
- `ApprovedSecurityProfile` now has a protected selection loader/compiler.
  Host-declared filesystem guarantees/mappings still require actual external
  enforcement. Finding validation and broader integrated acceptance remain
  incomplete. No feature milestone is complete merely because its record exists.
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
next full release gate. Resolve end-to-end latency without weakening the declared
budget. M6 graph/source-flow, M7 delegation/lifecycle and M8 importer, scanner
wrapper, fake-process gates and offline diff/CI example are implemented. Live
external scanner/runner behavior is unverified. Continue with a measured core/
Assurance latency optimization that preserves fresh configuration reads and all
security thresholds. Fresh review-scoped catalog reuse now passes the full suite
and integration gates, while standalone safety p95 and paired added-overhead
gates remain failed. Address remaining measured costs, then rerun exact-candidate
release gates. Complete the six
partial minimum scenarios and supported-platform CI; the authored workflow is
not a CI result. Complete physical broker acceptance, broader M10
validation/code-fix predicates and integrated lifecycle examples when actual
protected host enforcement is available. M11's offline developer workflow and
host adapter composition are verified locally; supported platform acceptance
remains open. M9 async replay and a provisional
frozen sample are verified, while actual model/hardware and independent
effectiveness/friction/latency acceptance remain open. Keep dependent M5 provider checks,
optional finite solver/promotion work and the release gates open; expanded
generated checks are not proof of the full objective.
Carry the existing Windows shell/latency/SQLite failures into the compatibility
audit; they must be resolved or explicitly verified on supported platforms
before any full completion claim. No background evaluation remains running.
