# Ordin Assurance implementation report

- Baseline SHA: `9f2568f70c677f607d631e252f609207f6a2cd60`.
- Feature branch: `feat/ordin-assurance`.
- Contract foundation SHA: `3773f23b08f1cd9b78a7b8aa041f952bd52d47cc`.
- Repository/profile implementation SHA: `bec1037d64fd0c52e043343c3ea1c960819ecb58`.
- Invariant-gate functional implementation SHA: `aa5345d6fa18ed9d6f9f6ff62995f1c9eec6dd38`.
- Full implementation SHA: pending; M3 full-regression/performance gates and M4–M12 remain open.
- Environment: Windows 11 10.0.26200, Python 3.13.12.
- Preexisting untracked items: specification, `.worktrees/`, `video/`; preserved.
- Optional providers/scanners: none installed or invoked for this work.

| Milestone | Status | Evidence / next gate |
| --- | --- | --- |
| M0 | baseline_captured_with_failures | Frozen inventory, doctor, isolated baseline wheel and nine corpus cases pass; original suite: 1359 passed, 16 failed, 39 skipped; installed baseline recheck: 11 passed, 5 failed |
| M1 | contract_foundation_verified | Ten immutable artifact contracts and schema pairs; 61 hostile/round-trip tests; source/schema/security/API gate 90 passed, 1 platform skip; agent/policy/entrypoint compatibility gate 108 passed; installed wheel and metadata gates pass |
| M2 | implemented_offline_verified | Scoped read-only inventory, four frozen source-backed drafts, protected profile loader/compiler; 162 passed / 2 POSIX skips; final installed wheel, metadata and SDK example pass |
| M3 | functional_sdk_verified_gates_open | Pure evaluator/gate and sealed host facts; 240 passed / 1 POSIX skip; wheel/SDK pass; full run 1135 passed / 5 failed / 27 skipped; two audit gaps fixed with 14-test recheck; end-to-end latency still failed |
| M4 | not_started | Independent policy replay/simulation |
| M5 | not_started | Seeded, minimized, replayed safe counterexamples |
| M6 | not_started | Bounded attack paths and authenticated origins |
| M7 | not_started | Delegation subset and lifecycle |
| M8 | not_started | Offline Codex Security import and optional scanner |
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

## Baseline failures and measurements (original source, continued)

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

## Outstanding limitations

- The artifact/profile/gate foundation is functional; it is not a complete
  Assurance system. M3 acceptance gates remain open; M4–M12 are not implemented. All AT-01–AT-35 require
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
independent feature is M4 frozen policy replay/simulation using the actual gate.
Carry the existing Windows shell/latency/SQLite failures into the compatibility
audit; they must be resolved or explicitly verified on supported platforms
before any full completion claim. No background evaluation remains running.
