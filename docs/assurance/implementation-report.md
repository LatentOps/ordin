# Ordin Assurance implementation report

- Baseline SHA: `9f2568f70c677f607d631e252f609207f6a2cd60`.
- Feature branch: `feat/ordin-assurance`.
- Implemented SHA: pending; current changes are uncommitted.
- Environment: Windows 11 10.0.26200, Python 3.13.12.
- Preexisting untracked items: specification, `.worktrees/`, `video/`; preserved.
- Optional providers/scanners: none installed or invoked for this work.

| Milestone | Status | Evidence / next gate |
| --- | --- | --- |
| M0 | baseline_captured_with_failures | Frozen inventory, doctor, isolated baseline wheel and nine corpus cases pass; original suite: 1359 passed, 16 failed, 39 skipped; failed-case recheck pending |
| M1 | contract_foundation_verified | Ten immutable artifact contracts and schema pairs; 61 hostile/round-trip tests; source/schema/security/API gate 90 passed, 1 platform skip; agent/policy/entrypoint compatibility gate 108 passed; installed wheel and metadata gates pass |
| M2 | not_started | Source inventory, draft/approved profiles and compiler |
| M3 | not_started | Invariant evaluator and monotonic AssuranceGate |
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
| `python scripts/recheck_assurance_baseline.py --python .assurance-work/baseline-recheck-venv/Scripts/python.exe --output .assurance-work/baseline-recheck-1` | Running: 16 original failed cases against the frozen 40-schema installed baseline, with fresh workspace fixtures |
| `python -m ruff format --check` for all new Python files; `git diff --check` | Pass |

## Baseline failures and measurements

The original suite failed before any package or schema registration changed.
Additive unregistered Assurance files/docs were created while the suite ran;
existing core/runtime source and original schema bytes remained unchanged.

- Missing installed-package/CLI setup: three integration example tests,
  runtime integration evaluation, and six installed-hook smoke tests.
- Latency gates: two integration evaluation tests, safety benchmark, and
  promoted-regression replay. The separately recorded benchmark runs executed
  concurrently with the original suite; these measurements include contention.
- A five-second MCP malformed-output shutdown test timed out.
- Concurrent session-store transactions produced one SQLite error; exact cause
  needs a focused recheck.
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

## Outstanding limitations

- The common artifact foundation is verified; it is not a working complete
  Assurance system. M2–M12 are not implemented. All AT-01–AT-35 require
  integrated implementation and current evidence before overall completion.
- `ApprovedSecurityProfile` is a protected selection handle contract. Its
  protected file loader/compiler is M2 work. Graph/finding/delegation/model
  records likewise do not implement their later analysis/issuance/provider
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
