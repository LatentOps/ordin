# Exact release evidence

The collector is an explicit development/CI tool. It builds both wheels from a
clean exact commit, rejects unversioned package inputs and executable repository
content filters, verifies every package source/resource byte in the wheels, and
records wheel SHA-256, commit/tree identity, immutable lock hashes, dependency
declarations, environment, report hashes and expected/observed boundaries.
Wheel production uses a fresh private copy of versioned checkout bytes, so
ignored build outputs and compiled bytecode from earlier checks cannot enter
the build. The wheel inventory still rejects unexpected payloads and compares
every package and resource byte with the original verified checkout.
Core-only compatibility is checked before the optional swarm wheel or test
tooling is installed. No hosted model, user prompt, credential or production
target is required. Test effects and public synthetic TLS keys stay inside the
explicit owned lab; never trust that test CA in production.

From a clean checkout with the hash-locked development tools installed:

```bash
python scripts/check_swarm_release.py --revision <exact-40-character-commit> --workspace /owned/new-release-check --owned-fixture
```

The workspace must be new and outside the source checkout. It contains an
isolated wheel environment and `evidence/release-manifest.json` plus bounded JSON
artifacts and the exact built wheels. The CI artifact retains both reports and
wheels so their recorded SHA-256 values can be checked later. This is CI artifact
retention, not a public package release. The explicit flag authorizes only the owned synthetic fixtures.
The separate Linux helper must verify original bounded-worker execution; an
unsupported Linux backend fails the required Linux lane. Windows runs its real
unsupported control and retains the Linux worker as unsupported. The Windows
lane does not substitute for Linux enforcement evidence.

The collector runs the installed offline two-agent quickstart, separate owned
Linux demo/Windows unsupported control, fixed MCP/hooks/custom SDK and
coordinator restart/epoch checks, the full versioned corpus inventory and the
unchanged Linux performance gate (p95 250 ms, p99 500 ms). Warm/cold timing,
paired overhead versus difference-of-p95, long-session capacity and retained
unknown/uncovered counts remain in the linked benchmark artifacts.

`local_gate_passed` covers only the declared required checks for that platform.
`complete_conformance` remains false while other-platform or external SDK,
PostgreSQL and Ordin Runtime entries are unmeasured. Their workflow/lock references
are explicit; a reference is not an observed passing test. Imported arbitrary
JSON, a recomputed hash or a claimed physical flag cannot restore an original
broker observation, grant, approval or runtime authority. Artifact verification
checks byte consistency and explicitly does not authenticate a runtime producer.

Dependency-security clearance is **not established** by this collector. In
particular, the historical CrewAI/chromadb tuple has unresolved advisories listed
in the [conformance/support matrix](conformance.md). Offline compatibility success
does not waive those findings, authorize that runtime, or permit production
expansion. Keep quarantined/unavailable integrations visible and require a
reviewed compatible dependency path and the unchanged security gates before
changing that status.
CrewAI's retained reference explicitly records `availability=security_blocked`,
SDK conformance `not_evaluated`, no active lock, and the four advisory records.
The separate mandatory `CrewAI security quarantine` job establishes rejection
before import; this collector does not borrow its result or turn that rejection
into a positive SDK compatibility result.

Public artifacts contain finite reason codes, counts, hashes and relative
contract names. Raw pytest diagnostics, if needed after failure, stay in an
log outside the published evidence directory, with owner-only modes on POSIX.
Protect the chosen workspace with appropriate Windows ACLs. Child environments
inherit only required system/proxy settings and fixed test settings; model/API
secrets, automatic plugins and user Python paths are not inherited.

Reports must be generated **after the final integrated commit is known**. Keep
the generators and schemas versioned; retain the generated Linux and Windows
reports as local/CI artifacts bound to that actual final HEAD. Do not commit a
report that claims its own later commit or copy a green result from an earlier
revision. This tool does not tag, publish, deploy, rotate production keys or
authorize a production rollout.

Before moving beyond observe-only, the operator must review the exact action,
actor, routing inventory and result differences and authorize the next scope:

1. **Observe:** retain unknowns and uncovered paths; imports and review calls
   start no service or execution. Require core compatibility and private output.
2. **Shadow:** compare the same inputs with the current core result. Investigate
   every downgrade, missing collector, disposition difference and false allow;
   shadow agreement does not establish interception or OS protection.
3. **Mediated canary:** explicitly configure owned routes, authenticated scopes,
   quotas, audit/privacy and a stop procedure. Require actual benign forwarding,
   denied unsafe callbacks, replay/epoch refusal and named bypass controls.
   Stop rather than fall back to core allow on missing authority or uncertain
   completion; preserve uncertain holds and obtain fresh authority after a fence.
4. **Restricted owned worker:** require the separate successful Linux lane for
   the exact finite worker/resource policy, current original grants/approvals,
   hard capacity bounds and actual authenticated backend observations. Raw host
   tools, existing credentials and unwrapped processes remain uncovered.

Restricted expansion requires explicit protected operator authorization and
fresh same-revision evidence for all required CI gates. These fixtures do not
authorize general production enforcement. Broader sandbox/routing/credential
bypass tests, incident/recovery readiness and the migration/rollback/rotation
procedure in the [operator runbook](operator-runbook.md) remain operator duties.
Downgrade or rollback must never reuse prior grants, approvals, permits or expired
epochs; reenroll and review the current represented action under fresh authority.
