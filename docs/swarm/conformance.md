# Swarm conformance and tested version windows

Conformance is scoped to an exact Ordin commit/tree, the wheel bytes, the
dependency lock hashes, and the environment recorded by the gate. A declared
integration or an installed SDK is not evidence that its checks ran. The release
manifest retains every matrix entry, including unsupported and not-evaluated
entries, and never grants execution authority.

| Surface | Version/platform window | Evidence boundary |
| --- | --- | --- |
| Core public API | Current release commit; existing Linux CI targets Python 3.10–3.13 and macOS 15/Python 3.13 | Existing v0.3 exports/schema names and conservative allow/block/unknown decisions; no required swarm extra, driver, model or coordinator |
| Installed release gate | Python 3.12 on the recorded Ubuntu 24.04 and Windows CI images | Fresh core and optional swarm wheels, exact code/resource parity, fixed owned fixtures |
| MCP and maintained hooks | This release's MCP, Claude Code, Codex, Cursor and Hermes adapters | Actual fixed installed regression groups and original host callback mediation; no OS-confinement claim |
| Custom SDK | This release's bundled custom-runtime adapter | Offline two-agent private handoff, allowed callback, denied egress/child callbacks, separate observe/shadow review comparison |
| Owned Linux worker | Recorded Linux x86-64 kernel with required backend support | Original broker result from a fresh finite read worker; replay/epoch controls and raw parent bypass reported separately |
| Windows host | Recorded Windows release-gate image | Actual unsupported-Linux-worker control plus reviews, mediation and validation; no whole-process or host confinement claim |
| LangGraph | Exactly 1.2.20, prebuilt 1.1.1, langchain-core 1.7.6, Pydantic 2.14.2; managed UUID Utils 0.19.0 under LangSmith's `>=0.12.0,<1.0` requirement | Dedicated installed framework workflow and immutable lock; not locally rerun by this collector |
| CrewAI | Security blocked; historical 1.15.35/core 1.15.35 tuple is unavailable | No active SDK extra or lock. The mandatory `CrewAI security quarantine` job verifies refusal before SDK import; positive SDK conformance remains not-evaluated |
| Legacy AutoGen | Archived AutoGen Core 0.7.5, Pydantic 2.14.2; Protobuf 5.29.6 under the upstream `~=5.29.3` constraint | Legacy compatibility fixture only; Protobuf 5.x is upstream EOL, with no maintenance, patched-closure or future-version guarantee |
| Coordinator restart/epochs | This release's real mTLS protocol over owned SQLite development fixtures | Takeover, retained uncertain holds, stale epochs and authenticated host scopes; no PostgreSQL consensus claim |
| PostgreSQL | Exact driver lock and owned-cluster gate at the same source commit | Separate coordinator workflow; not-evaluated in a local release collection until that actual gate runs |
| Optional Ordin Runtime | Exact supported compiler/runtime/prover combination tested by its own gate | Not-evaluated when not configured; no automatic runtime/prover install or inferred confinement |

These are **tested-version windows**, not a promise about future SDK releases,
arbitrary host configurations, upstream support duration, or a service SLA.
The tested window ends at the recorded pinned tuple. Expanding it requires new
immutable pins, the corresponding installed conformance gate, and a new release
evidence manifest. An archived integration stays explicitly legacy even when
its finite fixture passes. CrewAI remains `security_blocked` with SDK conformance
`not_evaluated`; its quarantine checks do not claim that the SDK works safely.

The previously pinned CrewAI 1.15.35 runtime dependency set includes
`chromadb==1.5.9`, which is affected by four open advisories:
[GHSA-36p7-vc44-83pf](https://github.com/advisories/GHSA-36p7-vc44-83pf),
[GHSA-xph7-9rjv-w5fr](https://github.com/advisories/GHSA-xph7-9rjv-w5fr),
[GHSA-2wm9-hf6c-p5cr](https://github.com/advisories/GHSA-2wm9-hf6c-p5cr), and
[GHSA-f4j7-r4q5-qw2c](https://github.com/advisories/GHSA-f4j7-r4q5-qw2c).
The reviewed advisory records listed no patched version when checked on
2026-11-06. A successful offline hook fixture does not resolve those findings.
`crewai-core` alone is not a compatible replacement for the Agent/Task/tool-hook
runtime. Do not remove required dependencies to manufacture a passing test,
dismiss alerts, or waive the dependency-security gate. A disabled/quarantined
adapter remains explicit in the inventory. The release manifest retains all four
advisory identifiers, primary-source URLs, the affected historical version and
the review date. Its active lock inventory contains only the development tools,
PostgreSQL, LangGraph and legacy AutoGen locks. There is no CrewAI provisioning
path; a matching SDK installed elsewhere remains blocked. Existing processes
must follow the operator fence/drain/restart procedure before the new guard can
apply. Production use is not authorized by this release evidence.

The collector references the existing
[`swarm-frameworks` workflow](../../.github/workflows/swarm-frameworks.yml),
[`coordinator` workflow](../../.github/workflows/coordinator.yml), and optional
[`runtime-extension` workflow](../../.github/workflows/runtime-extension.yml)
by the bytes of their definitions and lock files. It does not borrow their pass
status from a different revision or turn imported JSON into an observed result.
The integrator must separately verify every required CI check on the final
release commit and retain the exact artifact hashes for those checks.

The local gate runs fixed current-revision tests copied from a fresh Git archive
into an owned directory without source bytecode caches. Core and swarm package
namespaces are pinned to the installed wheels before those fixtures load. Git
hooks, fsmonitor callbacks, external diff/textconv and configured content filters
cannot become collector execution. The fixture tests are intentional reviewed
test code bound to the recorded source tree; report JSON never selects commands.

See [release evidence](release-evidence.md) for reproduction and the operator
acceptance conditions for each rollout stage. Broader protection remains outside
the guarantees of these finite synthetic fixtures.
