# Optional OpenShell integration

Ordin core reviews actions and derives data-only capability contracts. The
separate `ordin-openshell` package compiles supported contracts, invokes the
standalone prover explicitly, ingests structured runtime evidence, and produces
local shadow reports. Core has no dependency on OpenShell, PyYAML, or a service.
Compile, validate, ingest, and shadow evaluation never run a reviewed action.

Install from a matching checkout:

```sh
python -m pip install .
python -m pip install './integrations/openshell[yaml]'
```

The optional YAML extra uses PyYAML's structured serializer and safe loader.
JSON policy data works without the extra. Duplicate JSON/YAML keys, YAML
aliases, non-finite values, and oversized inputs fail validation.

## Compatibility and representability

The integration targets the released OpenShell `v0.1.2` source, authored policy
schema version `1`, standalone prover JSON schema `1`, and OCSF `1.8.0`.
Integration package version is `0.1.0`; Ordin remains `0.4.0.dev0`.
See upstream [architecture](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/about/architecture.mdx),
[network rules](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/how-it-works/policies/network-rules.mdx),
and [prover coverage](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/how-it-works/policies/prover.mdx).

`compile_openshell_policy(contract, ...)` is deterministic and produces an
immutable `EnforcementPlan` with action/contract/policy digests and semantic
provenance. The trusted operator supplies a non-root UID/GID and any exact file
object classifications or credential-provider references. These configuration
facts do not come from tool arguments. No credential values are accepted.

Compilation currently supports exact public IPv4 host/port REST endpoints,
exact HTTP method/path rules, absolute binary identities, and filesystem rights
that match OpenShell's actual enforcement primitives. A hostname receives
explicit public IPv4 ranges, excluding private, loopback, link-local, shared,
reserved, and multicast ranges; the compiler performs no DNS lookup. IPv6 is
outside this compiler subset. Missing request semantics, private endpoints,
wildcards, encoded paths, MCP/GraphQL/JSON-RPC/WebSocket/TCP, ambiguous objects,
privilege escalation, and unsupported child-process restrictions produce no
enforceable plan. Specific REST/tool capabilities never fall back to raw TCP.

OpenShell's read-only Landlock primitive grants read and execution; read-write
grants additional path rights including deletion. An Ordin read-only semantic
requirement therefore cannot silently become either primitive. Compilation
requires explicit matching rights in the input contract. Exact paths require an
operator-established file type; a directory would widen to descendants. An
empty OpenShell filesystem list disables Landlock, so the compiler rejects that
representation too. It disables implicit workdir access and requires Landlock
compatibility. Arbitrary base policies cannot introduce extra authority.

The current core derivation often knows only host-level network semantics or a
process requirement with unknown child behavior. Such contracts remain
unsupported here. Do not edit away unknowns to obtain a successful compilation:
the semantic review or trusted integration must establish the missing facts.
The tests include explicitly specified supported contracts; those fixtures are
not evidence that every shell command already derives all runtime requirements.

Credential mapping independently checks the binding ID, provider ID, exact
destination, and allowed method/path sets. A matching host never discovers or
grants a provider. Unknown or extra configuration fields, including secret
values, return `unsupported` without including their values in diagnostics.

## Compile and prove

```sh
ordin-openshell compile-contract --contract capability.json --uid 1000 --gid 1000 \
    --output policy.json
ordin-openshell validate --policy policy.json
```

Compilation produces policy data only. `--shadow` labels the plan diagnostic;
it does not install the generated rules in a runtime. The emitted request
policy describes the would-be enforced restrictions for comparison.

`verify_with_openshell_prover(candidate, boundary, ...)` snapshots bounded
regular-file inputs in private temporary files and invokes only the standalone
prover. It preserves exact input-byte digests, coverage, counterexamples, and
reason codes. Its byte digests are distinct from the plan's canonical policy
mapping digest. The parser checks schema/product versions, structured result,
process exit code, and all required domains. Only `within_boundary` succeeds;
`exceeds_boundary`, `unsupported`, `inconclusive`, and `error` fail verification.
Missing binaries and timeouts produce typed results and do not affect core.

## Structured events and private correlation

`parse_openshell_event()` accepts bounded OCSF JSON from a trusted local
collector. Product/version fields establish compatibility, not authenticity.
Protect the supervisor/gateway channel and collector; agent-produced JSON
must not be routed through this trusted path.

The adapter supports network connection events (`4001`), HTTP request events
(`4002`), and process launch events (`1007`, activity `1`). It validates the
fields used for mapping, including numeric outcome/type consistency,
destination identity, event UID, sandbox UID, and timestamp. Unknown classes
are explicitly unsupported. This OpenShell version has no supported structured
filesystem-denial class in this adapter; a terminal message is not a substitute.

Structured denials become `backend_enforced`. Allowed requests become
`backend_observed`: upstream encodes audit allows and enforce allows identically
as `Allowed`, with the audit distinction in human prose. The adapter does not
parse that prose or claim successful completion from permission. It preserves
only bounded request/process fields, source schema version, and event digest.
It strips query/fragment data, ignores headers, bodies, command lines, messages,
and arbitrary unmapped fields, and hashes event identity.

`CorrelationBinding` identifies the original action/digest/contract, exact
`RuntimeEvidenceSource`, event UID digest, event digest, and a bounded lifetime.
The host collector must establish attribution before registering it with
`CorrelationStore`; destination, tool text, timestamp, or numeric OCSF
`action_id` alone do not establish an Ordin action. An explicit per-event binding
is necessary when the backend lacks action IDs. Protect sandbox generation and
session ownership in the collector's transport/collection scope.

The SQLite mapping uses a dedicated application ID, atomic transactions, a
64 MiB database bound, at most 128 bindings, 0600 POSIX files, and owner-only
directory requirements. It stores no commands or raw events. Record checksums
detect accidental corruption; they do not make owner-controlled files tamper
proof. Bindings expire within one day and consumed IDs remain until the store
is retired, preventing replay. Capacity exhaustion fails instead of evicting
replay protection. Retire stores only when their source/session is retired.

`ingest_openshell_event(event, contract=..., source=..., store=..., now_ms=...)`
requires an exact event/action/session/sandbox/policy match before constructing
a strong `RuntimeObservation`. Unknown attribution returns a sanitized
`uncorrelated` backend record without a trajectory observation. Conflict,
expiry, changed payload, and duplicate IDs reject attachment. Accepted
observations can be passed to the original `IntegrationSession.observe_runtime()`;
the session independently checks its retained original action and reporting scope.

## Shadow evaluation and promotion

`build_shadow_report(ShadowCase(...))` compares already-reviewed contracts,
would-be compiled policies, caller boundaries, and host-correlated observations.
Use a bounded sequence of cases (128 actions/events maximum). This pure API
performs no backend mutation, process execution, network request, or telemetry.
The stable format is `ordin.runtime_shadow_report.v1`, with root and packaged
schema copies checked by doctor. Reports retain digests and stable mismatch
codes; they omit action parameters, plaintext resource values, and event payloads.

Metrics cover representable/unsupported contracts, correlated/mismatched events,
unpredicted and unused capabilities, would-deny requests, widening failures, and
all four boundary outcomes. Mismatch codes include `predicted_but_not_observed`,
`observed_but_not_predicted`, `compiler_widening_detected`,
`runtime_denial_expected`, `runtime_denial_unexpected`, and
`unrepresentable_capability`. Missing binary/request fields remain inconclusive.

A policy comparison checks modeled host/port/method/path/binary fields. It does
not prove DNS results, credential availability, symlink safety, actual runtime
enforcement, or successful execution. A request inside that projection can still
be denied by another runtime control. Unused capabilities mean unobserved in
the supplied window, not unnecessary in all executions. Denials observe
attempted requirements without claiming completed effects.

Promotion always requires operator review. Recommended gates are zero widening
violations, zero silently dropped unsupported fields, zero correlation
mismatches, boundary verification for every enforceable policy, passing core
and optional integration/adversarial suites, and manual review of unsupported
classes. Shadow evaluation never switches to enforcement automatically.

Explicit verified policy apply, active-policy drift readback, full runtime
end-to-end demonstrations, and compatibility doctor remain implementation work
in the full runtime-enforcement plan. The compile/evidence/shadow APIs here do
not claim those runtime guarantees.
