# Runtime enforcement integration design

This implements the repository's `ORDIN_OPENSHELL_RUNTIME_ENFORCEMENT_IMPLEMENTATION.md`
in phases. Ordin remains an execution-free semantic reviewer. An optional,
separately packaged OpenShell adapter translates supported capabilities into
policy; the external runtime owns enforcement, execution, and credentials.

## Contracts and identity

Add immutable, bounded, versioned `RuntimeCapabilityContract`,
`RuntimeObservation` / `RuntimeObservationHistory`,
`RuntimeCapabilityBoundary`, and `CapabilityDeltaProposal` types. Every
capability contract includes the audit-compatible canonical action digest and
a content-derived contract ID. A blocked review produces diagnostic data only;
an ask or warn retains an explicit human approval requirement.

Filesystem access and scope, network protocol/method/path, exact tool identity,
process requirements, privilege, credential bindings, and unknowns remain
separate. Derivation reads only the supplied reviewed action and its evidence.
It never resolves executable paths, traverses files, resolves DNS, or executes.
Missing or ambiguous information remains an explicit unknown.

## Trust boundaries

Ordinary JSON deserialization accepts caller-asserted observations only.
Stronger backend trust is constructed through an explicitly trusted adapter
interface, never through action parameters or ordinary agent JSON. Trust labels
describe confidence in the reporting integration, not cryptographic attestation.
Correlation checks retained action ID, canonical action digest, contract ID,
session identity, sandbox identity, policy digest, and event uniqueness.
Evidence is additive: predicted danger is never removed by runtime observations.

The boundary checker proves a documented conservative subset relation. Exact
identities are preferred. Filesystem lexical prefixes require an explicit
lexical boundary mode; they are never presented as symlink-safe isolation.
Only `within_boundary` succeeds. `exceeds_boundary`, `unsupported`, and
`inconclusive` prevent enforcement. Credentials are authorized independently.
Denials can produce minimal, human-approved proposals only for capabilities
already predicted for that action. New requirements require investigation.

## Compatibility and package boundary

Preserve `ActionReview.v1`, `ExecutionCapabilityProfile`, `ActionObservation`,
`ObservationHistory`, `AgentGate`, tool/MCP adapters, contract pinning, caller
policies, audit hash chaining, and existing session identities. New artifacts
are additive. Core required dependencies remain empty; the package version
remains `0.4.0.dev0`. Export the new APIs only after their tests are stable.

OpenShell code lives in `integrations/openshell/ordin_openshell/`. It owns
optional YAML serialization, policy compilation/validation, prover invocation,
event ingestion, private correlation records, shadow reports, doctor, and
explicit named-sandbox policy application. Core contains a compile/validate
protocol and data types, with no execute or apply method. Runtime subprocesses
are confined to explicit integration commands and never run reviewed actions.

## Representability and unsupported cases

Use the checked OpenShell source/docs and record its revision/version. Compile
structured mappings first, serialize using an optional YAML library, and retain
semantic provenance. Unknown protocols, missing binary identity, ambiguous
filesystem scope, unsupported request/tool restrictions, credential bindings
without operator configuration, and mappings that widen authority produce no
enforceable plan. In particular, REST and MCP permissions never fall back to TCP.
Default/base policies must not silently introduce additional authority.
Prover coverage must include every relied-on domain; non-success or incompatible
JSON results fail closed. Validation and digest-bound verification precede
apply; strict active-policy comparison detects drift where the backend supports
readback. Apply never executes or retries an agent action.

Runtime records omit raw action parameters, runtime payloads, and credentials.
Audit records link action, contract, compiled policy, verification, and event
digests; resources are hashed by default. Shadow mode only compares predictions,
compiled authority, boundary results, and runtime events. It does not apply
rules or switch into enforce mode automatically.

## Implementation and completion gates

1. Implement capability derivation, schemas, bounds, immutability, and tests;
   run the complete existing suite and doctor before Phase 2.
2. Implement runtime observations, correlation, history/session handling,
   additive temporal signals, provenance, and trust-boundary tests; rerun the suite.
3. Implement the backend protocol, boundary checker, and minimal proposals;
   verify subset, unknown, approval, and mismatch invariants.
4. Implement the OpenShell compiler with structured golden and adversarial
   fixtures using the actual upstream schema.
5. Add the prover adapter with typed compatibility errors and full coverage checks.
6. Add structured OCSF ingestion, private bounded correlation, and fixture tests.
7. Add shadow evaluation, mismatch categories, schema, and promotion guidance.
8. Add explicit verified apply only after the above gates pass.
9. Complete core/integration CLIs, examples, docs, threat-model updates, security
   corpus cases, optional OCSF export, benchmarks, and compatibility doctor.
10. Run full regression, quality, security, packaging/release gates and harmless
    runtime integration scenarios. Audit every requirement against actual results.

Required final report: Summary; Architecture implemented; Public APIs added;
Schemas added; Core files changed; OpenShell integration files changed; Safety
invariants; Unsupported cases; Tests run; Test results; Benchmark results;
OpenShell versions tested; Threat-model changes; Known limitations; Follow-up work.
Report exact commands/counts and measured percentiles. No completion claim is
made until the full document's core, integration, and enforcement gates are met.
