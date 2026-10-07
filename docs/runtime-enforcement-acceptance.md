# Runtime enforcement acceptance history

The current implementation uses [v2 request authority](runtime-request-authority-v2.md)
for complete GraphQL, MCP and generic JSON-RPC request constraints, plus exact
TCP endpoint authority. This page preserves the earlier milestone evidence and
its original scope. New acceptance reports are generated locally after merge
against the exact final HEAD; the earlier results below retain their tested
revision and do not certify the v2 extension.

This report tests implementation revision `010669336a05187114ef1903bf2f533c9040595a` from an immutable
Git checkout. Starting HEAD was `925468d7153ef11d966af7706ca1029f44ffcd65`. Source digest is
`ae81269d0e85726a176988418df4cca793f0d240344ac05899511f65ec7fd2e5`. The digest covers 600 committed
tracked files and excludes the six generated evidence outputs listed in the
[acceptance JSON](reports/runtime-enforcement-acceptance.json). Generated evidence
is committed separately. The evidence commit may have a different Git HEAD;
`tested_source_revision` and `tested_source_digest` identify the tested implementation.

Core version is `0.4.0.dev0`, with zero required dependencies.
The optional integration remains `0.1.0` and supports
pinned OpenShell `0.1.2`; no runtime version upgrade or hosted service was added.

## Current requirements and evidence

| Requirement | Current-source implementation and evidence |
| --- | --- |
| URL whitespace/control canonicalization | A shared pure check rejects ASCII controls 0x00-0x1F, space and DEL on original input before parsing; no stripping or normalization grants authority. It covers URLs, origins, gateway configuration and HTTP request paths while preserving filesystem names with spaces. |
| URL authority is fail-closed | [Derivation](../ordin/runtime_contract.py), [observations](../ordin/runtime_observation.py), [request parsing](../ordin/runtime_requests.py), [retry reasoning](../ordin/runtime_reasoning.py), setup and optional gateway validation use userinfo presence checks. Empty `@` and `:@` syntax cannot become endpoint authority. Query/fragment-bearing endpoint authority and malformed ports are rejected; port zero is not converted to a default. Errors omit rejected values. |
| Differential and ingestion regressions | [Contract tests](../tests/test_runtime_contract.py), [observation tests](../tests/test_runtime_observation.py), [native ingestion tests](../integrations/openshell/tests/test_observations.py), setup and gateway tests cover both empty-userinfo forms and valid/invalid URL comparisons. Native structured paths accept relative request targets only and reject full URLs before correlation. |
| Action-bound requirements, not grants | [Capability contracts](runtime-capabilities.md) retain action ID/digest, decision, risk and content identity. Unknowns remain diagnostic. Derivation does not execute, discover credentials, resolve DNS, or override ask/block decisions. |
| Protocol authority isolation | [Runtime request contracts and boundaries](runtime-requests.md) retain REST, GraphQL and MCP grants separately after transport projection. The unchanged #200 tests cover raw/mixed HTTP against protocol-only boundaries, explicit REST grants, and opaque high-level identities remaining unsupported. |
| Scoped GraphQL | Separate request artifacts support one named flat query/mutation operation, exact operation names and root fields, comments, response aliases, and reachable flat named/inline fragments. Actual field names determine authority. Conflicting aliases and missing/cyclic/duplicate/unused fragments are rejected. Variables, arguments, directives, nested selections, subscriptions, batches and ambiguous documents remain unmodeled. |
| Scoped MCP | Endpoint, protected logical server, supported method, exact tool and supported revision are retained. Parameter-free `ping`, `tools/list` and `notifications/initialized` have exact method boundaries. Older supported revisions require protected `mcp_versions` declarations; one requested revision is retained and conflicting declarations intersect. Nonempty tool/control arguments and wildcard tools/servers remain unsupported. |
| Boundary and compiler anti-widening | [Core boundary checks](runtime-boundaries.md), independent plan rebuilding, broader-base rejection and the optional prover retain non-success for unsupported authority. Pinned prover coverage is TCP/REST; it does not prove GraphQL/MCP containment. Configured proof refuses unmodeled domains. |
| Correlated runtime evidence | [Native ingestion](openshell-integration.md) and protected correlation bind the exact action/digest/contract/session/sandbox/policy/source/event. Ordinary JSON and direct constructors cannot restore strong trust. Replay, reset, stale and contradictory identities remain rejected. |
| Human approval and policy drift | [Capability deltas](capability-proposals.md) require explicit human approval and cannot mutate policy. Named apply requires exact approval, current policy/loaded revision/admission agreement, final reread and post-set verification. Runtime management remains external; no automatic approval, apply or retry was added. |
| OCSF 1.8 Detection Finding export | [Optional export](ocsf-export.md) uses explicit bounded timestamps, deterministic fixed categories and digest identities. Raw commands, tool arguments, credentials, headers and bodies are omitted. Malformed correlation artifacts are rejected; findings cannot become enforcement observations. |
| Malformed input and readback | Existing process identity, policy protocol/shape, MCP readback, correlation and timestamp tests are retained. Malformed native readback returns bounded non-success before any policy mutation. |
| Schemas and compatibility | Doctor validates 38 schemas with root/package parity, including runtime-request contract and boundary schemas. Frozen v0.3 behavior/export inventory and existing schema versions remain unchanged. |
| Architecture and threat model | [Threat model](threat-model.md) covers URL/protocol confusion, widening, TOCTOU, forged/cross-session evidence, approval/apply drift, compromised runtime, credential confusion, malformed readback and stale evidence. Core review/derivation remains execution-free, local and deterministic; OpenShell stays optional. No remote attestation is claimed. |

## Exact implementation validation

The focused required command ran before the full suite; it also included all
new raw-authority regressions:

```sh
python -m pytest -q tests/test_runtime_contract.py tests/test_runtime_observation.py tests/test_runtime_boundary.py tests/test_runtime_requirements.py tests/test_capability_delta.py integrations/openshell/tests/test_requests.py integrations/openshell/tests/test_observations.py integrations/openshell/tests/test_apply.py integrations/openshell/tests/test_compiler.py integrations/openshell/tests/test_ocsf_export.py tests/test_runtime_url.py integrations/openshell/tests/test_url_authority.py
python -m pytest -q
python -m ordin doctor
python -m pre_commit run --all-files --show-diff-on-failure
python scripts/run_runtime_enforcement_corpus.py --json-out /tmp/runtime-enforcement-corpus.json
```

Actual results on Python 3.12.3 / native WSL Linux:

- Focused tests: **442 passed, 0 failed, 0 skipped**.
- Full suite: **1313 passed, 0 failed, 11 skipped in 375.263 seconds**. Exact skip reasons and elapsed command times are recorded in JSON.
- Doctor: **38 schemas, 0 errors**.
- Pre-commit: all **7 hooks passed** (lint, format, typed boundaries, compile, doctor, namespace, workflow security).
- Runtime corpus: **13/13 passed, 0 failed**, source `010669336a05187114ef1903bf2f533c9040595a`. This is synthetic integration evidence, not kernel enforcement.
- Optional integration doctor: pinned runtime exited 0; deliberately missing runtime exited 2 with a bounded diagnostic. Core remained usable.
- GitHub PR #203: all **15 applicable validation checks passed**. Release attestation and publication are intentionally skipped for PRs. CI ran on the exact tested implementation SHA; the merged implementation tree is identical.

## Real pinned-runtime evidence

All linked reports were rerun for `010669336a05187114ef1903bf2f533c9040595a` and the same source digest:

| Report | Actual result and evidence scope |
| --- | --- |
| [VM/backend demo](reports/openshell-runtime-demo.json) | 6/6 assertions passed with KVM guest kernel 6.12.76: exact GET, denied POST/unrelated host, filesystem positive and read-only negative controls, and evidence returned to later review. Backend allows and the host filesystem probe are `backend_observed`; correlated network denials are `backend_enforced`. A fixture is not called kernel enforcement. |
| [Protocol probes](reports/runtime-protocol-enforcement.json) | Seven baseline cases and fourteen extension cases passed. Extensions cover allowed aliases/fragments, disguised field expansion, MCP discovery and initialization notification, an exact legacy tool, wrong tools and disallowed protocol revisions. Denials require HTTP 403 and the backend's policy/version denial code. Loaded canonical policy equals the final-source compiler output. Public echo tests validate request enforcement, not application GraphQL/MCP execution. |
| [Explicit apply](reports/openshell-runtime-apply.json) | Unapproved call required approval; exact host-fixture approval applied an authority-identical policy, with loaded revision/admission readback and two verified audit receipts. Apply executed no workload. |
| [Corpus](reports/runtime-enforcement-corpus.json) | 13/13 synthetic adversarial cases passed with decision/evidence checks; no backend enforcement claim. |

Task-owned sandbox and service identities were checked before cleanup. All task
runtime services were stopped, while fixture state and sanitized evidence remain.

## Packaging and historical evidence

Both core and optional wheels/source distributions were freshly built from
`010669336a05187114ef1903bf2f533c9040595a`; all four passed Twine. The core wheel was installed with
`--no-index --no-deps` in a fresh environment and imported with both YAML and
the optional integration absent. The optional wheel then imported and ran JSON
compilation/OCSF export with YAML absent. Missing/pinned integration doctor
returned the expected 2/0 exits.

The maintained installed-candidate gate passed all eight workload groups:
safety, trajectories, failure regressions, extended regressions, conformance,
integration, runtime and quickstarts. Actual per-group counts and elapsed times
are recorded in JSON. Distribution integrity creation and verification passed.
No artifacts were published.

## Practical limits

Supported compilation remains conservative: exact public IPv4 destinations,
unambiguous literal paths/methods or the scoped request models above, exact
binaries, non-root identity and representable filesystem rights. GraphQL
variables/arguments/nesting, directives, subscriptions, batches and ambiguous
documents, MCP argument
constraints, wildcard/ambiguous authority, unmodeled protocols, arbitrary TCP
compilation, encoded paths and private-address destinations remain unsupported.
Missing identities, unknown semantics, credential expansion and missing prover
coverage remain non-success. Credential bindings are references, not values.

Protected host inputs, collector and runtime remain trust roots. Hash chains do
not resist a fully compromised owner; CLI management readback is not atomic CAS.
Loaded permission does not establish completed execution. Finite local tests and
these runtime probes do not prove universal safety or remote attestation.
