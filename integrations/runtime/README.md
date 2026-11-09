# Ordin Runtime integration

This optional package compiles supported Ordin runtime capability contracts into
Ordin Runtime policy and returns runtime evidence through an explicit adapter boundary.
Ordin core has no dependency on this package. Compile/validate never apply policy
or execute a reviewed action.

Install from a matching checkout with `python -m pip install ./integrations/runtime[yaml]`.
YAML serialization is optional; structured JSON policy works without PyYAML.
The policy/compiler compatibility target is OpenShell **0.1.2**, authored schema
version **1**, and standalone prover JSON schema **1**. See
[`docs/runtime-integration.md`](../../docs/runtime-integration.md) for supported
scopes, trust boundaries, operator configuration, and verification requirements.

Exact request authority v2 uses the audited local runtime extension, including
matching build identity and confirmed mediation gates. See
[`docs/runtime-request-authority-v2.md`](../../docs/runtime-request-authority-v2.md).
The native standalone solver is composed with explicit bounded protocol and
commitment containment; its REST result alone is not a GraphQL/MCP/RPC proof.

Ordin Runtime is the Ordin-owned adapter and tooling. Its verified engine and
native policy/prover protocols come from the pinned NVIDIA OpenShell upstream;
this rename does not claim authorship of that implementation. Published event,
audit and backend identifiers remain compatible. See
[`docs/runtime-compatibility.md`](../../docs/runtime-compatibility.md) for the
exact retained upstream and wire identifiers and the public import migration.
