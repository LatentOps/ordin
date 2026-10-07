# Ordin OpenShell integration

This optional package compiles supported Ordin runtime capability contracts into
OpenShell policy and returns runtime evidence through an explicit adapter boundary.
Ordin core has no dependency on this package. Compile/validate never apply policy
or execute a reviewed action.

Install from a matching checkout with `python -m pip install ./integrations/openshell[yaml]`.
YAML serialization is optional; structured JSON policy works without PyYAML.
The policy/compiler compatibility target is OpenShell **0.1.2**, authored schema
version **1**, and standalone prover JSON schema **1**. See
[`docs/openshell-integration.md`](../../docs/openshell-integration.md) for supported
scopes, trust boundaries, operator configuration, and verification requirements.

Exact request authority v2 uses the audited local runtime extension, including
matching build identity and confirmed mediation gates. See
[`docs/runtime-request-authority-v2.md`](../../docs/runtime-request-authority-v2.md).
The native standalone solver is composed with explicit bounded protocol and
commitment containment; its REST result alone is not a GraphQL/MCP/RPC proof.
