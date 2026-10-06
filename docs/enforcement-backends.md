# Enforcement backend protocol

`EnforcementBackend` is a backend-neutral structural protocol with `name`,
`compile(contract)`, and `validate(plan)`. Core contains only interfaces and
immutable data models. It has no execute, start-sandbox, apply, or retry method.
Optional integrations own those explicit runtime operations.

`CompilationResult` has `success`, `unsupported`, or `inconclusive` status,
machine-readable reason codes, bounded reasons, unsupported fields, and an
optional `EnforcementPlan`. Success requires a complete plan with no discarded
unsupported fields. Non-success has no enforcement plan; an explicitly requested
shadow diagnostic may retain a shadow-only plan. It is never enforceable.

Plans retain the complete action-bound capability contract, immutable structured
policy, canonical policy digest, mode, and content-derived plan ID. A block or
unknown contract can only produce diagnostics. Ask/warn retains human approval;
a successful compile is not approval. An integration must validate the exact
policy digest and verify its boundary before explicit application.

`BackendValidationResult` distinguishes success, invalid, unsupported, and
inconclusive, preserving unsupported fields and the policy identity. Only
success passes. Implementations must independently reject mappings that widen
authority or cannot represent a required restriction. REST/tool capabilities
must not fall back to unrestricted TCP. Credential references need explicit
operator configuration; implementations must never emit credential values.

The first optional backend is OpenShell. Future backends can implement the same
compile/validate protocol without adding runtime dependencies to Ordin core.
