# Capability boundary verification

`RuntimeCapabilityBoundary` (`ordin.runtime_capability_boundary.v1`) describes
the maximum intended capabilities allowed by a caller. Defaults deny access.
`verify_runtime_capability(contract, boundary)` is a pure, bounded comparison;
it never executes actions, reads target files, resolves symlinks, or performs DNS.

The result is `within_boundary`, `exceeds_boundary`, `unsupported`, or
`inconclusive`. Only `within_boundary` succeeds. Results retain contract and
boundary digests, per-domain coverage, a counterexample where applicable, and
unsupported fields. Non-success or incomplete coverage prevents enforcement.
Passing verifies this capability model, not a running kernel or sandbox.

Filesystem rights are explicit. Read includes metadata; write does not grant
read, deletion, or execution. Exact path identity is preferred. A nested path
under a prefix returns unsupported unless `filesystem_semantics=lexical_prefix`
and `runtime_filesystem_guarantees=True` are explicitly supplied. That flag is
an operator assertion about the target runtime, not a filesystem check. Lexical
prefixes remain case-sensitive, segment-bounded intent; aliases/TOCTOU are not
resolved. A backend must supply real isolation and its own verification.

Network checks use exact host/port and a documented access lattice (write includes
read). REST grants require precise methods/paths. Every method/path pair must be
covered by a boundary rule; multiple rules may cover different pairs. A terminal
whole-segment `/**` is supported in a boundary, matching descendants rather than
the prefix itself. Candidate globs, encoded or ambiguous paths, unknown protocols,
and unsupported request features fail closed. TCP cannot masquerade as a narrow
REST request. Host aliases and private IP resolution are never inferred.
The checker does not prove that DNS resolves safely or that a backend inspects TLS.

Tools require exact runtime/server/tool identity. Process execution, executable
paths, child spawning, privilege escalation, and required UID are checked
separately. `allow_any_executable=True` is an explicit operator maximum; missing
candidate binary identity still fails. Unknown child scope is inconclusive under
a boundary that prohibits child processes. Credential binding, host, and port
must independently match an explicit credential allowance; network permission
alone cannot grant credentials.

Unknown capability states preserve non-success and incomplete coverage. Resource
budgets produce inconclusive results. Boundary verification is independent of
semantic approval: a block is rejected and an ask still needs human approval,
even if its modeled capabilities fit a maximum boundary.
