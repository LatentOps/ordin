# Repository inventory and approved profiles

Inventory is an explicit offline read of a host-selected repository root. It
does not run target imports, hooks, build scripts or commands. Python uses a
bounded AST/token pass; JavaScript uses finite syntax heuristics and is marked
partial. Other supported configuration/document files supply references, not
authorization facts. Unsupported languages, exclusions and parse failures remain
visible. No source or literal secret value is copied into the inventory.

```python
from pathlib import Path
from ordin.assurance import (
    AuthorizedRepository, RepositoryScope, inventory_repository,
    build_threat_model, render_threat_model,
)

scope = AuthorizedRepository(
    root=Path("/operator/authorized-snapshot").resolve(),
    repository=RepositoryScope("example/application", "reviewed-revision"),
    virtual_root="/repo",
)
inventory = inventory_repository(scope)
model = build_threat_model(scope, inventory)
markdown = render_threat_model(model)  # Path aliases by default.
# Local operator review may explicitly request real path:line citations.
private_markdown = render_threat_model(model, include_source_paths=True)
assert model.draft.authoritative is False
```

The physical root must be an absolute local path with resolved ancestors; on
macOS this distinguishes `/private/tmp` from the system `/tmp` symlink. Resolve
and authorize the physical directory in host code before providing it. The
POSIX `virtual_root` is
the host's explicit mapping into action/resource space; it is not inferred from
a Windows path. The host supplies repository identity/revision. That label is
not proof of a Git checkout. An independently computed snapshot digest pins
inspected bytes and coverage, and can be required with
`AuthorizedRepository(..., expected_snapshot_digest=...)` on future reads.

References bind relative path, actual line, symbol where supported, revision
and SHA-256 file bytes. Threat-model generation reconstructs the inventory
before accepting it; stale or JSON-forged facts cannot become inspected source
evidence. Routes are hypotheses even when entrypoint, transformation, control
and sink occur in one function. Authentication call names, approval guards and
module-load exceptions are candidate counterevidence; actual reachability and
host enforcement remain unverified.

Inventory excludes credential files, administrative/virtualenv/build/cache
directories, links, devices and unsupported names. It retains bounded gap codes
and reference hashes. Defaults: 256 inspected files/facts/assets, 16 MiB total,
1 MiB per file, 8 directory levels, 4,096 discovery entries, 256 entries per
directory, 20,000 Python tokens and 64 expression nesting levels. Oversized or
unavailable inputs produce partial coverage or controlled refusal, never a
clean scan claim. Empty harmless source still has deployment unknowns.

`propose_profile(draft, profile_id=..., version=...)` creates reviewable
`SecurityProfile` content only. It does not activate suggestions. A validated
file, `approved: true`, imported scanner verdict or model score cannot create
`ApprovedSecurityProfile`.

The activation API requires an operator-owned `ProtectedProfileSelection`:

1. Pin the exact JSON file's raw-byte SHA-256 and semantic profile digest, its
   version and exact repository identity/revision.
2. Supply a protected `RuntimeEvidenceSource` identifying the active host
   policy, and the host-owned `RuntimeCapabilityBoundary` for the agent.
3. Map the actual protected config file to its canonical runtime path. The
   host must enforce this mapping and the declared filesystem guarantees.
4. The loader rejects write/delete authority to that file or any ancestor,
   unknown filesystem scopes, unbounded privilege, root-agent configurations,
   unsafe links, changed bytes, mismatched repository/version/policy and
   unsupported profile flags. POSIX also requires an owner-only file and a
   protected parent directory. Windows ACL/agent separation is the host's job.
5. Call `load_approved_profile(selection, current_repository=host_scope,
   active_runtime_policy_digest=host_policy_digest)`. The result is immutable
   approved content bound to that selection; no permissions are issued.

These are trusted host constructors, like the existing `RuntimeEvidenceSource`.
Do not create them from tool arguments. Python types and hashes do not protect
against malicious code inside the trusted host process. The loader does not
install an OS sandbox, authenticate remote attestation, sign a profile or prove
backend readback. The execution host owns that protection and must refresh the
selection when source/policy/repository identity changes.

`compile_approved_profile` reuses `ActionPolicySet` for exactly representable
effect/resource restrictions. It emits only `ask` or `block`. Profile directory
matching is exact-or-slash-prefix (`/repo` and `/repo/...`, excluding `/repo2`);
the old v1 literal-prefix matcher retains its public meaning. Matching is lexical
review evidence, not a symlink-safe filesystem boundary.

Approval, authenticated principal, credential, delegation, temporal, provenance
and protocol/request checks are reported as `wrapper_required`, not projected
into catch-all rules. Missing effects or protected scope remain `unsupported`.
The conservative Assurance wrapper must evaluate those rows or escalate when
mandatory evidence is missing. A compiled policy alone does not establish that
every profile invariant has passed. Keep existing policies in the baseline
gate and apply additional restrictions through composition.

Ordinary generic `file.write` envelopes currently have no core semantic adapter.
Their parameters cannot invent trusted effects/resources: they still escalate.
Use the existing operator-owned tool/MCP semantics registry for a known adapter.
None of this changes `Ordin()`, existing hooks, CLI, sessions or optional OpenShell.
