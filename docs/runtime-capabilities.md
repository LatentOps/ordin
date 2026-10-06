# Runtime capability contracts

The additive `RuntimeCapabilityContract` and
`derive_runtime_capability_contract` APIs are available from `ordin`.

```sh
ordin capability derive --review review.json --json
ordin capability validate capability.json --json
ordin capability verify capability.json --boundary boundary.json --json
```

These commands read local artifacts without execution or runtime mutation.
Review decoding preserves the supplied v1 decision, provenance, and uncertainty;
it does not re-review the action. Hosts must protect reviewed artifacts, since
shape validation is not authenticity. Unknown scopes/protocols remain explicit.

`RuntimeCapabilityContract` (`ordin.runtime_capability.v1`) describes the minimum
runtime capabilities established by a supplied `ActionReview`. It is separate
from `ActionReview.v1` and the existing coarse `ExecutionCapabilityProfile`.

```python
from ordin import ActionEnvelope, Ordin
from ordin.runtime_contract import derive_runtime_capability_contract

review = Ordin().review_action(
    ActionEnvelope.shell("git status --short", action_id="step-1")
)
contract = derive_runtime_capability_contract(review)
print(contract.as_dict())
```

Derivation is deterministic and pure: it performs no action execution, host
filesystem inspection, DNS, network calls, policy changes, or runtime startup.
The action digest uses the audit canonicalization (sorted UTF-8 JSON keys,
compact separators, finite numbers). The content-derived `rc:` ID binds the
action digest, decision, capabilities, unknowns, and source provenance digest.
Changing any material invalidates the ID; deserialization checks that binding.

Filesystem entries preserve read, metadata, write, delete, execute, and unknown
access, with exact, prefix, or unknown scope. Recursive deletion uses a prefix
requirement. Paths are absolute POSIX syntax; unresolved relative paths,
expansions, globs, missing targets, and ambiguous effect/resource associations
remain explicit unknowns. Prefix scope is lexical intent, not symlink-safe
filesystem isolation.

Network entries distinguish access, host, port, protocol, methods, paths, and
tool identity. A host or URL alone never establishes REST request semantics.
Missing protocol/method stays unknown, preventing enforce compilation.
Malformed URLs and URLs containing userinfo, queries, or fragments are not
copied into contracts. Tool identity is retained only with a trusted exact
semantic binding; similar-looking names confer no trust. Process execution,
executable identity, unknown child spawning, privilege escalation, and unknown
UID remain separate facts. Compound shell syntax remains uncertain.

Credentials contain opaque binding identities and destination constraints,
never values. Ordinary action arguments cannot introduce a binding. Raw action
parameters, prose summaries, and credentials are absent from `source`; it
contains only adapter/kind/operation, typed effects, and provenance digest.
Digests redact content but do not encrypt low-entropy inputs.

Contracts are deeply immutable and their serialized copies are detached.
Collections are limited to 128 entries, text to 4096 characters, JSON nesting
to ten levels, and serialized artifacts to 1 MiB. Strict validation rejects
unknown fields, invalid types, non-finite numbers, and controls. Root/package
JSON schemas and the in-memory validation definitions are checked for parity.

`grant_state` is `diagnostic` for blocks or unresolved unknowns,
`requires_approval` for ask/warn, and `eligible` otherwise. Eligibility is not
authorization or enforcement. A backend must still compile without widening,
validate policy, verify its boundary, and require approval where applicable.
Existing core review, adapters, and capability-profile behavior are unchanged.
