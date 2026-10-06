# Minimal capability proposals

`CapabilityDeltaProposal` and `propose_capability_delta` are additive exports
from `ordin`. The core command produces data without approval, apply, or retry:

```sh
ordin capability propose --review review.json --contract capability.json \
    --denial private/denial.json --boundary boundary.json \
    --trusted-source private/source.json --json
```

Strong denial/source files must be explicit private host-owned evidence;
ordinary agent JSON cannot self-declare backend enforcement. The original
review's decision and uncertainty remain authoritative.

The optional `propose_openshell_delta` helper in `ordin_openshell.deltas` retains
the narrow core delta while constructing a whole backend candidate with the
reviewed startup requirements. It checks the candidate capability boundary,
compilation/validation, and configured standalone-prover result/input digests.
Every verification step and its coverage is retained. Unsupported, inconclusive,
exceeding, or mismatched proof results reject the candidate. Successful proof
still returns `requires_approval`; this helper never approves, applies, or retries.

`propose_capability_delta(review, contract, denial, boundary, backend=...)`
returns an immutable `CapabilityDeltaProposal` (`ordin.capability_delta_proposal.v1`).
It never approves a change, applies policy, executes an action, or retries it.
Initial proposals always require explicit human approval.

The original review must derive the supplied contract. The backend-enforced
denial must match its action digest and contract ID and, for session reviews,
the session scope. Caller assertions, blocks, conflicting identities, and
unmodeled requirements are rejected with stable reason codes and no grant.

Known filesystem access is narrowed to one exact denied resource. Known network
host/access prediction may be narrowed by a trusted denial to one REST method,
port, and path. A new network requirement after a filesystem-only prediction
returns `runtime_delta_unmodeled_requirement`; it never generates new authority.
Exact tools and credential bindings are handled independently. Unsupported
process or sandbox denials require investigation. No wildcard is added for
convenience. Unrelated uncertainty and the original decision remain intact.

The requested candidate is checked against the operator's maximum capability
boundary. This boundary is distinct from the currently active backend policy;
the denial identifies missing authority but does not prove the cause of drift.
When a backend is supplied, compile and validate results are retained. Unsupported,
inconclusive, incomplete, or digest-conflicting validation rejects the proposal.
An integration must additionally run its configured policy prover and preserve
coverage before explicit application. A verified narrow proposal is still not
approval, and core never transitions to `approved` or `applied`.

Privilege, credential changes, private/metadata network access, outside-repository
writes/deletes, recursive deletion, arbitrary TCP, unknown protocols, root paths,
unseen write hosts, and unmodeled requirements cannot be auto-approved. The initial
implementation also requires human approval for ordinary narrow proposals.
Operator approval and actual apply state belong to the optional runtime integration.
