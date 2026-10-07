# Exact runtime request authority

The v2 request contract binds an action to an exact approved request payload.
It stores a portable SHA-256 commitment and operation identifiers, with no
plaintext argument values. The original capability v1 contract remains embedded
and retains its action digest and semantic provenance.

| Protocol | V2 authority |
|---|---|
| GraphQL over JSON HTTP POST | Selected named or anonymous operations, variables, arguments, nested selections, aliases, fragments, directives, subscriptions and ordered batches |
| MCP over HTTP | Exact method, tool, parameter values, request/notification kind and approved protocol revision; initialization and pagination parameters are included |
| Generic JSON-RPC over HTTP | Exact method and parameters, request/notification kind, complete ordered batches; correlation ID values do not grant authority |
| TCP | Exact connection endpoint and executable identity; bidirectional authority requires `write`, with no application-level request claim |

Unknown fields, duplicate decoded JSON keys, ambiguous operation selection,
conflicting aliases, invalid or cyclic fragments and unmodeled transport choices
fail closed. GraphQL syntax follows the pinned Apollo parser's October 2021
grammar. Braced and surrogate Unicode escapes remain unsupported; literal
Unicode scalar values and supported four-digit escapes are accepted.

Use `ordin.runtime_requests_v2.derive_runtime_request_contract_v2(review)` or
`ordin-openshell derive-requests --review review.json`. The CLI defaults to v2;
`--schema-version 1` retains the coarse legacy request artifact. Legacy v1
GraphQL/MCP policies do not gain a request-argument proof through a POST-only
projection. Migrate them to v2 for complete request authority coverage.

`RequestAuthority.from_body(protocol, url, body)` computes the bounded authority
commitment without I/O. GraphQL commits the complete envelope. RPC projection
preserves method, parameters, missing versus null, kind, batch order and
multiplicity. Object key ordering is neutral. Exact decimal numeric values are
preserved across Python and Rust; float rounding cannot equate different wire
decimals. Integers and decimals remain distinct, as does signed decimal zero.

The limits are 1 MiB raw/framed bytes, 4096 nodes, depth 32, 128 items per JSON
container, 65536 UTF-8 bytes per string, 1024 number digits and decimal exponent
magnitude 10000. The domain prefix is outside the framed-byte budget. The v2
compiler explicitly sets the matching 1 MiB inspection limit.

The optional compiler intersects protocol rules with the commitment. Every
forwarding path checks POST, absence of URL query delimiters, absence of upgrades,
complete body framing and the commitment. It checks transformed bodies again
after middleware and credentials. A mismatch denies before forwarding.

Generic RPC method names may contain glob punctuation. Its coarse rule uses
`method: '*'`; the mandatory complete commitment enforces the exact method and
parameters. That policy requires the audited runtime extension. Stock 0.1.2
cannot establish compatibility by version string alone.

Host-owned `network_scopes` supply explicit host patterns, ports, protocols and
IP/CIDR ranges. The compiler expands them to the action's exact endpoint; it
does not copy wildcard network authority into the executable policy. Every
matching approval must agree on its address ranges. Private IPv4 and IPv6 ranges
are supported, while protected metadata, loopback, link-local, unspecified,
multicast and mapped-address ranges are excluded. Driver host-gateway aliases
are excluded because their special routing mode bypasses ordinary CIDR checks.

`RuntimeRequestBoundaryV2.network_grants` can bound wildcard host authority;
host-reviewed tool/server patterns are expanded to exact action identities.
The protocol and complete request commitment remain independently constrained.

The composed prover checks exact protocol, method/operation, arguments,
revision, executable and address containment before invoking the native solver
on an exact transport projection. It records original input hashes, component
hashes and explicit coverage. Raw REST cannot borrow GraphQL or RPC permissions.
An explicitly broader TCP maximum can contain narrower request authority.

Apply checks the audited CLI, gateway and supervisor build identities and the
current admitted configuration tuple. Literal TCP additionally requires actual
confirmed `seccomp-notify` and `seccomp-notify-procfs` mediation. These fields
are reported after authenticated boundary confirmation; caller JSON does not
establish the runtime capability. Human approval remains bound to the complete
preparation digest, and policy readback must match after the single mutation.

Successful native events carry the matched commitment and workload binary.
Pass the v2 artifact to ingestion with `--request-contract`: a coarse allow or
different payload cannot become exact request evidence. Protected event/action,
session, sandbox and policy bindings remain mandatory. Argument values, raw
bodies, headers and credentials are not retained in these artifacts.

Non-REST credential bindings, uninspected WebSocket messages, SQL and unknown
application semantics remain explicit non-successes. TCP grants do not imply
SQL or arbitrary application-level proof. Core retains zero required dependencies
and never starts a service, applies policy or executes an action.
