# Assurance machine contracts and trust

`ordin.assurance.models` supplies immutable profile content, non-authoritative
drafts, typed invariant definitions/evaluations, attack-path records, findings,
simulations, safe counterexamples, delegation proposals and model evidence.
Every top-level JSON artifact carries its own additive `ordin.assurance_*.v1`
schema. Existing v1 contracts remain unchanged.

The checked-in Draft 2020-12 schemas, packaged copies and in-memory definitions
must agree byte-for-byte for the copies and structurally for runtime definitions.
`scripts/generate_assurance_schemas.py` regenerates only the fixed reviewed
Assurance contracts. It is a development tool, not an importer or policy loader.

| Bound | Value |
| --- | --- |
| Encoded JSON artifact | 1 MiB |
| JSON value nesting | 12 levels |
| Total JSON nodes | 65,536 |
| Text value | 4,096 characters |
| Object members / ordinary artifact collections | 256 |
| Attack-path edges | 512 |
| Simulation cases / global prevalidation array limit | 4,096 |
| Model answers | 32 |
| Ordinary identifiers | 128 characters |

Schema-specific bounds apply after global parsing limits. JSON parsing rejects
duplicate decoded keys, nonfinite numbers, surrogate/control text, excessive
nesting and oversized artifacts. Source references are bounded relative ASCII
paths and line numbers; traversal, URLs, drive paths and ambiguous separators
are rejected. Reading/verifying references against an authorized snapshot is
a separate repository-inventory operation.

Python validation also checks semantic facts that JSON Schema cannot establish:
unique IDs across records, graph references/session consistency, asset
references, ordered latency percentiles, grant lifetime/depth, counterexample
input digests, incomplete simulation claims, model answer consistency and
authenticated provenance/closure. Structural schema validity is neither
approval nor proof of observation. A schema describes the exported shape;
ordinary JSON import may refuse privileged host evidence in that shape.

Returned mappings/lists are detached from the immutable records. Canonical
digests bind sorted UTF-8 JSON under an explicit artifact/domain/version prefix;
array order is retained. Digests detect changed content. They authenticate no
issuer and do not encrypt low-entropy paths, identities or secrets.

`SecurityProfile` is validated content. `ApprovedSecurityProfile` is a separate
host selection handle that cannot be decoded from JSON. Profiles may contain
exact private asset values for local operator use. Their `as_dict()` output is
private content serialization, not a public redacted report. Keep these files
outside agent write scope and out of public logs. Public report generation must
redact identifiers/resources and reject secret-bearing values before export.

`EvidenceLink` separates origin from confidence. Ordinary decoding accepts
caller/static/imported/model claims, but cannot claim `policy_verified`,
`runtime_backend_observed` or `deterministically_derived`. Protected host APIs
must issue those origins from independently verified inputs and bind their
payloads. Finding `confirmed`/`refuted` closure likewise requires verified host
validation; imported findings remain hypotheses/inconclusive.

`DelegationGrant` is a proposal/evidence artifact, never a credential or an
issued host authority handle. Even an input-declared `issued` status conveys no
authority. Later lifecycle checks must obtain the current host-issued record
and verify exact subset, expiry, revocation, session and epoch before use.
