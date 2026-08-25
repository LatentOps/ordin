# JSON Schema Contracts

Ordin publishes machine-readable JSON Schema contracts for its stable
JSON surfaces. The checked-in schemas use JSON Schema Draft 2020-12 and are
available under `schemas/`; installed packages carry the same files under
`ordin/resources/schemas/`.

## Published contracts

- `command-card.v1.schema.json`
- `search-result.v1.schema.json`
- `risk-review.v1.schema.json`
- `review-result.v1.schema.json`
- `review-request.v1.schema.json`
- `action-envelope.v1.schema.json`
- `action-review.v1.schema.json`
- `policy-set.v1.schema.json`
- `action-trace.v1.schema.json`
- `risk-rules.v1.schema.json`
- `effect-catalog.v1.schema.json`
- `effect-graph.v1.schema.json`
- `command-pack.v1.schema.json`
- `pack-list.v1.schema.json`

## Versioning policy

A schema version identifies a machine contract, not the package release.
Backward-compatible additions should be optional or otherwise preserve existing
consumers. Removing fields, changing field types, changing required semantics,
or reinterpreting an existing field requires a new schema version.

Command cards remain `ordin.command_card.v1`; the typed effect metadata
added to cards is additive. Command review requests use
`ordin.review_request.v1`. Generic actions use `ordin.action_envelope.v1` and
return `ordin.action_review.v1`. Declarative policies use
`ordin.policy_set.v1`. Pack manifests use `ordin.command_pack.v1`, while
`ordin packs --json` returns `ordin.pack_list.v1`.

The generic action schema deliberately permits future action-kind identifiers.
Schema acceptance does not imply semantic confidence: if Ordin has no deterministic
adapter for an accepted kind/operation, review returns `ask` rather than `allow`.

Policy provenance is additive on `ordin.action_review.v1`: the `policy` and
`policy_matches` fields are emitted only when an explicit policy is evaluated.
Unconfigured action reviews therefore retain their original serialized shape.

## Doctor validation

`ordin doctor` validates repository/package metadata in layers:

1. schema files are present and declare Draft 2020-12;
2. command cards, risk rules, effect catalogs, pack manifests, and public policy schemas satisfy their contracts;
3. risk rule regexes compile, rule IDs are unique, and risk values are valid;
4. command templates use known slot names and valid `safe_defaults`;
5. command-pack files exist, use safe relative paths, and reference the expected analyzer bindings;
6. typed graph effects and references are valid;
7. graph and pack-list exports satisfy their public JSON Schemas;
8. source data, pack data, schemas, and packaged resource copies are identical in a source checkout.

The runtime validator is intentionally dependency-free. It implements only the
JSON Schema keywords used by the checked-in contracts, including bounded string,
array, and object sizes where the runtime consumes untrusted action and policy
payloads. The schemas themselves remain standard Draft 2020-12 documents that
external tooling can validate with full JSON Schema implementations.

Any validation error makes `doctor` return a non-zero exit status.
