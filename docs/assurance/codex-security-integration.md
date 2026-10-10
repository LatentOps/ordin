# Offline Codex Security artifacts

`ordin-assure codex import` reads saved JSON/SARIF and optional threat-model
Markdown. It requires no account, API key, Node.js, scanner installation, model
download, network or subprocess. The data-only API is included in the normal
wheel at `ordin.assurance.codex_security`; the separate optional
`ordin_codex_security` adapter namespace reexports it.

```console
ordin-assure codex import --artifact-root /private/scan-output --repository example/repo --revision reviewed-sha
ordin-assure codex import --artifact-root /private/exports --repository example/repo --revision reviewed-sha --format sarif --sarif-path results.sarif
```

Default output is redacted advisory JSON: counts, hashes, reported severity/
confidence, coverage and gaps. It omits original message bodies, code, paths,
endpoint/identity fields, Markdown and vendor IDs. `--report ./new-file.json`
creates a new file explicitly and refuses overwrite. `--include-details` selects
the sensitive lossless machine record; keep that output private. The SDK's
`as_dict()` is that private record, while `public_dict()` is the routine summary.
`reported_details()` and `reported_metadata()` recover original structured data,
including multiline code, validation, reachability, counterevidence, remediation,
tests, taxonomy, source links, extensions and exclusions. SHA-bound printable JSON
chunks keep this capture immutable without relaxing public contract text limits.

Native documents follow the [pinned upstream findings/manifest/coverage schemas](https://github.com/openai/codex-security/tree/6f4c62875baa310c6f18608035309e77bc8e808b/plugins/codex-security/schemas).
The adapter pins commit `6f4c62875baa310c6f18608035309e77bc8e808b`, TypeScript SDK
`0.2.0`, and individual Git schema blobs. Trusted bundled schemas are hash-checked;
artifact `$schema`/`$ref` values cannot fetch anything. The Apache-2.0 schema
license and exact source metadata are preserved in the integration resources.

Native findings preserve original finding/occurrence IDs, exact duplicate rows,
reported levels/scores and complete vendor details. Ordin records stay `imported`,
`origin=imported_claim`, `verification_method=none`; a vendor `confirmed` field
never becomes Ordin confirmation or backend evidence. Sealed content hashes are
checked for every declared artifact under the authorized output root, but those
hashes authenticate bytes only, not vendor identity or exploitation.

Missing manifest, coverage, target or revision data remains unknown. Partial,
failed/canceled/interrupted or mismatched scans cannot report complete import
coverage. Zero imported findings does not mean clean or secure. A completed scan
can retain exclusions; the importer preserves them instead of expanding the
claim beyond its selected scope. `ImportScope.source_repository` optionally
verifies source references against actual authorized bytes/version/line ranges.
Missing/renamed sources remain unverified and prevent conclusive mapping.

Imports reject linked/hardlinked/special artifacts, traversal/absolute/unsafe
references, duplicate JSON keys, nonfinite values, unsafe controls/surrogates,
unknown native schema fields, malicious hyperlinks, changed seals and inconsistent
IDs. Limits are one MiB per JSON file, 16-level input nesting, 65,536 nodes,
256 findings, 128 supporting artifacts and eight MiB total sealed input. Source
locations are inert data and no code/remediation is executed. Markdown instructions
cannot change environment, policy, observations or permission.

SARIF supports a bounded 2.1.0 subset of producer/rules/results/messages/locations/
properties/fingerprints, related locations, code flows and suppressions. Its full
supported details are retained as claims. External URI bases/property files and
absolute or encoded source-URI languages require separate authorized mapping and
are refused. A projection lacks verified native scope/coverage/seal, so its
completeness remains unknown, including zero-result projections. Reported SARIF
levels are preserved in details; missing vendor severity/confidence stay unknown.

Exit 0 means a valid complete **imported scope**, not vulnerability confirmation.
Exit 2 means partial/unknown/malformed import. Optional `--fail-on-severity high`
returns 1 for a complete import containing a vendor-reported threshold finding;
partial coverage retains exit 2. Findings remain unconfirmed in either case.

`propose_imported_profile` produces only a non-authoritative draft. Restriction
suggestions require fresh authorized source-reference validation; absent source
verification leaves suggestions empty. Private threat-model narrative remains
context, never executable policy. Operator review/selection and protected
installation remain separate.

CLI command contracts differ between the [current online reference](https://learn.chatgpt.com/docs/security/cli/reference)
and the [pinned repository CLI guide](https://github.com/openai/codex-security/blob/6f4c62875baa310c6f18608035309e77bc8e808b/sdk/typescript/docs/cli.md).
The latter supports positional saved-directory export and `--scan`, policy drafts
and threat-model export; the online reference documents the positional export
shape. Future invocation must inspect the selected executable/version/help first.
No `npx`, package install or live scanner has been invoked in this work. The live
wrapper, offline diff triage and optional CI example remain M8 work.
