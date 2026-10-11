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
No `npx`, package install or live scanner has been invoked in this work.

## Explicit optional scanner wrapper

`ordin.assurance.codex_security.scanner` (also
`ordin_codex_security.provider`) exposes `ScannerSelection`, `inspect_scanner`,
`configuration_review_digest`, `scan_action`, `run_diff_scan` and
`mock_scanner_run`. Selection requires absolute native runtime and optional
entrypoint paths, SHA-256 pins, exact CLI version, trusted working directory,
fresh private state directory and bounded timeout/output. Explicit native helper
pins supply PATH directories; target-local Node/npm, shell launchers and implicit
installation are refused. Installation, working directory, state and helpers must
be outside the target and every detected enclosing Git worktree. Linked/remote/
hardlinked executable mappings are refused. The host must protect the complete
installed dependency tree against writes; entrypoint hashes alone do not pin its
transitive modules or provide a physical execution boundary.

Inspection launches only the explicitly selected trusted process: `--version`,
`scan --help`, then `info --json`. It checks the actual flag surface, CLI/SDK and
optional bundled-plugin versions, no project-config selection and the upstream
`scanMcp: false` contract. Version drift, malformed metadata, output overflow,
missing installation, interruption and timeout remain distinct. Live invocation
currently supports the inspected **0.2.0** command contract only.

Live scans require a matching protected profile/source, an actual `HostApproval`
for `scan_action` and an action-bound satisfied `HostConstraintAssessment` with
`kind="scanner_isolation"` and `invariant_id="scanner.isolation"`. These receipts
cannot be reconstructed from JSON. The approval action explicitly discloses
source upload and binds executable/entrypoint/helper locations and hashes,
resource limits, target/base Git object SHAs and configuration review. Use
`configuration_review_digest` to capture supported project/native/Git config
inputs; existing unreviewed, inaccessible, linked or changed inputs refuse.
`reviewed_files=((absolute_path, sha256), ...)` must match actual bytes and scope.
A caller-supplied digest cannot bypass that check. Mutable branch/ref names are
refused for both scan ends. Configuration is rechecked after inspection.

The protected isolation assessment is issued only after the host's actual broker
has verified a read-only authorized target, private output ACLs, immutable trusted
installation, exclusion of unreviewed repository/native config, executable/MCP/
hook restrictions, credential routing and network destinations restricted to the
approved OpenAI service. Managed-device settings and platform sandbox behavior
must also be reviewed. A digest/boolean or these SDK checks alone cannot establish
those properties. Unresolved isolation must use `inconclusive`/`unsupported` and
the wrapper refuses it. The SDK does not create this physical sandbox or grant
credentials. These obligations are explicit because the scanner executes model
workflows and may start its own child processes.

Only an explicitly provided `OPENAI_API_KEY` is forwarded. Ambient credentials,
project selection, native preloads, cloud tokens and shell environment are
excluded; HOME/CODEX_HOME/state are isolated and Git hooks/fsmonitor/global config
are disabled in the child environment. No arbitrary flags, config/plugin paths,
custom provider endpoints, deep scan, patch or publication option is accepted.
The fixed scan uses `--diff BASE_SHA --head TARGET_SHA --mode standard --auth
api-key --provider openai --headless --json`. It reads sealed native output and an
available `threatmodel.md` through the offline importer. Raw stdout/stderr remain
bounded in process memory and routine reports contain only hashes/counts.

Processes use argument arrays and `shell=False`. POSIX uses a process session;
Windows starts suspended, joins a kill-on-close Job Object, then resumes through
the documented thread API. Timeout/cancellation/overflow and normal completion
end ordinary descendants and close pipes. The broker must prevent escape through
privileged external process services; process lifetime management is not an
egress or filesystem sandbox. POSIX execution remains unverified on this host.
Each invocation has its own deadline, including version/help/info inspection.

A native exit 1 with a valid completed matched import is `severity_violation`;
it is not a scanner failure. Exit 2, zero-finding partial output, failed schema/
seal validation and unmatched scope never become success. Exit 130/143 and
explicit cancellation remain canceled; other OS exit codes are preserved.
`ScannerRun` is an advisory execution/import receipt, never confirmation of an
Ordin vulnerability or execution grant. No live scanner result is claimed here.

```console
ordin-assure codex mock --exit-code 1
ordin-assure codex mock --completeness partial
```

The built-in mock starts no process and accepts no credentials. The SDK tests use
a host-owned fake Python entrypoint for actual local process state checks; it
does not load scanner, Node.js or model packages.

## Offline source and authority diff

`triage_source_diff` compares two `AuthorizedRepository` snapshots using the
bounded inventory, plus optional `SimulationPolicy` and `SecurityProfile` inputs.
It flags protected asset edits, new subprocess/network/tool syntax, enforcement,
MCP schema, host boundary and dependency file changes. Policies reuse the existing
capability/request subset comparator. Widened rights require review; unknown or
unsupported algebra and inspection gaps remain partial. Profile data never
activates or compiles itself through this API. Doc-only changes have a separate
finite heuristic classification. Alias/dynamic dispatch and unsupported-language
misses remain possible; no vulnerability scan, reachability or exploit proof is
claimed. Revision labels require host attestation; no Git or target code runs.

```console
ordin-assure source diff --baseline-root /authorized/before --candidate-root /authorized/after --repository example/repo --baseline-revision base-sha --candidate-revision head-sha --virtual-root /repo
python -I -m ordin.assurance.examples.source_diff --output ./new-synthetic-diff
```

Paired `--baseline-policy/--candidate-policy` and
`--baseline-profile/--candidate-profile` accept validated inspection data. Public
output contains reference hashes; `--include-details` explicitly retains private
source references. Exit 1 denotes deterministic authority widening, 2 unresolved
coverage/algebra or malformed input, and 0 a completed finite triage; inspect
`review_required` and limitations even after exit 0. Renames appear as separate
delete/add candidates, and absent/excluded files never imply resolved findings.

## Optional private CI example

[private-diff-scan.yml](../../integrations/codex_security/examples/private-diff-scan.yml)
is an example, not an enabled workflow. It allows only an explicitly approved
manual run on the private repository's protected main branch, under a protected
environment and an ephemeral broker-isolated Linux runner. Fork PRs and public
repositories have no credentialed scan path. Checkout/upload actions use full
commit pins; scanner CLI/Node SHA-256 pins come from protected deployment
variables and CLI/SDK version 0.2.0 is checked. Install reviewed Ordin and scanner
dependencies under `/opt/ordin-scanner`, outside all checkouts, before enabling
the workflow. No checkout dependency installation or automatic patching occurs.

The runner administrator must enforce the same isolation/configuration review
listed above, immutable runtime/helper installation, fixed service egress, total
CPU/memory/disk limits and destruction after the job. The example uses private
umask, file-size and process-time limits and saves diagnostic/native JSON output
outside the checkout. It imports saved artifacts with the trusted Ordin install,
retains only the redacted JSON advisory in private Actions artifacts for three
days, and propagates severity/incomplete/interrupted/timeout states after import.
Native JSON/SARIF and diagnostics stay in private ephemeral runner storage; private
repository Actions readers still need operator-approved access. It posts no
finding details, SARIF annotations, patches or PR comments. This workflow has
passed the local workflow guard; no remote runner, scanner or upload was tested.
