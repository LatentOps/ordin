# Offline external workflow claims

`ordin-assure codex import-workflow` reads saved validation, patch, fix-verification
or patch-risk output. It never invokes Codex Security, runs reported commands,
applies patches, opens report links, creates PRs or changes an Ordin policy.
Reported `fixed`, `verified`, `reportable`, `merge` or `auto_merge_candidate`
values remain imported claims. They cannot replace Ordin's source/test/host
validation or authorize execution, publication or integration.

The parser supports the inspected [pinned SDK/CLI source](https://github.com/openai/codex-security/tree/6f4c62875baa310c6f18608035309e77bc8e808b):

| Selected workflow | Saved format |
| --- | --- |
| `validate` | SDK disposition/report JSON with optional outputDir/threadId; CLI prose via `--format text` |
| `verify_fix` | Repository, optional scanId and ordered id/status/evidence results |
| `patch` | Saved-finding occurrence/status/files/verification/reason results, or supplied-issue file/application summary |
| `patch_risk` | Standalone structured patch-risk-assessment JSON |

These shapes are distinct. A validation disposition may reflect static reasoning
rather than reproduction. File changes alone do not establish a fix. Prose is
preserved without inferring a verdict from words or headings. Embedded risk prose
without a supported structured assessment remains private capture with a gap.
See the [pinned workflow reference](https://github.com/openai/codex-security/blob/6f4c62875baa310c6f18608035309e77bc8e808b/sdk/typescript/docs/cli.md#validate-and-patch-findings).

The risk schema is vendored under the existing upstream Apache license, with Git
blob `b89b932582bd31e3f0dcf7ddaff3b9366157b579` verified before parsing. Unknown
fields, duplicate JSON keys, nonfinite values, unsafe links and absolute/traversing
reported file paths are refused. The parser enforces numeric JSON type distinctions,
unique collections and property-count limits. Artifact `$schema`/`$ref` values
cannot fetch files, services or alternative schemas.

Native output may omit version, revision or expected coverage. Save an
operator-reviewed `workflow-capture.json` using `WorkflowCapture.as_dict()`:

- Workflow and repository ID/revision.
- Reported tool/version and scan ID where applicable.
- Native repository mapping and ordered expected finding identifiers.
- Saved artifact SHA-256, reported terminal status and exit code.
- Patch SHA-256 for risk assessment.

The manifest is an imported declaration. Matching hashes establish byte identity,
not authenticity, reproduction or permission. Wrong/missing hashes, version drift,
scope/scan/patch mismatch and missing/duplicate/reordered finding coverage retain
partial/unknown status. Standalone validation can lack a scan ID; its captured
finding identity must remain explicit. Fix-verification exit `0`/`1`/`2` is checked
against reported fixed/vulnerable/inconclusive results without promoting them.

Routine output hashes identifiers and scope metadata and omits raw evidence,
instructions, paths, code and report text. `--include-details` and the private SDK
detail methods explicitly expose preserved vendor material. Keep it out of shared
logs. `complete` means internally consistent capture, while `closure` always
stays `not_performed` and `authority_change` stays `none`.

Import an already-saved fix-verification report:

```bash
ordin-assure codex import-workflow --artifact-root /private/saved-workflow \
  --repository project/example --revision REVIEWED_REVISION \
  --workflow verify_fix --expected-scan-id SCAN_ID \
  --expected-identifier OCCURRENCE_ID --report new-summary.json
```

Use `--expected-patch-digest REVIEWED_SHA256` for `patch_risk`. For saved validation
prose, choose `--workflow validate --format text` and its artifact path. Exit `0`
means complete import only; exit `2` indicates partial/unknown/malformed capture.
No severity, fix or merge label becomes an active restriction or approval.

The SDK is in `ordin.assurance.codex_security.workflow`, with an optional
`ordin_codex_security.workflow` facade. Live external execution, authentication,
patch application and publication remain explicit operator actions outside
Ordin's default runtime. They were not exercised by these tests.
