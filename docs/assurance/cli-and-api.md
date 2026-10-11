# Assurance CLI and Python reference

All commands are under the independent `ordin-assure` entrypoint. Ordinary Ordin
commands keep their existing configuration and behavior. The equivalent module
invocation is `python -m ordin.assurance.cli`. JSON is the deterministic default;
`--json` is accepted explicitly. `--report`/`--output` creates a new report only,
refusing existing files. JSON input paths can be `-` for bounded stdin; native
scanner/workflow artifacts remain explicit files in a scoped artifact root.
Malformed input produces a coarse diagnostic without source/secret echo.

| Command | Purpose and authority limit |
| --- | --- |
| `profile validate PATH` | Validate content; does not approve it |
| `profile inspect PATH` | Summarize rules/assets, with optional explicit private details |
| `invariants check --profile PATH --action PATH` | Preview intrinsic selectors; no protected approval or active restriction |
| `policy simulate` | Replay independent detached configurations and a frozen corpus |
| `policy diff` / `report compare --before PATH --after PATH` | Compare simulation reports only when corpus/order match |
| `challenge list` | List finite supported properties and proof limits |
| `challenge run` | Seeded bounded synthetic property/authority tests |
| `challenge replay` / `counterexample replay PATH --revision REV` | Reproduce the exact saved checker failure, not an unsafe action |
| `counterexample regression-propose PATH --case-id ID --revision REV` | Prepare a reproduced failure plus benign control for host review; no adoption |
| `counterexample regression-replay PATH --revision REV` | Recheck a saved boundary regression and its exact code/revision/control bindings |
| `codex import` | Offline findings/SARIF ingestion |
| `codex import-workflow` | Offline external validation/patch/fix/risk claims |
| `codex mock` | Synthetic scanner lifecycle/status examples |
| `source diff` | Read-only source/configuration triage |
| `attack-path analyze --evidence PATH` | Inspect imported graph data; strong labels are not authenticated |
| `delegation verify --parent PATH --child PATH` | Compare declared rights; operator/task maxima are separate inputs |
| `finding validate --input PATH --mode static` | Check candidate/rubric source references; no runtime closure |

Use each command's `--help` for its complete arguments. Declaration/data-only
operations never issue credentials, grant execution, restore backend trust from
JSON, apply a policy/patch, install dependencies, call a model/scanner or publish.
CLI execution-capable validation/inference is intentionally supplied by the
protected SDK host rather than fabricating receipts from command-line flags.

Exit meanings:

- `0`: selected validation/comparison/import completed within its documented
  scope; it is not universal safety or permission to execute.
- `1`: security regression, excessive declared authority, baseline denial or
  a matching prospective restriction.
- `2`: partial/unknown/unsupported/malformed input, unavailable proof, untrusted
  graph data or static review without runtime closure.

Each complete gate retains its own proof scope. For example, static finding
review always remains inconclusive about runtime reproduction, imported graph
analysis retains `origin=imported_claim`, and a matching delegation declaration
does not establish expiry/revocation/lifecycle or physical enforcement. Missing
operator/task maxima cannot be inferred from the parent.

Public Python entrypoints are in `ordin.assurance`: profile selection/compiler,
gate and host facts, simulation/counterexamples, source origins/graphs, delegation,
finding/fix workflows and deterministic adapter composition. Offline helpers
include `inspect_profile_content`, `preview_invariants`, `inspect_attack_path`,
`compare_delegation_data` and `review_static_candidate`. Optional namespaces are
`ordin_codex_security` and `ordin_decision_models`; core dependencies remain empty.

`SecurityProfile.from_dict()` produces validated content.
`load_approved_profile()` requires a `ProtectedProfileSelection` with exact file/
profile/version/repository/runtime bindings and a protected host source. Arbitrary
files, JSON flags and profile digests cannot activate a profile. Strong SDK
receipts cannot be reconstructed from ordinary JSON.

Optional `RestSemantics` is an explicit typed host selection for literal REST
actions. `RestRequestAuthority`, `RestRequestBoundary`, `RestRequestContract`,
`derive_rest_request_contract` and `verify_rest_request_authority` preserve exact
method/URL/headers/JSON-body requirements beside unchanged core v1/v2 schemas.
Read the [REST scope reference](rest-requests.md); ordinary CLI preview does not
activate these semantics or a transport.

The registered schema list is reported by `python -m ordin doctor` and
`ordin.schema.SCHEMA_FILES`; source schemas and packaged copies are byte-checked.
CLI preview/inspection schemas include profile inspection, invariant preview,
attack-path inspection, delegation inspection, static finding review and challenge
catalog. Existing records retain their independent bounds and semantic checks.

Read the [trust model](security-and-privacy.md), [profile lifecycle](profiles.md),
[finding/fix scope](finding-validation.md), [external claim formats](external-workflow-claims.md),
[delegation](delegation.md), [provider setup/privacy](decision-models.md) and
[exact current implementation evidence](implementation-report.md). The
[offline quickstart](../../examples/assurance/README.md) is shipped as a runnable
module. Release, disclosure and real-provider/host acceptance remain separate.
