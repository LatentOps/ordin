# Ordin threat model

Ordin reviews proposed actions and supplies integration decisions. It is not a
sandbox, credential broker, authorization server, or proof that a tool's
implementation is safe. An `allow` means the supplied evidence passed the
configured review; the execution host must still enforce permissions.

## Trust boundaries

Agent/model output, proposed tool arguments, MCP client requests, upstream
responses, and discovery descriptions are untrusted. Parser limits, exact
identities, and data-only schemas reduce what these inputs can influence.
Discovery supplies contracts to review; it never grants semantics by itself.

The host must protect Ordin's installation/configuration, policy and semantics
files, reviewed contract pins, shell startup environment, filesystem controls,
and release-verification trust roots. Caller context, session/history state,
and post-action observations are trusted evidence only when the caller obtains
and isolates them correctly. A tool can lie about its effects; typed observation
fields are not independent measurement. Integration IDs correlate evidence but
do not authenticate the process supplying it.

Release trust includes the repository maintainers, protected source history,
GitHub Actions platform, selected action commits, Python build dependencies,
and artifact attestation identity. Signed provenance identifies a build; it
does not establish that all those components were uncompromised.

## Threat coverage

| Threat | Coverage and residual responsibility |
| --- | --- |
| Agent proposes destructive actions | **Prevents known blocked proposals** through correctly wired gates; unknown semantics generally require approval. Coverage is conservative and incomplete. |
| Prompt/tool injection | **Reduces** impact by reviewing resulting actions. It does not solve prompt injection or understand every malicious instruction. |
| Trusted identity changes contract | **Detects** drift when reviewed pins and correlated complete discovery are enabled. A server can preserve a schema while changing its implementation. |
| Agent modifies policy/semantics/configuration | **Does not solve** same-user configuration tampering. Protect files outside the agent's write scope; review changes and configuration digests. |
| Review/execution TOCTOU | **Does not solve** changes after review. The host must bind the reviewed action to actual execution and enforce resource access at use time. |
| Symlink or path target changes | **Reduces** accidental aliasing in private stores and retains literal policy identities. Lexical path matching is not filesystem isolation. |
| Malicious upstream MCP result | **Reduces** protocol abuse with bounded parsing, correlation, deadlines, and session isolation. It cannot establish truthful output or undo server-side effects. |
| Malformed/ambiguous protocol | **Prevents** rejected framing and duplicate/ambiguous JSON at strict MCP boundaries. Host hook formats have their separately documented contracts. |
| Cross-session contamination | **Prevents** mismatched retained identities/configurations through maintained session APIs; **does not solve** forged evidence from a compromised trusted caller. |
| Approval bypass through bad installation | **Does not solve** bypassed hooks or unguarded execution paths. Codex unresolved pre-tool decisions deny; host hooks must be installed and trusted. Normal shell Enter remains unwrapped. |
| Secrets in logs, audit, or diagnostics | **Reduces** exposure through default redaction and opt-in capture. Policy labels and explicitly included fields may still be private; raw capture is unsafe to share. |
| Compromised action/build dependency | **Reduces** exposure with immutable action pins, minimal permissions, dependency review, CodeQL, reviewed updates, checksums and provenance. These are not a proof of safe source. |
| Local audit modification/reordering | **Detects** inconsistent hashes, linkage, ambiguous JSON and incomplete records during verification. Trusted external checkpoints detect loss of the recorded tail. |
| Whole-file replacement or forged audit history | **Does not solve** an attacker rewriting a complete chain and any colocated checkpoint. No trusted external timestamp or signer is implied. |

## Runtime capability and evidence boundaries

The optional [OpenShell adapter](openshell-integration.md) adds an enforcement
plane outside core. Capability contracts are advisory until a runtime applies
them. The core derives and verifies data; it does not start a sandbox, grant
credentials, run an action, or retry a denied operation.

| Threat | Controls and residual responsibility |
| --- | --- |
| URL authority/userinfo confusion | Capability derivation, observations, request parsing, setup, and gateway configuration reject userinfo by presence, including empty `@` and `:@` syntax. Endpoint-only URLs reject queries/fragments and malformed ports. Retry reasoning cannot normalize a rejected URL into a permitted endpoint. Native event paths accept relative targets only; full URLs are rejected before protected correlation. Rejected values are omitted from bounded diagnostics. |
| Raw HTTP vs GraphQL/MCP authority confusion | Request verification retains each original protocol's grants after transport projection. Raw HTTP and mixed raw/protocol candidates cannot borrow GraphQL/MCP permissions on overlapping host/port/path. Explicit HTTP grants remain independently usable. Opaque high-level boundary identities are unsupported rather than discarded. |
| Compiler widening | Unsupported/unknown fields produce no enforceable plan. Golden and negative tests cover exact REST rules, binary identity, filesystem primitive rights, wildcard/private expansion, and credential mapping. Plan validation rebuilds from the original contract independently of a backend override. Shadow reports expose widening rejections. Core boundary checks and backend prover coverage answer different questions; both are needed where configured. |
| Runtime evidence spoofing | Ordinary JSON/direct constructors reject strong trust labels. Only a host-owned `RuntimeEvidenceSource` can report backend evidence. Protect the collector and its backend channel; a product label in JSON is not authentication. Allowed OCSF events stay `backend_observed` because this version does not structurally distinguish audit allows from enforcement allows. |
| Stale contract / TOCTOU | Canonical action digest and content-derived contract ID detect changed reviewed inputs. Private correlation binds the exact event digest, original action/contract, session, sandbox, and policy. The host still must enforce those identities at execution time; lexical scopes and hashes do not freeze filesystem objects. |
| Policy drift | Plans/correlation retain canonical policy digests; prover results retain input-byte digests. The explicit applier verifies configured boundaries, binds operator approval to current state, and checks effective policy, loaded revision, sandbox identity, and workload admission. It refuses live startup-policy changes. The host must serialize management: CLI readback is not an atomic server-side CAS and cannot prevent a later trusted update or runtime compromise. |
| Runtime compromise | Ordin trusts the supervisor/gateway/runtime and the host adapter reporting path. It does not solve compromised enforcement, forged backend output from that trusted path, or an attacker in the trusted Python process. Strong trust labels are not cryptographic remote attestation. |
| Credential-binding confusion | Credential bindings have independent boundary and destination checks. Host access never discovers or grants a provider. The compiler accepts only explicit provider identities with matching endpoint/method/path restrictions and never accepts secret values. Raw headers, bodies, commands, event messages, and URL queries are excluded from new evidence artifacts. |
| Cross-session event contamination | Session digest/reset epoch, original action digest, contract ID, sandbox identity, policy digest, bounded expiry, and consumed event identity reject stale/mismatched attachment. The collector must protect sandbox-generation attribution; the adapter never guesses attribution from host/tool names, time, or numeric OCSF action IDs. |
| Malformed runtime readback | Canonicalization validates endpoint, rule, allow, and parameter shapes before traversing MCP selectors. Unsupported readback stops preparation before policy mutation; unexpected defaults or added authority are not silently removed. A structured backend result still depends on the protected runtime channel. |
| Stale release evidence | Acceptance evidence records the actual tested source revision/digest, versions, schema count, test/skip counts, and the provenance of each runtime report. Historical reports are labeled separately. Green results for a different revision, a fixture, or an uncorrelated event do not prove current-source runtime enforcement. |

The private correlation SQLite store requires owner-only POSIX files and a
protected directory, bounds records/database size, and writes atomically.
Checksums detect corruption, not malicious owner rewriting. Capacity fails
instead of dropping replay protection. Shadow reports are local projections
of supplied facts, omit plaintext action/resource/event data, and never promote
themselves to enforcement. Missing facts remain inconclusive.

## Local evidence

`JsonlAuditSink(hash_chain=True)` uses a private regular file and an advisory
writer lock. Cooperating instances/processes read the current chain head while
holding that lock. An unchanged file can reuse its verified head; changed file
metadata causes revalidation. Locks do not constrain a malicious process that
ignores them. The host must provide a trusted local directory; shared/network
filesystems with different lock semantics are outside this guarantee.

The verifier bounds file/line sizes and rejects duplicate keys, non-finite
values, excessive nesting, broken links, altered event hashes, and incomplete
lines. It verifies internal consistency, not truthfulness of decisions or
timestamps. An empty chain or a valid truncated prefix can be internally valid.
Retain the last hash outside the writer's control and pass
`expected_last_hash=...` to detect divergence from that checkpoint.

Audit and capture stores are separate from session-state transactions. A
persisted proposal is not proof that the host executed it. See
[trace capture](trace-capture.md) and [audit evidence](audit-and-provenance.md).

## Repository and release controls

- `main` requires passing CI and PR merges; force pushes and deletion are disabled.
- Workflow actions are pinned to full commit SHAs with version comments;
  checkout does not persist credentials. A permanent guard rejects floating
  actions, broad defaults, privileged PR triggers, and inherited secrets.
- CodeQL analyzes Python on PRs, main, and a schedule. Dependency review checks
  newly introduced vulnerabilities in runtime/development dependencies.
  Dependabot maintains actions, package declarations, and release-tool pins.
- Private vulnerability reporting, security updates, secret scanning, and push
  protection are enabled through GitHub repository settings. These settings
  are not controlled by YAML; maintainers should recheck them after transfers
  or organization policy changes. Provider validity checks are not enabled.
- PR builds only have read permissions. Tag/manual attestation and tag-only
  publishing jobs receive their specific signing or release permissions. Publication downloads
  the already tested artifact by immutable artifact ID and never rebuilds it.

The workflow guard and protected-branch review are the repository posture
checks here. A separate Scorecard publishing action is omitted: it would add
another workflow/token surface without replacing these explicit checks or the
deterministic safety benchmark. Dependency review may display upstream
Scorecard signals; they are advisory.

Checksums detect changed bytes. GitHub attestations bind the checksums and
distribution assets to the workflow/source identity. The release workflow
checks version/tag/source equality, verifies the remote tag again before
publication, and refuses to replace an existing release. Maintainers still
must protect tags/accounts and review dependency updates. See
[releasing](releasing.md) for verification commands and the SBOM's scope.

## Protocol request scope and exported findings

GraphQL operation/field and MCP method/tool/version permissions use a separate
action-bound request artifact. Nested selectors, variables and argument
constraints must not disappear when the backend cannot enforce them. A request
boundary checks transport and high-level scope independently; protocol apply
requires that boundary and exact host approval. The pinned standalone prover
does not cover GraphQL/MCP, so configured backend proof refuses application.
Logical MCP server identity depends on protected host transport declarations
and existing semantic/contract pinning, not a name substring or remote
attestation. Generic HTTP events do not establish high-level request fields.

GraphQL aliases and flat fragments are resolved to actual root field names;
conflicting aliases, missing/cyclic fragments and unmodeled constraints fail
closed. MCP control methods require exact method boundaries and host transport
bindings. Older MCP revisions require explicit host version declarations,
retained in provenance and intersected rather than unioned. The pinned backend
cannot enforce GraphQL arguments/nested fields or MCP argument values; policy
serialization support alone is not enforcement evidence.

Optional OCSF Detection Findings retain digests and fixed machine categories,
omitting commands, arguments, human reasons, resource identities and raw
payloads. They report local decisions and diagnostics; they cannot be restored
as backend-enforced runtime observations or authorize an action. The local
hash-chained audit remains the explanation/integrity record.
