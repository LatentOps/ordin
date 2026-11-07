# Operator runbook

Keep the protected operator configuration, trust roots, enrollment pins and
backend objects outside agent-controlled repositories, prompts and message
payloads. Validate the actual host route inventory before assigning capability
maxima. A workload name, policy JSON or signed-looking text is not an operator
identity.

## Start and upgrade

Pin the core/adapter wheel digests, selected SDK versions, schema versions,
coordinator backend and policy digest in the deployment record. Check supported
routes using the maintained adapter diagnostics. Enable observation first and
retain unknown pre-attachment history. Use bounded shadow replay before a scoped
canary; classify synthetic review, host callback results and actual runtime
evidence separately.

Back up the protected transactional state and its independent audit checkpoint
before a version change. Preserve high-water marks, tombstones, consumed quota,
uncertain reservations and revocation history. The coordinator rejects missing
or changed authority schema; replacing a corrupt store with a fresh empty store
does not establish recovery. Validate migrations against a separate owned copy.

Do not keep two independently active central owners without the store's current
owner fence. Expired leases, incompatible schema, journal gaps and unavailable
authority refuse fresh high-impact effects. PostgreSQL supplies multi-host
transactions; local locks and SQLite do not provide distributed consensus.

## Change policy and roll back

Prepare the exact document against the protected maximum, simulate it, approve
the exact selection and activate a strictly newer epoch. Structural or observed
relaxation requires explicit approval. Refresh parent contexts before children,
rebind evidence sources, and obtain new current grants/reservations.

Rollback selects an older document through that same workflow with a new epoch.
It never restores its old approvals or tickets. Fence and drain protected
dispatch before downgrading software. An older binary must not be introduced as
an alternative route around the current broker. If it cannot read the current
authority/schema, retain the fence and use a tested migration/recovery path.
Re-evaluate pending work; do not deserialize execution permission from a report.

## Respond to an incident

Select the smallest supported scope and inspect the affected contexts before
publishing the durable fence. Narrow automatic rules are disabled until the
operator explicitly configures exact rule IDs, severity and blast-radius bounds.
Pause/revoke/quarantine must publish the DB fence without waiting for a callback
to finish. Backend notifications and issuer/credential cleanup run afterward.

Report canceled, completed, unable-to-stop and unknown work independently. A
completed external effect cannot be undone by revoking its grant. Local
credential-route revocation is distinct from rotation at the upstream provider;
complete the provider's authorized rotation procedure separately and re-enroll
the new scoped credential through the protected vault.

Resume only after actual backend reconciliation, current operator authorization
and a new owner/policy fence. Original known broker outcomes may resolve status
while uncertain quota remains held. Unknown/disconnected outcomes cannot be
declared clean by operator text or a copied JSON receipt. New sessions need
fresh evaluation and authority; revoked grants remain revoked.

## Privacy and capacity

Keep raw tool payloads, private messages, paths and credentials out of default
exports. Export only the minimum tenant-scoped projection needed by the
recipient. Retention is not secure erasure of filesystem backups, process memory
or upstream services. Keep independent audit anchors to detect truncation.

Set finite actor/source/journal/graph, reservation, incident and artifact limits.
Capacity exhaustion and incomplete collection remain visible proof gaps. Raising
a limit does not recover missing history or reset accounting. Use an explicit
authorized sweep for managed retention; do not delete the authority store to
free quota. Review optional inference separately from authenticated observations
and never turn an LLM risk score into an approval or execution receipt.

## Rotate TLS credentials and enrollment pins

Treat a leaf credential and its pinned enrollment as one protected identity.
Changing a name in a request or replacing a certificate file is not rotation.
Plan the change with the authorized host operator and preserve a separate
administrative recovery path.

1. Publish the appropriate coordinator/containment fence before changing trust
   material. Reconcile supported in-flight jobs; retain unknown outcomes and
   reservations. Rotation does not undo a completed effect.
2. Revoke the original workload/broker enrollment with
   `WorkloadAuthenticator.revoke_enrollment(enrollment_id, operator=...)`.
   Revoke an operator through `SwarmOperatorDirectory.revoke(...)`; that also
   invalidates the directory generation and its cached human channels, so other
   operators must re-authenticate. Close the original host TLS connections and
   channel handles. Provider-side key invalidation is a separate authorized step.
3. Issue a new distinct leaf certificate/key using the operator's approved PKI.
   Enroll its independently checked certificate digest through the protected
   `enroll_workload`, `enroll_broker` or directory `enroll` API, with explicit
   host, current original context/source, task and role bindings. Do not reuse an
   old enrollment ID or treat an identical common name as authentication.
   An operator may retain the same human principal after revocation; two active
   enrollments for that principal are refused. Revocation releases its active
   directory slot while the authenticator retains bounded certificate and
   revocation history, including refusal of the old certificate.
4. Authenticate a new actual TLS socket. Workload and broker certificates cannot
   become operator credentials. Obtain fresh current grants, approval receipts,
   reservations and evidence bindings; old original channels and grants are not
   transferred to the new enrollment by copying their JSON references.
5. Re-evaluate the canary and inspect coverage before the current authorized
   recovery ceremony clears the fence. Keep the fence if any step is uncertain.

CA trust/root or SSL-context configuration changes require a planned fresh
authenticator/service lifecycle. Existing authenticators bind their original TLS
configuration; silently editing that context is not a supported hot trust-store
update. Preserve durable accounting/revocation history, advance owner/policy
fences as required, re-enroll and re-authenticate with the new protected trust
configuration. Package upgrades likewise do not patch code already loaded by a
running process: fence/drain and restart affected old adapters, particularly the
security-blocked CrewAI path. Never use public fixture keys or CAs in production.

## Rotate tenant audit HMAC keys

The current journal is bound to its tenant privacy key and exact policy; there
is no in-place `rekey` operation. Opening an existing journal under a different
key fails integrity/key validation. Do not work around that check, relabel an old
chain, discard the old segment or the separate coordinator history or claim an empty journal has verified it.

1. Quiesce the protected audit producer as part of the authorized service change.
   Call `SwarmAuditSource.flush(operator=..., timeout=...)` within its supported
   bound and check its result and diagnostic gaps, then close the source and check that result too. A failed
   drain is an explicit incomplete segment, not successful persistence.
2. Save `SwarmAuditJournal.checkpoint(operator=...)` in an independent protected
   location and retain the original journal and old key under the configured
   retention/access policy. The checkpoint's trust comes from that protected
   custody; a checkpoint copied beside an attacker-controlled bundle is not an
   independent anchor.
3. Generate a new protected 32–64-byte tenant key. Create a NEW owner-only journal
   at a new path with `SwarmAuditJournal(..., key=new_key, create=True)` and bind
   its protected scope/producer in the fresh service lifecycle. Do not overwrite
   the old file or export either key with a report.
4. Retain an operator-controlled transition record containing the old checkpoint
   reference, new journal reference, applicable policy/owner fence and explicit
   gaps. This is an operational link, not a fabricated hash continuation or a new
   execution permission. Verify the old segment with its old custody/key and the
   new segment separately. Pseudonyms change with the key; do not automatically
   join them across key versions or tenants in public diagnostics.

Rotation/retention does not guarantee erasure of Python memory, backups, external
collectors or upstream provider records. Use the relevant authorized procedures
for those separate stores.

## Configuration versions and support window

This release supports the exact schema/manifest versions accepted by the shipped
parsers and store validators. Protected configuration rejects unknown fields and
versions according to its documented parser; changed authority DDL and missing
history fail closed. The shipped coordinator migration is the initial
schema, not a general automatic upgrade/downgrade engine. Rehearse changes on an
owned backup; retain label floors, tombstones, expenditure, uncertain holds,
fences and external audit anchors. Restore an older policy through a NEW approved
epoch. An incompatible older binary is not a fallback route around the broker.

The support matrix is a tested-version record, not a promise for all newer
releases. Core compatibility is checked by the existing Python 3.10–3.13 and
platform release lanes. Framework conformance names its exact SDK pins and tested
Python lane (currently 3.12). The finite physical worker requires tested Linux
x86_64 kernel controls; Windows host review/control tests do not establish Linux
runtime enforcement. AutoGen remains archived-version compatibility. CrewAI is
security-blocked until a verified patched dependency closure and new conformance
checks permit re-enablement. Do not describe two active maintained SDKs.

Before changing any pinned SDK, driver, schema or runtime version, rerun the
relevant source, installed-artifact, security, negative/bypass and compatibility
lanes and record the actual revision/environment. No calendar
LTS/EOL commitment is defined for this development release. Untested versions and
missing external conformance remain explicitly not evaluated.

Before clearing the fence, verify these acceptance conditions: old credential/channel
rejection after revoke; new pin requires new original enrollment; changed SSL
context refuses old authority; old journal/new key rejects; new journal has a
separate reference and no continuity claim; failed drain preserves a gap.
