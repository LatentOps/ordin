# Guarded artifacts, shared memory and workspaces

`SwarmArtifactGateway` controls an explicit host-managed data store. It provides
tenant/workspace isolation, exact-agent permissions, immutable version metadata,
conditional updates and conservative sensitivity labels. It does not intercept
raw file opens, shared-memory pointers or arbitrary vector-store queries.

## Resource and authority model

`ArtifactAddress` fixes tenant, swarm, workspace, namespace, key and resource
kind (`artifact`, `workspace`, `kv` or `vector_entry`). Workspaces and
namespaces are explicit host configuration. Policy, system-prompt and credential
namespaces are forbidden, including case variants. Keys are bounded identifiers,
not arbitrary paths; `../` traversal cannot address a host policy file.

The original protected `HostEventSource` identifies each caller through the
current registry context and bound host evidence source. Serialized agent IDs,
metadata and grant IDs are not authority. The creating context owns the
resource. Another context needs an original `ArtifactGrant` issued with the
exact protected operator capability.

Grants select read/write/delete/export rights, one immutable version, allowed
sensitivity labels, the exact recipient context and a bounded lifetime. A
write grant cannot introduce stronger labels than the operator allowed.
Old public grants do not expose a later sensitive version. Expiry, revocation,
restart and policy-epoch changes deny stale access. A successor or delegated
agent gets no automatic rights from its name or parent: the operator must
explicitly approve its current generation and version. Artifact sharing does
not mint tool delegation or workload credentials.

## Writes and immutable versions

`write` requires complete original lineage handles for the exact UTF-8 value,
the expected current version and a bounded TTL. The first version requires
`expected_version=0`; later writes compare against the actual high-water mark.
Concurrent updates with the same expected version cannot both commit.

Every material write verifies the actual bytes, records an authenticated
`artifact_write` event, and creates protected source classification for that
stored version. Labels join all current inputs and the resource's prior
classification. A public replacement, deletion/recreation or a changed filename
does not strip prior sensitivity. Version metadata retains bounded lineage
digest pointers, including the preceding version digest.

Ordinary writes cannot lower a resource's classification. An operator may use
the separate source-flow declassification API for a checked immutable payload
and publish it under a new explicitly approved resource identity. That preserves
the original resource's classification and the declassification audit.

Bytes, journal and protected classification must commit before a new version is
published. A partial backing/journal failure fences the service for explicit
host reconciliation. An ordinary capacity rejection occurs before mutation and
keeps the existing store usable. There is no automatic replay of an uncertain
write or silent version rollback.

## Reads, labels and export proposals

`read` checks current rights and allowed labels before accessing bytes. It
verifies the backing digest and byte length, then records the actual read
parented to its immutable write version. The returned `PrivateArtifactRead`
contains private text, the protected reader-local `InstructionOrigin`, read
event and, when available, an original source-flow lineage handle.

Text remains data even when it contains instructions or role claims. The body
and protected handles are omitted from the object's representation and public
metadata. The origin's `kind` is `repository_file`, not an operator instruction
source. A downstream host can correlate exact source bytes through the existing
Assurance source-flow APIs.

When historical lineage is unavailable, immutable labels survive and explicit
proof gaps remain. A read does not invent complete provenance or permission to
export. `prepare_export` additionally requires export rights, a configured sink
and exact proposed action parameter bytes, then uses `SwarmSourceFlow.assess`.
Sensitive unauthorized or incomplete exports are restricted.

Export preparation returns checked data to the protected host. It executes
nothing and grants no action permit. The actual host tool/network mediator must
still apply its existing action gate, approvals, current broker constraints and
forwarding checks; this API cannot downgrade a warning, escalation or denial.
Unwrapped reads followed by direct network access remain outside this boundary.

## Backing stores and adapters

`MemoryArtifactStore` is a bounded private KV fixture. `FilesystemArtifactStore`
stores content-addressed immutable blobs in an explicitly supplied empty private
directory. It requires POSIX no-follow and directory-relative descriptor support,
owned private directories/files, regular single-link blobs and exact digest
checks. A pinned directory descriptor prevents path replacement from redirecting
writes. Symlink, hardlink, FIFO and changed-content substitutions are rejected.
Partial writes are removed when possible and further access is fenced.

The filesystem adapter fails closed on Windows or unsupported platforms; the
memory backend remains available there. It does not weaken controls to an
unverified path check. Host-account access that bypasses the adapter is
explicitly `uncovered`. Private file permissions are not a sandbox for hostile
code sharing the host's account or memory. This store does not claim encrypted
storage or secure erasure of backups.

The maintained `ordin_swarm.artifact_gateway` exports the same SDK:

- `WorkspaceArtifactAdapter` manages logical versioned workspace keys, including
  the protected filesystem backend; it does not patch arbitrary file APIs.
- `SharedMemoryAdapter` provides the same guarded put/get/delete/export checks
  for bounded KV/shared-memory entries.
- `VectorPointArtifactAdapter` supports exact record operations through the
  guarded API. `GuardedVectorPointAPI` specifies the host-enforced provider
  contract. Opaque vector search, ranking and arbitrary native database access
  remain unsupported; their result text cannot assert that ACLs were applied.

A future external vector provider must enforce authenticated subject/tenant
scope, immutable content/version conditions and classification at its actual
host boundary, and pass conformance tests. Arbitrary introspection or a returned
JSON `enforced` flag is insufficient.

## Retention and evidence

TTL and per-resource version retention remove inaccessible old bytes through
reference-counted blob cleanup. Shared identical blobs are retained while any
version references them. Resource identities and monotonic version high-water
marks remain bounded tombstones; deletion and expiry do not reset them.
New identities are refused at capacity rather than evicting replay/version
history. Metadata is local to this protected coordinator; arbitrary directory
contents or JSON cannot restore authority after restart.

The current store is a single protected coordinator. Its local locks are not a
multi-host distributed transaction protocol. Diagnostics report that managed
API access is mediated, raw backing access is uncovered and physical
enforcement is false. Audit contains digests, operations, versions and labels,
without artifact text or raw filesystem errors.

Contracts:
[artifact metadata](../../schemas/swarm-artifact.v1.schema.json),
[diagnostics](../../schemas/swarm-artifact-diagnostics.v1.schema.json).
