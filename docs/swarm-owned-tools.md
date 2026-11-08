# Managed owned tools

`LinuxOwnedToolsBackend` is a closed Linux x86-64 executor for exact reads and
bounded atomic UTF-8 artifact writes. It is an opt-in execution integration;
ordinary review APIs still have no execution side effects. Existing
`LinuxFileReadBackend` integrations retain their original behavior.

The operator creates a **new dedicated workspace** below a private operator-owned
directory. The workspace is mode `0700` and its explicitly copied flat input
files are mode `0600`, regular, singly linked, and owned by the worker UID/GID.
`LinuxOwnedToolsBackend.worker_identity()` returns the required identity: the
current UID/GID when non-root, or `65534:65534` when root. A root launcher may
chown only the newly created workspace and newly copied files after checking
their original identities. The backend never chowns supplied paths. Existing
user repositories and arbitrary host paths are outside this executor.

The installation directory must be fresh, private, operator-owned and outside
Git worktrees. Worker code, interpreter, workspace identity and configuration
are pinned and rechecked. `initialize=True` creates durable managed-file history
once. A subsequent backend uses `initialize=False` and a fresh installation
directory; missing, changed or unresolved history fails closed. Reinitializing
existing history is refused. Persisted file metadata does not restore an
authorization, approval, data lineage or sensitivity label.

The read action is `read_file({path})` in the configured tool runtime. Write
arguments are exactly:

```json
{"path":"/managed/report.txt","content":"bounded UTF-8 text","expected_version":0,"expected_digest":null}
```

Only configured canonical flat destinations are accepted. Version zero and a
null digest mean create-only. Replacing an existing artifact requires both its
positive current version and exact SHA-256 digest. The protected operator can
obtain metadata with `snapshot(path, operator=operator)`. This returns version,
digest and byte count; it grants no execution permission. Content is bounded
before hashing; both character and UTF-8 byte bounds apply (maximum 64 KiB).

Normal writes retain core `warn` / medium risk and require protected human
approval for the exact action and original owned job. Configuring a write route
does not approve it. Broker policy, delegation, currentness, budget reservation,
approval lease and use-time fencing continue to apply. The factory's fresh
temporary write is an explicit protected-owner installation self-test, never an
approval for a workload or user-data action. JSON reports and copied receipts
cannot become execution authority.

Each write uses a fresh immutable worker, Landlock, a closed seccomp profile,
non-root identity and hard memory/CPU/process/descriptor/file/output bounds.
Landlock allows the **managed directory**, because atomic publication needs
directory operations. The immutable worker and seccomp checks bind the one
exact flat target, exclusive staging file, content digest and CAS condition.
This is not a kernel exact-file claim or a general host/agent sandbox. Raw host
access and other processes running outside this owned route remain uncovered.

The worker writes and verifies a new exclusive file, fsyncs it, then publishes
with `renameat2`: no-replace for creation, exchange for replacement. Exchange
keeps the displaced file until its original identity is verified. Symlinks,
hard links, changed file identities and stale versions refuse. The parent
retains original child/job custody and verifies the kernel receipt and final
identity before recording a successful next version. Durable intent is committed
before effects. Cancellation, lost worker/commit acknowledgments or a racing
destination can leave an uncertain effect; the history then blocks subsequent
operations pending operator reconciliation. No automatic retry or fallback can
overwrite that uncertainty. Unsupported kernels return non-success.

An unknown result retains the original child/job custody when termination is
unconfirmed. `request_stop(original_job, operator=operator)` retries only that
original process, using its retained descriptor when available. Later successful
cleanup leaves the original unknown outcome and uncertain holds unchanged.
`close()` fences new work before stopping existing jobs and checks again after
acquiring the execution lock. If cleanup remains unconfirmed it raises while
retaining process and storage ownership; the protected owner must retry close.

`OwnedHTTPRoute` selects one exact HTTP(S) GET URL and literal application
headers, explicit pinned IP addresses, a response byte limit, and optional
protected CA material. Query and request-body bounds are zero in this initial
route. An unconfigured URL, method, header, query or body refuses. The backend
retains the entire original `RestRequestContract` in a closed `OwnedRequestPlan`;
the original capability retains its explicit REST commitment requirement. It is
never turned into a TCP grant or a generic enforceable capability plan. Only a
core-allow request with that one fully accounted REST requirement is supported;
other uncertainty and warning/approval cases refuse.

The trusted parent connects to the first exact configured IP with no DNS,
automatic failover, proxy environment, redirects, cookies or ambient credentials.
The fresh worker receives only that preconnected socket and private control/output
descriptors, then installs Landlock/seccomp/UID/resource controls before TLS
handshake or HTTP bytes. Its kernel network scope is that preconnected socket;
the host parent software binds the selected destination and the worker checks
the actual peer. This is not a host-wide network firewall. HTTPS verifies the
hostname and pinned CA set with TLS 1.2 or newer. Default trust uses compiled-in
system CA locations rather than SSL_CERT_FILE/DIR environment overrides. Plain
HTTP and private IPs need separate explicit operator opt-ins; link-local,
unspecified, multicast and unsupported reserved destinations always refuse.

Requests use exact bounded GET/Host/Connection-close/Accept-Encoding-identity
framing. Application headers cannot replace transport framing or Authorization.
Response headers have an 8 KiB limit, are ASCII, and cannot contain duplicates,
folding, chunking or content encodings. Interim responses and redirects refuse.
Bodies have a route-specific hard limit with at most one overflow-probe byte.
TLS responses require Content-Length (or the known empty 204 form). Slow,
ambiguous, oversized or incomplete responses return non-success with no retry.
When HTTP routes are configured, factory readiness also retains an original
confined HTTP outcome from a one-shot operator-owned loopback endpoint. It never
contacts configured external endpoints or uses their credentials. Strict TLS
and destination/credential checks are verified again at the actual use.

Credentialed routes accept only protected destination-bound bearer bytes and
retain the same original `HostCredentialUse` through review and use-time checks.
Copied/wrong-source/wrong-destination proofs refuse. The exact action is consumed
before any connection effect; uncertain or repeated calls cannot mint another
proof for it. A keyed wire tag binds Authorization without publishing an
offline-checkable digest of its secret bytes. No endpoint-controlled response
body, headers, status or hash is exposed for credentialed calls: after a valid
bounded response the caller receives only
`{"completed":true,"credentialed":true}`. Credentialless routes return the
bounded body. This does not promise zero covert or timing channels; endpoint
trust and the private credential boundary remain explicit.

`tests/swarm_owned_tools_samples.py::configured` supplies original TLS-enrolled
actors, read/write delegation rights, core semantics, backend, broker, source
contexts and a write-action helper for native governance integration. It grants
no approval. Native tests must verify actual writes and negative kernel controls;
portable parser/profile tests alone do not establish physical enforcement.

`test_routes=(TestRoute(...),)` adds the concrete `LinuxConfinedTestRunner`,
constructed inside the aggregate's fresh installation. The constructor accepts
only the exact typed route catalog; it accepts no caller runner or callback.
Each route pins an operator-selected project root, fixed pytest selectors and a
curated `PythonRuntimeCatalog`. The separate trusted catalog builder copies only
the supported Python/pytest runtime inputs; it does not mount a user's full
environment. Test routes require the qualified privileged Linux namespace,
read-only mount, Landlock, seccomp and bounded tmpfs profile. Missing controls
return non-success with no weaker executor.

The public call is `run_tests({test_id})`. Before core or human review, protected
host code calls `prepare_action(action, operator=operator)`. This seals the
bounded project snapshot and puts its original reference and digest outside the
public arguments. Rechecks use that same snapshot; they never silently capture
new bytes. Source, sealed copy, runtime, interpreter and complete declared
filesystem/process requirements are checked again before the owned effect.
Project capture has a 16 MiB / 2048-file ceiling, runtime capture 192 MiB / 4096
files, and the aggregate retains at most sixteen test jobs/snapshots. Original
snapshot references cannot reconstruct missing process or execution authority.

The exact host conditional runtime declaration is required: read-prefix rights
for project and curated runtime, the one pinned interpreter, and
`spawn_children=False`. Core `code.execute` remains warn/medium and needs the
real protected human approval lease. The aggregate validates that lease against
its original aggregate job before forwarding the same original lower runner
plan/job. It verifies the retained lower outcome before creating its own result.
Factory setup executes only a newly created trusted test fixture, never a
configured project's tests or an implicit approval of a workload.

Default test limits are 30 seconds wall time, 10 CPU seconds, 512 MiB address
space, 4 MiB scratch and 128 scratch inodes. A supplied exact
`ProtectedProcessLimits` can make other supported finite choices; raw diagnostic
output cannot exceed the aggregate payload budget. The worker's trusted
readiness handshake is retained before untrusted code runs, and the original
owned child exit/stop is observed externally. Output and pytest counts remain
untrusted diagnostics. The result contains externally measured `exit_code`,
bounded `output`, `output_truncated`, `snapshot_digest`,
`output_trust="untrusted_test_diagnostic"` and
`test_correctness_verified=false`. Exit zero does not prove test correctness.
The final JSON byte bound applies even when escaping expands the diagnostic.
