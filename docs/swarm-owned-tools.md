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

`OwnedHTTPRoute` currently validates an operator-selected exact GET route,
explicit pinned IPs and private credential configuration. HTTP execution is
delivered separately; this write checkpoint explicitly refuses request-domain
execution. It does not project a full HTTP request into TCP permission.

`tests/swarm_owned_tools_samples.py::configured` supplies original TLS-enrolled
actors, read/write delegation rights, core semantics, backend, broker, source
contexts and a write-action helper for native governance integration. It grants
no approval. Native tests must verify actual writes and negative kernel controls;
portable parser/profile tests alone do not establish physical enforcement.
