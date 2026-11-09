# Private managed MCP tool host

`ordin-swarm-host` runs one shared Linux tool service for separately authenticated
actors. It exposes MCP stdio through a client bridge and uses loopback mutual
TLS between the bridge and daemon. Tool calls share the existing Ordin native
delegation, coordinator, durable budgets, human governance and owned workers.
No model provider is required.
The daemon declares its original backend's required effective UID before sealing
the assurance/session configuration. Caller JSON cannot select this deployment
requirement. It grants no identity or permission; the original native outcome
must still establish the actual worker and effect.

The synchronous shared host serializes authentication and authority phases,
including owned jobs. Queued requests are checked against fresh original clock,
role and lease state when admitted; waiting never renews an approval or other
deadline. Periodic maintenance/checkpoint work skips a busy phase. Original
job, RPC and lease bounds remain in force, so a long job can cause a queued RPC
or expired proposal to fail. Remote shutdown retains normal fresh authentication;
local signals and the original operator capability still fence admission and
request stops without waiting for that phase. Cleanup retains storage and TLS
custody until the phase leaves and original children have actually stopped.

This service controls its own tools. A normal MCP client can still have other
tools, sockets and credentials. Its process is outside this boundary unless an
explicit supported protected launch establishes confinement. Loading a profile
or reviewing a core action starts no daemon, issues no approval and opens no
agent transport.

## Explicit initialization

Use a supported Linux x86-64 host with the required Landlock/seccomp facilities,
the installed `ordin-swarm` package and an explicitly selected trusted OpenSSL
executable (`/usr/bin/openssl` by default). Initialization refuses an existing
installation. Failed partial installations remain private for inspection.

Select the complete profile before running initialization. This minimal profile
gives `reader` one source document and a one-way handoff to `writer`; only
`writer` may propose creating the report:

```json
{
  "schema_version": "ordin.swarm_tool_host_profile.v1",
  "profile_id": "documents", "tenant_id": "local",
  "swarm_id": "reports", "task_id": "report",
  "workspace": "/home/operator/ordin-task/workspace",
  "files": [
    {"name": "document.txt", "label": "private_code"},
    {"name": "report.txt", "label": "secret"}
  ],
  "actors": [
    {"agent_id": "reader", "read_files": ["document.txt"], "write_files": [], "http_routes": [], "peers": ["writer"]},
    {"agent_id": "writer", "read_files": [], "write_files": ["report.txt"], "http_routes": [], "peers": []}
  ],
  "http_routes": [],
  "limits": {"requests": 128, "output_bytes": 1048576, "concurrency": 2, "lifetime_seconds": 600}
}
```

```console
ordin-swarm-host init --directory /home/operator/ordin-task --profile /home/operator/profile.json --input document.txt=/home/operator/source.txt
ordin-swarm-host doctor --directory /home/operator/ordin-task
ordin-swarm-host serve --directory /home/operator/ordin-task --port 9443 --policy-epoch 0 --initialize-scope
```

Every readable managed file needs an explicit UTF-8 seed. Source files are
copied; their ownership and permissions stay intact. Only the newly created
dedicated workspace and copied managed files receive the closed worker's UID
and GID. Configuration, PKI, durable databases and fresh worker installations
remain operator-owned. Root execution uses the worker's unprivileged identity.
An existing user workspace is never adopted or chowned.

Initialization generates fresh private keys rather than using test keys or
installing a machine trust root. The private tree contains a separate
`pki/PRINCIPAL/cert.pem` and `key.pem` for each role. Keep the installation and
each exported client bundle private. An actor bundle grants that actor's
transport identity; it is not a general execution credential.

## Connect a client

After the daemon publishes its role bundles, write a new private client config:

```console
ordin-swarm-host client-config --directory /home/operator/ordin-task --actor reader --output /home/operator/reader-mcp.json
ordin-swarm-host doctor --directory /home/operator/ordin-task --live --actor reader
```

The generated `mcpServers` entry invokes the installed Python module's
`connect --client-directory ...` bridge. It contains paths, not private key
contents. Point the chosen MCP client at that entry. The daemon chooses the
actor from the actual authenticated certificate; actor names or labels in tool
JSON cannot change membership. Connections and frames are finite, and the host
retains at most 4,096 protocol IDs over its lifetime. It never evicts replay
history to make a used ID reusable.

`tools/list` advertises only the actor's allowed tools. `read_file` returns
UTF-8 data and an original retained resource reference. Its digest names the
actual returned bytes; a separate version check reports `version_match` and
only supplies a usable `version` when the protected current snapshot matches.
Write-only actors have no read or content-hash lookup. `handoff` accepts only an
original resource reference and a configured peer; labels follow the original
bytes through the existing source-flow/message gateway. Received content is
data and confers no execution authority.

## Review a proposed write

`write_artifact` takes the managed name, exact UTF-8 content, `expected_version`
and `expected_digest`. Version zero with a null digest is create-only. An update
requires the exact current version and digest. Managed writes retain the core
warning and require the real operator queue; profile permissions never approve
the body automatically.

```console
ordin-swarm-host operator --directory /home/operator/ordin-task queue
ordin-swarm-host operator --directory /home/operator/ordin-task show --request-ref REQUEST
ordin-swarm-host operator --directory /home/operator/ordin-task show --request-ref REQUEST --include-content --preview /home/operator/proposal.json
```

The default view contains identities, target, version and content commitment.
It also displays the original `expires_at`. Review **and fulfill before that
deadline**: it is bounded by the original workload lease (at most 30 seconds),
not the task's 600-second lifetime. Expiration requires a fresh proposal and
fresh review; an approval never migrates to or extends a renewed lease.
Use the opt-in preview to inspect the exact retained content in a **new private
0600 file**. Content is never printed to ordinary command output. After review,
use the `expected_binding` from that exact view:

```console
ordin-swarm-host operator --directory /home/operator/ordin-task approve --request-ref REQUEST --expected-binding BINDING --idempotency-key REVIEW
ordin-swarm-host operator --directory /home/operator/ordin-task fulfill --request-ref REQUEST --expected-binding BINDING
```

`deny` uses the same explicit reference/binding/key arguments. Fulfillment uses
the retained original action, workload channel, lease, approval receipt and
verified broker outcome. An expired or disconnected request cannot migrate to
a fresh caller. Reservations cover queued output custody before approval;
unknown effects retain uncertain holds. A missing reply is not permission to
replay an action.
Denied or uncertain operator outcomes return a nonzero command status,
including an outer acknowledgement whose actual fulfillment is unknown. A
successful explicit `deny` resolution returns zero. Ordinary fulfillment output
omits tool bodies and test diagnostics; use `fulfill ... --private-result
/absolute/new-receipt.json` to opt into a private 0600 full receipt. This does
not change the command's success/failure status or retry the effect.

## Stop and restart

```console
ordin-swarm-host operator --directory /home/operator/ordin-task stop
ordin-swarm-host serve --directory /home/operator/ordin-task --port 9443 --policy-epoch 1 --takeover
```

Stopping closes admission and requests stopping original active jobs; it cannot
undo effects already started. A final acknowledgement can race transport close.
If an original child or client cannot close, the host keeps its original cleanup
handles and installation lock and remains fenced. An embedding caller of
`host_cli.main` receives the original private cleanup exception and must retain
it for `retry_cleanup()`. The actual console/module entry point instead remains
in the foreground supervising **cleanup only** until it succeeds; Ctrl-C and
SIGTERM do not silently abandon that cleanup. It then exits nonzero for the
original failed command. Fixed messages omit private causes and contents. No
tool action is replayed, and prior unknown outcomes/holds remain unknown/held.
SIGINT/SIGTERM also stop the foreground daemon, including when protocol capacity
has been exhausted. Restart requires the same intact databases and scopes plus
an explicit fresh monotonic policy epoch. Old handles, votes and approvals are
not restored from JSON. Spent and uncertain budgets are preserved rather than
reset by the new epoch. Do not delete or rename databases to regain capacity.

The task lifetime is finite (at most 600 seconds for the delegated host task).
Maintenance heartbeats current original scopes and checkpoints online ownership;
it does not extend a human request or delegated grant. Every start uses a new
bounded private worker installation. After 64 installations, operator maintenance
is required; existing nonempty worker installations are never silently reused.

## Explicit fixed tests

Preinstall the optional, qualified pytest runtime explicitly. From the matching
repository root, install both packages from that same checkout:

```console
python -m pip install . "./integrations/swarm[test-runtime]"
```

The `test-runtime` extra pins `pytest==9.2.0`; it does not add a dependency to
core Ordin. Initialization never installs packages. Missing runtime
distributions produce a sanitized nonzero result with this installation action.
Any partial private installation remains for inspection; use a new installation
directory after preinstallation instead of overwriting it.

A profile may additionally select `test_routes` such as
`[{"test_id":"report","selectors":["test_report.py::test_report"]}]`,
`test_runtime: "state/test-runtime"` and an actor's `test_ids: ["report"]`.
The selected Python file must be in the managed file inventory and explicitly
seeded at initialization. Add `--with-tests --input test_report.py=/absolute/test_report.py`
to the **new-install** init command. This stages a curated copy of the already
installed trusted Python/pytest runtime; it downloads nothing and executes no
`.pth` files or discovered plugins. Restart revalidates the original private
catalogue pin, actual tree and base interpreter; it never rebuilds an old pin.

`run_tests` accepts only `{"test_id":"report"}`. A test route grants access to
a read-only sealed snapshot of the **whole dedicated managed workspace**;
it is broader than a single `read_file` name. Configure the actor accordingly.
The host checks that exact actor/test pair before preparing the snapshot, then
passes the same protected snapshot commitment through core review, the human
queue and owned execution. Client paths, selectors, argv, runtime roots and
snapshot references are not accepted. A later changed project cannot replace
the approved snapshot.

The operator view includes the fixed selectors, snapshot commitment and trusted
runtime identity. The existing code-execution warning still requires exact
operator approval. Returned diagnostics carry `output_trust:
"untrusted_test_diagnostic"`, conservative sensitivity labels and
`test_correctness_verified: false`. A zero exit code says that this fixed test
process exited successfully; it does not prove code correctness or make its
output instructions authoritative. Kernel confinement is required for this
route; unsupported hosts cannot fall back to a normal host pytest process.

## Fixed offline workflow evaluation

```console
ordin-swarm-host evaluate --directory /home/operator/new-evaluation --output /home/operator/evaluation.json
ordin-swarm-host evaluate --directory /home/operator/new-protected-evaluation --output /home/operator/protected-evaluation.json --with-tests --protected-agent
```

This explicitly creates a new private installation, an owned exact loopback
public-reference endpoint, two TLS actors and a separate scripted operator.
It exercises private read, original handoff, public fetch, exact queued review
and a managed report write. Negative cases include actor substitution, traversal,
caller URLs/labels, forged resources, write-only reads, unapproved writes and
stale compare-and-swap. The aggregate records observed completions, false blocks,
false allows and local latency, and exits unsuccessfully when a case fails.
The optional enhanced fixture also stages/reloads the pinned test catalogue,
reviews and executes the sealed test snapshot, then runs a fresh confined Python
agent through the same host's private MCP route. That fixture verifies its
original kernel outcome and independently checks the retained managed report;
it never substitutes a normal subprocess when confinement is unavailable.
Its dedicated protected fixture result does not promote the other TLS clients
into confined processes. Incomplete runs report `complete: false`; unexecuted
attacks are not counted as either stopped attacks or false allows.
The aggregate contains no fixture contents or keys.
The source includes a concrete malicious tool/actor/URL directive. Its exact
bytes survive the handoff as data; scripted attempts to follow that directive
cannot self-approve a replacement report or select an arbitrary endpoint.
The fixture verifies source/report bytes and attempts admission through both
the original transport and opaque binding after authenticated shutdown.
These finite scripted policy cases do not measure model effectiveness, universal taint tracking or arbitrary
client-process containment.
