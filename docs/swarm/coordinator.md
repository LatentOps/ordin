# Optional durable coordinator

`SwarmCoordinator` is an explicitly configured online authority for authenticated
hosts. Ordinary Ordin review remains dependency-free and works offline. Importing
`ordin.swarm`, `ordin_swarm.coordinator` or either store starts no service and does
not import psycopg. Install the optional driver with
`pip install './integrations/swarm[postgres]'` when using PostgreSQL.

## Authority and deployment

Use `PostgresCoordinatorStore` for multi-host accounting. It serializes all
authority transactions with an actual PostgreSQL row lock, then reads the latest
committed state. A single protected coordinator can serve multiple independent
mTLS hosts. This is one linearizable database authority, with bounded capacity;
it is not an active-active consensus protocol or a local-lock replication scheme.
The tradeoff is serialized admission throughput across its configured scopes.
See PostgreSQL's [row-lock contract](https://www.postgresql.org/docs/current/explicit-locking.html).

`SQLiteCoordinatorStore` is a private single-host/dev authority. Do not place its
file on a network share or describe two processes sharing it as multi-host HA.
Both adapters require explicit initialization, retain a random database identity
and schema manifest, check history integrity, and reject missing/changed state.
They never recreate an absent initialized table or scope as empty accounting.
Initial schema migration is transactional. Unsupported schema versions fail
closed; no automatic destructive upgrade or reset is provided.

The database, coordinator operator, native issuers, TLS keys, storage gateways,
brokers and collectors belong to the trusted host. Give the database role its own
protected namespace, restrict its credentials to this service, and keep agent
roles out of SQL and schema ownership. Network connections require verified TLS;
private local Unix sockets are supported for owned fixtures. The store requires
durable PostgreSQL settings (`fsync`, full page writes and synchronous commits).
It does not attest a provider's storage/HA deployment. Coherent backup rollback by
a database administrator is outside the integrity checksum boundary: fence hosts
and reconcile before restoring an older database. Never resume old offline leases.

Construct one original `CoordinatorClock(store)` **before** enrolling a registry,
issuer, workload authenticator, temporal engine and policy runtime. Pass that same
clock object to each. It reads database epoch seconds; leases use precise database
time. Client timestamps and clocks do not decide expiry or temporal admission.
The service rejects clock rollback. Collection starts at actual enrollment and
never invents complete pre-attach history.

```python
from ordin.swarm import (
    CoordinatorClock, PostgresCoordinatorStore, SwarmCoordinator,
    CoordinatorEndpoint,
)

store = PostgresCoordinatorStore(protected_dsn, schema="ordin_swarm", create=True)
clock = CoordinatorClock(store)
# Build/enroll the original registry, issuer, mTLS authenticator, native service,
# current policy runtime and real broker using this original clock and operator.
coordinator = SwarmCoordinator(store, operator=operator, clock=clock)
control = coordinator.control_source(operator=operator)
scope = coordinator.register_scope(
    native_service, approved_budget, control=control,
    broker_channels=(broker_channel,), brokers=((host_id, broker),),
    runtime=policy_runtime,
)
coordinator.initialize_scope(scope, control=control)  # new scope only
coordinator.budget_view(scope, control=control)  # bind shared counters into facts
coordinator.start(scope, control=control)
endpoint = CoordinatorEndpoint(coordinator, scope)
```

Reopening uses `create=False`, retaining the exact database identity. Each native
authenticator serves one tenant/swarm/task. A listener pins its original scope;
JSON cannot choose another tenant, role, task, source or control capability.
Multiple task scopes share the applicable tenant/swarm budget buckets. Ancestry
across task scopes requires an explicit protected bridge; missing history stays
unknown. Root/control sources never travel on the client data protocol.

## Authenticated state machine

The TLS server must retain the original CA-verifying `SSLContext`, authenticate
actual server-side sockets, and pin workload/broker certificates with the
operator. `CoordinatorEndpoint.serve_one(socket)` handles one bounded frame on
that socket; call `close_connection(socket)` on EOF/disconnect. A verified
`CoordinatorClient` checks the server hostname and never reconnects or retries an
ambiguous call automatically. Frames are limited to 64 KiB, JSON depth to 32 and
each exchange to ten seconds. Duplicate keys and unknown operation fields fail.

| API | Required live authority | Result |
| --- | --- | --- |
| `admit` / `renew` | Verified current workload channel | Short database lease bound to actor, certificate, host, policy and owner fence |
| `bind_grant` | Same workload and original live native grant | Historical grant metadata and ancestor chain; no restored native grant |
| `policy`, `producer`, `status`, `budget` | Same workload and current lease | Scoped data-only snapshot |
| `evaluate` | Current lease and native grant | Non-authorizing baseline preview, exact action digest and expiring reference |
| `reserve` | Same exact evaluation/action/channel and fresh policy | Atomic shared quota holds plus original native/broker preparation |
| `cancel` | Owning workload, unused reservation | Release only a proven never-forwarded hold |
| `event` | Current workload and assigned original producer | Ordered redacted causal metadata; caller/backend claims remain distinct |
| `forward`, `commit`, `uncertain`, `dispatch` | Verified matching broker host | Current online transition; JSON never supplies an executor |
| Operator fence/checkpoint/recovery | Original server-only control source | Durable intents and explicit reconciliation, never a wire permission |

`reserve` never weakens baseline/Assurance/delegation or current declarative
policy. Its protected `CoordinatorBudgetView` adds shared database counters to
runtime fact freshness. It retains the broker's original local ledger and hard
executor limits. All required active budget limits must remain represented with
equal or stricter maxima. Known costs come from deterministic semantics or the
actual configured broker's bounded executor plan. Unknown billing/token costs
require an approved finite ceiling; caller estimates cannot reset a hard quota.
The coordinator reports admission accounting, not physical billing containment.
The accounting window begins with explicit coordinator initialization. It cannot
certify earlier unmediated spend. Retain existing native accounting and treat
unavailable earlier charge history as unknown; JSON imports never create credit
or prove that an earlier budget was unused.

The order is: evaluate → reserve → **commit durable forwarding** → call the
original broker once → record the authenticated host result. The database lock is
released before the external effect. The broker owns native ticket consumption
and its local ledger forwarding; the coordinator never consumes either twice.
`dispatch` on the wire uses only a real configured broker. The host-only native
mediator path accepts a protected application callback and reports mediation;
callbacks cannot be supplied through JSON or borrow physical/policy evidence.

## Durable history, storage and recovery

Scope state stores policy epoch/selection, owner fence, revoked subjects/grants,
reservation phases and shared charges. An append-only hash-chained outbox and
materialized checkpoints are committed with transitions. Workload events retain
assigned source/sequence, redacted parent/action/resource digests and database
admission time. Event IDs, prompt/action bodies, credentials and client timestamps
are not persisted. Out-of-order events have a bounded receive window; missing
sequences/parents block sensitive admission until validated backfill resolves
them. Cycles, conflicting sequence reuse and foreign review anchors are rejected
before publishing a graph mutation. Workloads cannot assert backend observations.

`checkpoint(scope, control=control)` validates the journal and records graph
metadata, protected artifact version/classification/tombstone floors and protected
temporal facts/coverage as **historical-only** data. `history` verifies its digest.
Use `artifact_write` / `artifact_delete` for durable managed mutations: an intent
commits before the original gateway effect, then its metadata floor commits.
A partial backing failure retains an unknown intent. A known validation denial
can clear only an unchanged, healthy original gateway's no-effect intent.
Raw backing access and gateway writes outside this wrapper are unmediated paths.
A blank/rolled-back gateway cannot erase stored labels or resurrect a tombstone.

On owner restart/takeover, fences advance, old leases/evaluations expire and live
grants require revalidation. Unused preparations are canceled; forwarding becomes
uncertain and retains quota holds. Checkpoints cannot recreate original lineage,
grants, authorization objects or sealed runtime receipts. Missing live artifact
or temporal state requires reconciliation; stored JSON is never promoted back to
complete protected evidence. `prehistory` remains `unknown` after replay.

`record_fence` supports action/agent/subtree/task/swarm/tenant scopes. It publishes
a monotonic revocation intent before backend notification, cancels unused holds,
and preserves uncertainty for in-flight effects. Task/swarm/tenant barriers also
block newly enrolled subjects. This logical fence does not claim atomic kernel
revocation. A protected controller may be bound with `bind_recovery_verifier`.
`reconcile_fence` accepts only original issued fence/resume objects, requires a
fresh owner fence or policy epoch, calls the controller outside database/control
locks, then rechecks exact scope/epoch/owner and all group members before commit.
Revoked grants remain revoked and workloads need fresh admission. Unknown effects
are never refunded by a resume acknowledgement.

For an incident that caught forwarding in progress, first call
`reconcile_broker_outcome(scope, reservation_id, original_receipt,
control=control, revocation_epoch=epoch)`. It derives the original bound broker
authorization, verifies an original completed/canceled control or result receipt
outside database locks, and records that known outcome under the exact current
incident. It changes no held/consumed counters. In-process takeover may retain
original objects for this historical verification only. A process restart cannot
restore them from JSON. Resume rejects affected uncertain/forwarding reservations
without a verified current-incident outcome, even when a caller supplies a true
boolean or a controller tries to approve an unknown effect.

## Failures and limits

| Failure | Admission/forwarding behavior |
| --- | --- |
| Database/coordinator partition or lost acknowledgement | Deny new forwarding; return unknown when the effect/commit may have occurred; never automatically replay an effect |
| Expired workload/owner lease, certificate revocation, stale ancestor/grant/policy | Deny and require current protected enrollment/authorization |
| Competing coordinator owners | DB fence and short owner lease select one; old owner cannot forward after takeover |
| Clock skew/rollback | Use database time; backward authority time is unavailable |
| Event gap, slow collector or excessive projection lag | Unknown/incomplete and deny actions requiring current history |
| Corrupt/missing schema, budget, journal or checkpoint history | Fail closed; never initialize empty replacement state |
| History capacity | Bound and stop admission; an operator must archive/reconcile deliberately rather than silently dropping revocation or charge history |

Default limits are 64 scopes, 4,096 durable transition records and 2,048 ingested
events per scope (configurable within finite maxima), an 8 MiB scope projection,
10-second workload leases and a 30-second owner lease. Checkpoint regularly before
the configured journal-lag limit. No offline execution lease is issued. Status
reports `unmediated_execution=uncovered` and `physical_enforcement=false`; concrete
broker/runtime evidence remains separate and covers only its tested route.

Run `python scripts/check_swarm_coordinator_postgres.py` with optional driver and
PostgreSQL binaries installed. It creates a unique private local cluster, runs
real mTLS/two-host, process/crash, partition and broker tests, and stops only that
owned cluster. The dedicated CI job installs hash-locked optional dependencies.
