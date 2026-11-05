# Transactional swarm budgets

`BudgetLedger` controls protected admission accounting across a tenant, swarm,
task and agent hierarchy. Each reservation is bound to an exact action, current
enrolled context, policy epoch and host operation key. It is not an execution
permit and cannot weaken an existing action/tool/Assurance decision.

## Host policy and quantities

Construct an immutable `BudgetPolicy` with bounded `BudgetLimit` entries.
Supported integer metrics are:

| Metric | Unit / meaning |
| --- | --- |
| `dollar_micros` | Millionths of a dollar; no floating-point currency arithmetic |
| `tokens` | Protected provider/adapter token maximum |
| `external_operations` | Protected maximum external operations |
| `child_spawns` / `processes` | Protected spawn/process maximum |
| `requests` / `tool_calls` | Protected request/tool-call accounting units |
| `concurrency` | In-flight units held until completed or reconciled |
| `output_bytes` | Protected output-byte maximum |
| `destructive_actions` | Protected destructive-action maximum |

Costs come from protected host policy and adapter semantics. Values supplied in
an action's JSON, such as `actual_cost` or `budget`, confer no accounting
authority. Requests and concurrency reserve at least one unit for a possible
forwarding call, even if a provider supplies zero. A host can supply a larger
conservative batch maximum.

Missing costs default to denial. An explicit `unknown_ceiling` permits a
conservative reservation up to an operator maximum, optionally restricted to
actual protected review effects through `unknown_effects`. Every matching
scope must permit that fallback. The largest applicable ceiling is charged to
all aggregate/ancestor buckets, so a narrower child selector cannot lower the
parent's reservation. Unknown fallback never means an uncharged fail-open.

These are admission bounds. A counter does not physically cap uncapped provider
billing, token generation, processes or bytes. The trusted connector/broker must
actually enforce any maximum used for a physical guarantee. Reports explicitly
state `physical_enforcement: false`. A policy with
`require_physical_enforcement=True` rejects admissions as unsupported through
this local ledger; an estimate, JSON flag or settlement observation cannot
upgrade it into an enforcing broker contract.

For a shared aggregate, configure tenant/swarm limits as operator maxima in
addition to narrower task/agent limits. A specific task/agent selector constrains
that protected logical identity. Wildcard task and agent limits charge each
distinct current ancestor task/agent as well as the requesting child. Siblings
therefore share their parent bucket, and restarting or renaming a child cannot
escape its protected parent limit. Buckets use stable logical scope keys, so
generation/epoch changes do not reset consumed expenditure.

`for_registry` creates a protected view for another registry under the same
live coordinator. Tenant limits aggregate across its swarms. It does not create
a separate coordinator, reset counters or authenticate a remote host.

## Reservation lifecycle

`reserve(context, action, channel=..., adapter=..., idempotency_key=..., costs=...)`
atomically checks every selected bucket and adds held quantities. It consumes
no expenditure. Identity, ancestry, costs, limits and epoch must be host-owned.
The returned original `BudgetTicket` cannot be reconstructed from JSON or a
copied identifier.

The host operation key identifies one logical attempt across retries. It is
tenant-scoped, including across registry/swarm views. The exact current context,
action and cost declaration remain bound to its record. A repeated reservation
returns the original local reserved handle only while that identical attempt
is still reserved. Conflicting, canceled, expired or previously forwarded keys
cannot issue another execution. Terminal keys are retained at the explicit
history capacity rather than evicted to make replay possible.
Live ticket bindings are published only after confirmed durable commit. A rolled
back reservation publishes no handle. If the commit succeeded but its ACK was
lost, its hold remains in history without an executable ticket; retry does not
mint a replacement authorization for that uncertain admission.

`begin_forward` rechecks the original ticket, exact action, current enrollment,
policy and TTL, then commits `forwarding` before any executor is called.
It is one-use. This follows the same reserve/consume separation as the existing
local delegated-operation quota; delegation limits remain an independent
restriction.

`cancel` and `expire` release only work that never began forwarding.
Forwarding, pending or uncertain effects never expire into free capacity.
`uncertain` retains the full reservation, including concurrency. A callback
failure is not proof that no external side effect occurred.

After a verified host callback completes, `commit` charges the reserved bound
and releases in-flight concurrency. Consumed accounting and observed expenditure
remain separate: without a protected settlement receipt, observed spend is
unknown. No claim of remote exactly-once effects follows from callback completion.

## Settlement, reconciliation and recovery

An explicit protected `BudgetObservationSource` issues original settlement
receipts for the reservation ID, action and context. Model text, caller
dictionaries and forged receipt objects cannot refund a hold.

The receipt covers every selected metric. A `no_effect` receipt attests zero
expenditure for every metric. `reconcile` additionally requires the original
operator capability. An uncertain attempt remains held until such evidence is
supplied. A completed callback's conservative charge can also be refined once
when its final authenticated settlement arrives later.

Settlement is idempotent, and conflicting later settlements are rejected.
An observed cost above the reserved maximum is charged rather than hidden,
reported as `overrun` and blocks that metric for the current policy epoch.
The host must correct its bound/enforcement configuration and explicitly advance
policy before admitting new work. A counter cannot undo an already incurred
external overrun.

`InMemoryBudgetStore` is a stable bounded test backend. `SQLiteBudgetStore`
uses the shared private-database checks, a distinct application identifier,
durable synchronization, foreign keys and `BEGIN IMMEDIATE` transactions.
Counters and reservation transitions commit together. It is a local
single-coordinator persistence adapter, not an eventually consistent cache or
multi-host consensus service.

Initialize a new accounting domain explicitly:

```python
store = SQLiteBudgetStore(private_directory / "budgets.sqlite", create=True)
```

Open existing history after restart without the creation flag:

```python
store = SQLiteBudgetStore(private_directory / "budgets.sqlite")
```

Missing, replaced, corrupt or uninitialized existing files fail closed. An
ordinary reopen never silently starts a zero-spend store. Do not restore an old
backup as current accounting authority; external storage rollback and distributed
partition fencing require an independently trusted coordinator/checkpoint.
Schema creation occurs once for an explicitly new store. Active transactions and
reopens validate the required table/index definitions and coordinator history;
missing or changed schema is rejected without recreating empty counter tables.

A new `BudgetLedger` over the existing store fences every older coordinator
generation. Old reserved work is safely canceled because its fenced ticket
cannot begin forwarding. Old forwarding work becomes uncertain and retains its
hold. A callback already in flight cannot be undone; late operator reconciliation
must use its exact original scope. An older coordinator cannot cancel or forward
after fencing.

## Gateway integration

Configure `SwarmToolGateway(budget_ledger=ledger)` with the same protected
registry view as the gate. The default costs count requests and concurrency.
An optional `budget_cost_provider(context, action, decision)` returns immutable
`BudgetCost` values from host policy/verified adapter bounds.

For each budgeted proposal, pass a protected
`budget_idempotency_key` to `gateway.prepare`. The gateway still generates
its own action ID; model-supplied action IDs do not establish retry identity.
Missing keys deny admission. Reusing the logical operation key after lost
acknowledgement cannot produce a fresh executor call.

Reservations happen only after the baseline decision is executable. Blocked,
unmediated and unsupported-approval proposals do not consume or reserve budget.
A budget denial returns no forwarding ticket and includes a bounded budget
reason code. The authorization exposes the exact reservation ID for audit.

Immediately before the host executor, the gateway calls `begin_forward`.
Completed callbacks commit conservatively; failed, pending or exception outcomes
retain uncertain holds. Stale/expired pre-forward attempts and explicit
`gateway.cancel` release safe reservations. Revocation fences pending gateway
tickets even if accounting cleanup fails. Core warnings, approvals and denials
retain their existing behavior.

`report` returns hashed bucket identifiers and remaining/reserved/consumed/
observed quantities without tenant-private resource names or credentials.
`reservation_status` binds an audit result to the original action reservation.
`audit` is bounded and paginated behind the protected operator capability.
All reports deny execution authority.

The APIs are also available from `ordin_swarm.budget_store`. Importing them
opens no database, transport or background worker. The host protects the store,
operator capability, observation source, cost provider and issued handles from
agent control; this is not an isolation boundary against hostile code sharing
that host memory.

Contracts:
[budget](../../schemas/swarm-budget.v1.schema.json),
[reservation](../../schemas/swarm-budget-reservation.v1.schema.json),
[audit](../../schemas/swarm-budget-audit.v1.schema.json).
