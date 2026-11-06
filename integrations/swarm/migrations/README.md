# Coordinator migrations

The packaged reference is
[`0001-coordinator.sql`](../ordin_swarm/migrations/0001-coordinator.sql).
`ordin.swarm.coordinator_store.TABLES` is its runtime source of truth; tests
check the exact initial DDL and manifest. Use the protected store constructor,
which initializes schema, database identity and root checksum in one transaction.
Executing the DDL alone creates no usable authority.

Initialization requires a genuinely absent namespace/file and explicit
`create=True`. Reopen with `create=False`. Missing initialized history, changed
constraints, unknown versions or partial initialization fail closed. This release
has one initial migration; no implicit upgrade, blank-state repair or destructive
rollback is attempted. Take protected backups and fence/reconcile live hosts before
any operator-managed database restore or future schema upgrade.
