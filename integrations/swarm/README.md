# Optional swarm host adapters

Install this package alongside Ordin 0.4 development to import
ordin_swarm.SwarmMCPAdapter and ordin_swarm.SwarmHookAdapter. Both reexport the
same tested core host adapters; they do not start services or discover clients.

See [tool gateway documentation](../../docs/swarm/gateway.md). Keep enrollment,
source handles and executor/transport callbacks in the trusted host. Calls routed
around the adapter remain uncovered. No framework planner is replaced and no
model, hosted collector or extra system dependency is installed.

The optional [human governance integration](../../docs/swarm/approval.md) exports
the original TLS/RBAC directory, durable approval service and host-injected
operator CLI session from `ordin_swarm.approval_service`. Configure it explicitly
before sealing the native assurance gate. JSON reports never restore approval.

The [private operations integration](../../docs/swarm/operations.md) exposes
original audit sources and the authenticated operator API from
`ordin_swarm.operator_api`. CLI diagnostics and the static dashboard remain
local. `ordin-swarm[telemetry]` enables explicitly requested OpenTelemetry SDK
exports; no network exporter is configured by default.
