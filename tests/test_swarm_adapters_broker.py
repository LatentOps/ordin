"""SDK/coordinator/broker composition obtains the original actual kernel result."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integrations/swarm"))
from ordin_swarm.sdk import SwarmSDK
from ordin.swarm.budgets import BudgetPolicy
from ordin.swarm.coordinator import SwarmCoordinator
from ordin.swarm.coordinator_store import CoordinatorClock, SQLiteCoordinatorStore
from tests.test_swarm_broker import fixture, require_kernel
from tests.test_swarm_policy_broker import current_policy_broker, scoped_policy


def test_sdk_coordinated_route_uses_real_owned_broker_not_framework_callback(tmp_path):
    require_kernel()
    store = SQLiteCoordinatorStore(tmp_path / "coordinator.db", create=True, clock=lambda: 100)
    clock = CoordinatorClock(store)
    (tmp_path / "broker").mkdir()
    with fixture(tmp_path / "broker", shared_clock=clock) as data:
        with current_policy_broker(data, scoped_policy(data[13]), shared_clock=clock) as current:
            runtime, broker, _, native, channel, grant, context, operator = current
            coordinator = SwarmCoordinator(store, clock=clock, operator=operator)
            control = coordinator.control_source(operator=operator)
            scope = coordinator.register_scope(
                native,
                BudgetPolicy(runtime.epoch, runtime._budget.policy.limits),
                control=control,
                broker_channels=(broker._broker_channel,),
                brokers=(("host-b", broker),),
                runtime=runtime,
            )
            coordinator.initialize_scope(scope, control=control)
            coordinator.budget_view(scope, control=control)
            coordinator.start(scope, control=control)
            parent_channel = next(
                handle
                for handle, row in native.authenticator._channels.items()
                if row.enrollment.context is not None
                and row.enrollment.context.identity.agent_id == "parent"
            )
            parent_grant = next(
                reference for reference, row in native._grants.items() if row.parent_ref is None
            )
            parent = coordinator.admit(scope, parent_channel)
            lease = coordinator.admit(scope, channel)
            coordinator.bind_grant(scope, parent_channel, parent.reference, parent_grant)
            coordinator.bind_grant(scope, channel, lease.reference, grant)
            sdk = SwarmSDK(operator=operator)
            host_runtime = object()
            session = sdk.bind_coordinator(
                host_runtime,
                coordinator=coordinator,
                scope=scope,
                workload_channel=channel,
                broker_channel=broker._broker_channel,
                lease=lease,
                grant_ref=grant,
                identify=lambda: host_runtime,
                operator=operator,
            )
            called = []
            tool = sdk.register_tool(
                session,
                name="read_file",
                runtime="fixture",
                callback=lambda args: called.append(args),
                guard=lambda: None,
                operator=operator,
            )
            prepared = sdk.prepare(
                session, tool, {"path": str(data[13])}, request_id="sdk-owned-read"
            )
            assert prepared.disposition == "execute" and prepared.call is not None
            result = sdk.forward(session, prepared.call)
            assert result.status == "completed" and result.value == b"broker-owned-benign-data\n"
            assert (
                result.physical_enforcement
                and sdk.verify_result(result, prepared.call)
                and not called
            )
            report = coordinator.budget_report(scope, channel, lease.reference)
            assert report["limits"][0]["consumed"] == 1 and report["limits"][0]["reserved"] == 0
