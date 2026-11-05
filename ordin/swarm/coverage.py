"""Explicit late-attach inventory; no inventory claim upgrades enforcement."""

from dataclasses import dataclass

from .gateway import ROUTES
from .models import CoverageEntry, CoverageManifest, identifier

PATHWAYS = ("hook", "mcp", "sdk", "gateway", "outbound_network", "credential", "executor")
ROUTE_PATHWAYS = {
    "shell": "hook",
    "mcp": "mcp",
    "sdk": "sdk",
    "file": "gateway",
    "database": "gateway",
    "http": "gateway",
}


@dataclass(frozen=True, slots=True)
class AttachCoverage:
    mode: str
    routes: frozenset[str] = frozenset()
    telemetry: bool = False
    restart_required: frozenset[str] = frozenset()
    observed_pathways: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if (
            type(self.mode) is not str
            or self.mode not in {"observe", "intercept", "enforce"}
            or type(self.routes) is not frozenset
            or not self.routes <= ROUTES
            or type(self.telemetry) is not bool
            or type(self.restart_required) is not frozenset
            or not self.restart_required <= set(PATHWAYS)
            or type(self.observed_pathways) is not frozenset
            or not self.observed_pathways <= set(PATHWAYS)
            or (self.observed_pathways and not self.telemetry)
        ):
            raise ValueError("invalid late-attach coverage inventory")

    def diagnostics(self, *, routing_verified: bool = False, live: bool = True) -> list[dict]:
        self.__post_init__()
        mediated = {
            "hook": "shell" in self.enabled_routes,
            "mcp": "mcp" in self.enabled_routes,
            "sdk": "sdk" in self.enabled_routes,
            "gateway": bool(self.enabled_routes),
            # Wrapping an HTTP route is not host-wide outbound-network control.
            "outbound_network": False,
            "credential": False,
            "executor": False,
        }
        plans = {
            "outbound_network": "route_egress_or_restart_in_constrained_runtime",
            "credential": "revoke_or_rotate_existing_credentials",
            "executor": "stop_and_restart_with_constrained_executor",
        }
        return [
            {
                "pathway": pathway,
                "state": "restart_required"
                if pathway in self.restart_required
                else "covered"
                if live
                and (
                    routing_verified
                    and mediated[pathway]
                    or self.telemetry
                    and pathway in self.observed_pathways
                )
                else "unknown"
                if pathway not in plans
                else "uncovered",
                "coverage": "mediated"
                if live
                and routing_verified
                and mediated[pathway]
                and pathway not in self.restart_required
                else "observe_only"
                if live
                and self.telemetry
                and pathway in self.observed_pathways
                and pathway not in self.restart_required
                else "coverage_gap",
                "plan": plans.get(pathway, "verify_future_call_routing"),
            }
            for pathway in PATHWAYS
        ]

    @property
    def enabled_routes(self) -> frozenset[str]:
        return frozenset(
            route for route in self.routes if ROUTE_PATHWAYS[route] not in self.restart_required
        )

    def manifest(self, boundary_id: str) -> CoverageManifest:
        identifier(boundary_id, "boundary_id")
        if self.mode == "enforce":
            raise ValueError("live attach has no verified enforcing broker admission")
        entries = tuple(
            CoverageEntry(
                route,
                route,
                "future_routed_calls",
                boundary_id,
                "mediated"
                if self.mode == "intercept" and route in self.enabled_routes
                else "observe_only"
                if self.telemetry
                and ROUTE_PATHWAYS[route] in self.observed_pathways
                and ROUTE_PATHWAYS[route] not in self.restart_required
                else "coverage_gap",
            )
            for route in sorted(self.routes)
        )
        return CoverageManifest(self.mode, entries)
