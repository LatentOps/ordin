"""Verified future-call routing on a host-owned running Python dispatcher."""

from ordin.swarm import HostSessionEndpoint, SwarmAttachManager
from ordin_swarm.sdk import SwarmSDK


class CustomRuntimeAdapter:
    def __init__(self, manager: SwarmAttachManager, endpoint: HostSessionEndpoint):
        if type(manager) is not SwarmAttachManager or type(endpoint) is not HostSessionEndpoint:
            raise ValueError("original protected attach manager and live endpoint required")
        self.manager = manager
        self.handle = manager.register(endpoint)

    def setup(self, *, dry_run=True):
        return self.manager.attach(self.handle, dry_run=dry_run)

    def bind_sdk(self, sdk: SwarmSDK, *, operator: object):
        return sdk.bind_attached(self.manager, self.handle, operator=operator)

    def invoke(self, route, action, executor):
        row = self.manager._row(self.handle)
        self.manager._check_live(row)
        if row.router is None:
            raise ValueError("verified live dispatcher route unavailable")
        return row.router.call(route, action, executor)

    def status(self):
        return self.manager.status(self.handle)

    def doctor(self):
        return self.manager.doctor(self.handle)

    def close(self):
        return self.manager.detach(self.handle)


__all__ = ["CustomRuntimeAdapter"]
