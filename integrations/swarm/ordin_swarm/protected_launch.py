"""Explicit fresh-agent launch over one original host-owned private MCP route."""

from __future__ import annotations

import importlib
from pathlib import Path
from threading import Event, Thread

from ordin.swarm.managed_process import (
    LinuxProtectedProcess,
    ProtectedProcessJob,
    ProtectedProcessLimits,
    ProtectedProcessOutcome,
)


class ProtectedAgentLauncher:
    """A trusted parent holds host/TLS authority; the fresh child gets only fd3.

    Constructing this object installs no listener, starts no workload and loads
    no provider/model. The operator selects the actor and pinned program once.
    Child JSON cannot rebind that actor, create another session or issue permits.
    """

    def __init__(
        self,
        host,
        actor_id: str,
        program: Path,
        program_digest: str,
        install_root: Path,
        *,
        operator: object,
        limits: ProtectedProcessLimits = ProtectedProcessLimits(),
    ):
        # The host-owned package is a fixed dependency, not caller-selected
        # plugin code. Runtime imports keep the optional integration opt-in.
        host_module = importlib.import_module("ordin_swarm.host_runtime")
        protocol = importlib.import_module("ordin_swarm.host_protocol")
        if (
            type(host) is not host_module.ManagedToolHost
            or type(operator) is not object
            or host._operator is not operator
            or type(actor_id) is not str
            or not 1 <= len(actor_id) <= 128
        ):
            raise ValueError("exact original managed host, actor and operator required")
        self._host, self._session_type, self._operator = host, protocol.MCPHostSession, operator
        self._actor, self._program, self._program_digest = actor_id, Path(program), program_digest
        self._engine = LinuxProtectedProcess(install_root, operator=operator, limits=limits)

    def prepare(self, *, operator: object) -> ProtectedProcessJob:
        if operator is not self._operator:
            raise ValueError("original launch operator required")
        return self._engine.create_job(self._program, self._program_digest, operator=operator)

    def run(self, job: ProtectedProcessJob, *, operator: object) -> ProtectedProcessOutcome:
        if operator is not self._operator:
            raise ValueError("original launch operator required")
        if not self._engine.start(job, operator=operator):
            return self._engine.finish(job, operator=operator)
        completed = Event()
        monitor = None
        try:
            with self._host.open_local_session(self._actor, operator=operator) as session:
                if type(session) is not self._session_type:
                    raise ValueError("original private MCP host session required")

                def invalidate_on_exit():
                    while not completed.wait(0.01):
                        if not self._engine.is_alive(job, operator=operator):
                            session.close()
                            return

                monitor = Thread(
                    target=invalidate_on_exit, name="ordin-owned-agent-session", daemon=True
                )
                monitor.start()
                self._engine.admit(job, operator=operator)
                while True:
                    request = self._engine.read_request(job, operator=operator)
                    if request is None:
                        break
                    response = session.handle(request)
                    if response is not None:
                        self._engine.reply(job, response, operator=operator)
        except (OSError, ValueError, TimeoutError, EOFError):
            self._engine.request_stop(job, operator=operator)
        except BaseException:
            # Cancellation must close the owned child and original transport;
            # cleanup errors must not replace the caller's original interrupt.
            try:
                self._engine.request_stop(job, operator=operator)
                self._engine.finish(job, operator=operator)
            except Exception:
                pass
            raise
        finally:
            completed.set()
            if monitor is not None:
                monitor.join(timeout=1)
        return self._engine.finish(job, operator=operator)

    def request_stop(self, job: ProtectedProcessJob, *, operator: object) -> str:
        return self._engine.request_stop(job, operator=operator)

    def status(self, job: ProtectedProcessJob, *, operator: object) -> str:
        return self._engine.status(job, operator=operator)

    def verify_outcome(self, outcome: ProtectedProcessOutcome) -> bool:
        return self._engine.verify_outcome(outcome)

    def evidence_record(self, outcome: ProtectedProcessOutcome) -> dict:
        return self._engine.evidence_record(outcome)

    def close(self, *, operator: object) -> None:
        self._engine.close(operator=operator)
