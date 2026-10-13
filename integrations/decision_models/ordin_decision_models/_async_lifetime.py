"""Bounded async waits, with leases retained through nested request cleanup."""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")
_pending: set[asyncio.Future[Any]] = set()


class _Lifetime:
    def __init__(self, release: Callable[[], None]):
        self.release = release
        self.tasks: set[asyncio.Future[Any]] = set()
        self.released = False

    def completed(self, task: asyncio.Future[Any]) -> None:
        self.tasks.discard(task)
        if not self.tasks and not self.released:
            self.released = True
            self.release()


_lifetimes: ContextVar[tuple[_Lifetime, ...]] = ContextVar("ordin_async_lifetimes", default=())


async def bounded_await(
    awaitable: Awaitable[T], timeout: float, *, release: Callable[[], None] | None = None
) -> T:
    """Discard late answers and propagate cancellation without awaiting resistance.

    Keep strong task references and consume late exceptions. Nested bounded
    requests inherit the caller's lease, so returning a timeout from an adapter
    cannot release a router slot while its transport still performs cleanup.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    owners = _lifetimes.get()
    if release is not None:
        owners += (_Lifetime(release),)
    token = _lifetimes.set(owners)
    try:
        task = asyncio.ensure_future(awaitable)
    except BaseException:
        if release is not None:
            release()
        raise
    finally:
        _lifetimes.reset(token)
    _pending.add(task)
    for owner in owners:
        owner.tasks.add(task)

    def completed(future: asyncio.Future[Any]) -> None:
        _pending.discard(future)
        if not future.cancelled():
            future.exception()
        for owner in owners:
            owner.completed(future)

    task.add_done_callback(completed)
    try:
        done, _ = await asyncio.wait((task,), timeout=timeout)
        if not done or loop.time() >= deadline:
            task.cancel()
            # Allow cooperative cancellation to acknowledge without waiting
            # for a provider that catches cancellation and keeps working.
            await asyncio.wait((task,), timeout=0)
            raise asyncio.TimeoutError
        return task.result()
    except asyncio.CancelledError:
        task.cancel()
        await asyncio.wait((task,), timeout=0)
        raise
