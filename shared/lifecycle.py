"""Service lifecycle helpers — graceful shutdown on SIGTERM/SIGINT.

Usage:
    async def my_worker(shutdown: asyncio.Event):
        while not shutdown.is_set():
            await do_work()
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

    asyncio.run(run_with_shutdown(my_worker))
"""
from __future__ import annotations

import asyncio
import logging
import signal
from typing import Awaitable, Callable

log = logging.getLogger(__name__)


def install_shutdown_handlers(shutdown: asyncio.Event) -> None:
    """Set the shutdown event on SIGTERM and SIGINT."""
    loop = asyncio.get_event_loop()

    def _handler(sig: int) -> None:
        log.info("Shutdown signal received: %s", signal.Signals(sig).name)
        shutdown.set()

    # Windows does not support SIGTERM — only SIGINT (Ctrl+C)
    signals = [signal.SIGINT]
    if hasattr(signal, "SIGTERM"):
        signals.append(signal.SIGTERM)

    for sig in signals:
        try:
            loop.add_signal_handler(sig, _handler, sig)
        except NotImplementedError:
            # Windows does not support loop.add_signal_handler
            signal.signal(sig, lambda s, _f: _handler(s))


async def run_with_shutdown(
    worker: Callable[[asyncio.Event], Awaitable[None]],
    timeout_s: float = 10.0,
) -> None:
    """Run the worker with a shutdown event; clean exit on SIGTERM."""
    shutdown = asyncio.Event()
    install_shutdown_handlers(shutdown)

    task = asyncio.create_task(worker(shutdown))
    try:
        await task
    except asyncio.CancelledError:
        log.info("Worker cancelled")
    finally:
        if not task.done():
            shutdown.set()
            try:
                await asyncio.wait_for(task, timeout=timeout_s)
            except asyncio.TimeoutError:
                log.warning("Worker did not shut down within %ss, cancelling task", timeout_s)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
