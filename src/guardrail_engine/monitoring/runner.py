"""Runs the monitors' ``tick`` functions on a timer, off the request path (M4-04).

One **daemon** thread, so a tick that hangs cannot hold up process exit; :meth:`close` waits
at most ``timeout`` for it and then lets it go. A tick that raises is logged and the loop
carries on. Time between ticks is real time (``threading.Event.wait``); the monitors' own
clocks are injected separately.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class PeriodicRunner:
    def __init__(self, ticks: list[Callable[[], Any]], *, interval_s: float = 30.0) -> None:
        if interval_s <= 0:
            raise ValueError("interval_s must be positive")
        self._ticks = list(ticks)
        self._interval_s = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="guardrail-monitor-runner", daemon=True
        )
        self._thread.start()

    def run_once(self) -> None:
        """Run every tick now, in this thread."""
        for tick in self._ticks:
            try:
                tick()
            except Exception:
                logger.exception("monitor tick failed")

    def _run(self) -> None:
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self._interval_s)

    def close(self, timeout: float = 1.0) -> None:
        """Stop the loop and wait at most ``timeout`` seconds for the thread."""
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
