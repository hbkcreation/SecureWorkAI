"""Moves packet analysis off the capture thread so a traffic surge cannot freeze the app.

The capture thread only drops each packet into a bounded queue (microseconds). One worker
thread drains it in batches and runs the analysers (flow aggregation, rule IDS, protocol
counts, batched ML). If traffic outruns the analysers the OLDEST backlog is bounded by the
queue size and the excess is counted as dropped, instead of growing memory or blocking.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Callable

logger = logging.getLogger(__name__)


class PacketPipeline:
    def __init__(self, handlers: list[Callable], after_batch: Callable[[], None] | None = None,
                 maxsize: int = 50_000, batch_size: int = 100) -> None:
        self._handlers, self._after_batch = list(handlers), after_batch
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._batch_size = batch_size
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.dropped = 0
        self.processed = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="packet-pipeline", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    @property
    def backlog(self) -> int:
        return self._q.qsize()

    def submit(self, packet) -> None:
        """Capture-thread entry point: never blocks."""
        try:
            self._q.put_nowait(packet)
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                batch = [self._q.get(timeout=0.1)]
            except queue.Empty:
                self._flush_after()
                continue
            while len(batch) < self._batch_size:
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            for packet in batch:
                for handler in self._handlers:
                    try:
                        handler(packet)
                    except Exception:
                        logger.exception("Packet handler failed")
            self.processed += len(batch)
            self._flush_after()
            time.sleep(0.002)  # yield the interpreter lock so the UI thread always gets a turn

    def _flush_after(self) -> None:
        if self._after_batch:
            try:
                self._after_batch()
            except Exception:
                logger.exception("Pipeline batch hook failed")
