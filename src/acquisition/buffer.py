"""
Event Buffer & Event Streaming Queue for Ingestion Pipeline
"""

import collections
import queue
import threading
from typing import List, Optional
from .collectors import SecurityEvent


class EventBuffer:
    """
    Thread-safe circular ring buffer retaining recent events for windowed analysis.
    """

    def __init__(self, maxlen: int = 10000):
        self._buffer = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def append(self, event: SecurityEvent):
        with self._lock:
            self._buffer.append(event)

    def extend(self, events: List[SecurityEvent]):
        with self._lock:
            self._buffer.extend(events)

    def get_recent(self, n: int = 50) -> List[SecurityEvent]:
        with self._lock:
            return list(self._buffer)[-n:]

    def count(self) -> int:
        with self._lock:
            return len(self._buffer)

    def clear(self):
        with self._lock:
            self._buffer.clear()


class EventStreamingQueue:
    """
    High-throughput thread-safe FIFO streaming queue connecting collectors to correlators.
    """

    def __init__(self, maxsize: int = 50000):
        self._queue = queue.Queue(maxsize=maxsize)

    def push(self, event: SecurityEvent, block: bool = True, timeout: Optional[float] = 1.0) -> bool:
        try:
            self._queue.put(event, block=block, timeout=timeout)
            return True
        except queue.Full:
            return False

    def pop(self, block: bool = True, timeout: Optional[float] = 1.0) -> Optional[SecurityEvent]:
        try:
            return self._queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

    def drain_batch(self, batch_size: int = 100) -> List[SecurityEvent]:
        batch = []
        while len(batch) < batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def qsize(self) -> int:
        return self._queue.qsize()
