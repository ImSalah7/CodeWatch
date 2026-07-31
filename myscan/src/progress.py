"""Real-time scan progress tracking with SSE event emission."""

from __future__ import annotations

import json
import queue
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ScanEvent:
    """An event emitted during a scan."""
    event_type: str  # progress, finding, file, rule, complete, error, paused, resumed
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class ProgressTracker:
    """Tracks scan progress and emits events for SSE streaming."""

    def __init__(self, job_id: str):
        self.job_id = job_id
        self._queues: list[queue.Queue] = []
        self._lock = threading.Lock()

        # Progress state
        self.total_files: int = 0
        self.scanned_files: int = 0
        self.current_file: str = ""
        self.current_rule: str = ""
        self.phase: str = "initializing"
        self.findings_count: int = 0
        self.severity_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        self.start_time: float = time.time()
        self.elapsed: float = 0.0
        self.eta: float = 0.0
        self.paused: bool = False
        self.cancelled: bool = False

    def emit(self, event_type: str, data: dict[str, Any] | None = None) -> None:
        event = ScanEvent(event_type=event_type, data=data or {})
        with self._lock:
            dead: list[queue.Queue] = []
            for q in self._queues:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._queues.remove(q)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._lock:
            self._queues.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._queues:
                self._queues.remove(q)

    def on_file_start(self, file_path: str) -> None:
        self.current_file = file_path
        self.phase = "scanning"
        self._update_timing()
        self.emit("file", {"file": file_path, "scanned": self.scanned_files, "total": self.total_files})

    def on_file_done(self, file_path: str) -> None:
        self.scanned_files += 1
        self.current_file = ""
        self._update_timing()
        self.emit("progress", {
            "scanned": self.scanned_files,
            "total": self.total_files,
            "percent": round(self.scanned_files / max(self.total_files, 1) * 100, 1),
            "elapsed": round(self.elapsed, 1),
            "eta": round(self.eta, 1),
            "phase": self.phase,
        })

    def on_rule(self, rule_name: str) -> None:
        self.current_rule = rule_name
        self.emit("rule", {"rule": rule_name})

    def on_finding(self, finding: dict) -> None:
        self.findings_count += 1
        sev = finding.get("severity", "info")
        self.severity_counts[sev] = self.severity_counts.get(sev, 0) + 1
        self.emit("finding", {
            "finding": finding,
            "total": self.findings_count,
            "severity_counts": dict(self.severity_counts),
        })

    def on_complete(self, summary: dict) -> None:
        self.phase = "completed"
        self._update_timing()
        self.emit("complete", {
            "summary": summary,
            "elapsed": round(self.elapsed, 1),
        })

    def on_error(self, error: str) -> None:
        self.phase = "error"
        self.emit("error", {"error": error})

    def on_paused(self) -> None:
        self.paused = True
        self.phase = "paused"
        self.emit("paused", {})

    def on_resumed(self) -> None:
        self.paused = False
        self.phase = "scanning"
        self.emit("resumed", {})

    def _update_timing(self) -> None:
        self.elapsed = time.time() - self.start_time
        if self.scanned_files > 0:
            rate = self.scanned_files / max(self.elapsed, 0.1)
            remaining = max(self.total_files - self.scanned_files, 0)
            self.eta = remaining / max(rate, 0.1)
        else:
            self.eta = 0.0

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "total_files": self.total_files,
            "scanned_files": self.scanned_files,
            "current_file": self.current_file,
            "current_rule": self.current_rule,
            "phase": self.phase,
            "findings_count": self.findings_count,
            "severity_counts": self.severity_counts,
            "elapsed": round(self.elapsed, 1),
            "eta": round(self.eta, 1),
            "paused": self.paused,
            "cancelled": self.cancelled,
            "percent": round(self.scanned_files / max(self.total_files, 1) * 100, 1),
        }


# Global registry of active progress trackers
_active_trackers: dict[str, ProgressTracker] = {}
_tracker_lock = threading.Lock()


def get_tracker(job_id: str) -> ProgressTracker | None:
    with _tracker_lock:
        return _active_trackers.get(job_id)


def create_tracker(job_id: str) -> ProgressTracker:
    tracker = ProgressTracker(job_id)
    with _tracker_lock:
        _active_trackers[job_id] = tracker
    return tracker


def remove_tracker(job_id: str) -> None:
    with _tracker_lock:
        _active_trackers.pop(job_id, None)


def emit_scan_event(job_id: str, event_type: str, data: dict | None = None) -> None:
    tracker = get_tracker(job_id)
    if tracker:
        tracker.emit(event_type, data)
