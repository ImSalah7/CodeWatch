"""Performance Engine - Parallel scanning, caching, and optimization.

Features:
- Parallel file scanning with thread pool
- AST result caching
- Repository-level caching
- Incremental scanning (only scan changed files)
- Memory-efficient streaming
- Progress tracking
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


@dataclass
class ScanMetrics:
    """Performance metrics for a scan."""
    files_total: int = 0
    files_scanned: int = 0
    files_cached: int = 0
    files_skipped: int = 0
    lines_scanned: int = 0
    scan_duration: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    parallel_workers: int = 1
    peak_memory_mb: float = 0.0
    ast_parse_time: float = 0.0
    dataflow_time: float = 0.0
    dedup_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "filesTotal": self.files_total,
            "filesScanned": self.files_scanned,
            "filesCached": self.files_cached,
            "filesSkipped": self.files_skipped,
            "linesScanned": self.lines_scanned,
            "scanDuration": round(self.scan_duration, 2),
            "cacheHits": self.cache_hits,
            "cacheMisses": self.cache_misses,
            "parallelWorkers": self.parallel_workers,
            "peakMemoryMb": round(self.peak_memory_mb, 1),
        }


class ASTCache:
    """Caches AST parse results by file content hash."""

    def __init__(self, max_size: int = 1000, cache_dir: Optional[str] = None):
        self._cache: dict[str, dict] = {}
        self._file_keys: dict[str, set[str]] = {}
        self._max_size = max_size
        self._cache_dir = Path(cache_dir) if cache_dir else None
        self._hits = 0
        self._misses = 0

    def get(self, file_path: str, content: str) -> Optional[dict]:
        key = self._make_key(file_path, content)
        if key in self._cache:
            self._hits += 1
            return self._cache[key]
        if self._cache_dir:
            cached = self._load_from_disk(key)
            if cached is not None:
                self._hits += 1
                self._cache[key] = cached
                return cached
        self._misses += 1
        return None

    def put(self, file_path: str, content: str, ast_result: dict) -> None:
        key = self._make_key(file_path, content)
        if len(self._cache) >= self._max_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        self._cache[key] = ast_result
        if file_path not in self._file_keys:
            self._file_keys[file_path] = set()
        self._file_keys[file_path].add(key)
        if self._cache_dir:
            self._save_to_disk(key, ast_result)

    def invalidate(self, file_path: str) -> None:
        keys = self._file_keys.pop(file_path, set())
        for key in keys:
            self._cache.pop(key, None)

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def clear(self) -> None:
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _make_key(file_path: str, content: str) -> str:
        return hashlib.sha256(f"{file_path}:{content}".encode()).hexdigest()

    def _load_from_disk(self, key: str) -> Optional[dict]:
        if not self._cache_dir:
            return None
        cache_file = self._cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                return json.loads(cache_file.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def _save_to_disk(self, key: str, data: dict) -> None:
        if not self._cache_dir:
            return
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = self._cache_dir / f"{key}.json"
            cache_file.write_text(json.dumps(data), encoding="utf-8")
        except Exception:
            pass


class IncrementalScanner:
    """Tracks file changes for incremental scanning."""

    def __init__(self, state_file: Optional[str] = None):
        self._state_file = Path(state_file) if state_file else None
        self._file_hashes: dict[str, str] = {}
        self._load_state()

    def has_changed(self, file_path: str, content: str) -> bool:
        current_hash = hashlib.sha256(content.encode()).hexdigest()
        old_hash = self._file_hashes.get(file_path)
        return old_hash != current_hash

    def update(self, file_path: str, content: str) -> None:
        current_hash = hashlib.sha256(content.encode()).hexdigest()
        self._file_hashes[file_path] = current_hash

    def get_changed_files(self, file_paths: list[str], contents: dict[str, str]) -> list[str]:
        changed = []
        for fp in file_paths:
            content = contents.get(fp, "")
            if self.has_changed(fp, content):
                changed.append(fp)
        return changed

    def save_state(self) -> None:
        if self._state_file:
            try:
                self._state_file.parent.mkdir(parents=True, exist_ok=True)
                self._state_file.write_text(json.dumps(self._file_hashes), encoding="utf-8")
            except Exception:
                pass

    def _load_state(self) -> None:
        if self._state_file and self._state_file.exists():
            try:
                self._file_hashes = json.loads(self._state_file.read_text(encoding="utf-8"))
            except Exception:
                self._file_hashes = {}

    def clear(self) -> None:
        self._file_hashes.clear()


class ParallelScanner:
    """Scans files in parallel using a thread pool."""

    def __init__(self, max_workers: int = 4):
        self._max_workers = max_workers

    def scan_files(
        self,
        files: list[tuple[str, str]],
        scan_fn: Callable[[str, str], list],
    ) -> list[tuple[str, list]]:
        results = []
        if self._max_workers <= 1 or len(files) <= 1:
            for file_path, content in files:
                try:
                    findings = scan_fn(file_path, content)
                    results.append((file_path, findings))
                except Exception:
                    results.append((file_path, []))
            return results

        with ThreadPoolExecutor(max_workers=min(self._max_workers, len(files))) as executor:
            future_to_file = {}
            for file_path, content in files:
                future = executor.submit(self._safe_scan, scan_fn, file_path, content)
                future_to_file[future] = file_path

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_path_result, findings = future.result()
                    results.append((file_path_result, findings))
                except Exception:
                    results.append((file_path, []))

        return results

    @staticmethod
    def _safe_scan(scan_fn: Callable, file_path: str, content: str) -> tuple[str, list]:
        try:
            findings = scan_fn(file_path, content)
            return file_path, findings
        except Exception:
            return file_path, []


class ScanProgress:
    """Tracks scan progress for streaming UI updates."""

    def __init__(self, total: int = 0):
        self._total = total
        self._completed = 0
        self._start_time = time.time()
        self._callbacks: list[Callable] = []

    @property
    def total(self) -> int:
        return self._total

    @property
    def completed(self) -> int:
        return self._completed

    @property
    def percentage(self) -> float:
        return (self._completed / self._total * 100) if self._total > 0 else 0.0

    @property
    def elapsed(self) -> float:
        return time.time() - self._start_time

    @property
    def estimated_remaining(self) -> float:
        if self._completed == 0:
            return 0.0
        rate = self._completed / self.elapsed
        remaining = self._total - self._completed
        return remaining / rate if rate > 0 else 0.0

    def update(self, count: int = 1) -> None:
        self._completed += count
        for cb in self._callbacks:
            try:
                cb(self)
            except Exception:
                pass

    def on_update(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def reset(self, total: int = 0) -> None:
        self._total = total
        self._completed = 0
        self._start_time = time.time()
