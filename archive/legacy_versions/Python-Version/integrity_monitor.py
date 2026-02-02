#!/usr/bin/env python3
"""
File Integrity Monitoring (FIM)
===============================
Baseline hashes and real-time change detection for protected paths.

Designed as an optional component: falls back gracefully if watchdog
is not available.
"""

import hashlib
import json
import threading
from pathlib import Path
from typing import Dict, Iterable, Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    from security_event_logger import SecurityEventLogger, SecurityEvent
    HAS_LOGGER = True
except ImportError:
    HAS_LOGGER = False


def sha256_file(path: Path) -> Optional[str]:
    """Compute SHA256 for a file."""
    try:
        hasher = hashlib.sha256()
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


class IntegrityMonitor:
    """Baseline hashing + change detection."""

    def __init__(self, baseline_path: Optional[Path] = None):
        self.baseline_path = Path(baseline_path or r"C:\\ProgramData\\AntiRansomware\\integrity_baseline.json")
        self.baseline: Dict[str, str] = {}
        self.observer: Optional[Observer] = None
        self.logger = SecurityEventLogger() if HAS_LOGGER else None
        self._lock = threading.Lock()

    def load_baseline(self):
        if self.baseline_path.exists():
            try:
                self.baseline = json.loads(self.baseline_path.read_text())
            except Exception:
                self.baseline = {}

    def save_baseline(self):
        try:
            self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
            self.baseline_path.write_text(json.dumps(self.baseline, indent=2))
        except Exception:
            pass

    def create_baseline(self, paths: Iterable[str]):
        """Create or refresh baseline hashes for provided paths."""
        self.baseline = {}
        for raw in paths:
            p = Path(raw)
            if p.is_file():
                digest = sha256_file(p)
                if digest:
                    self.baseline[str(p)] = digest
            elif p.is_dir():
                for f in p.rglob('*'):
                    if f.is_file():
                        digest = sha256_file(f)
                        if digest:
                            self.baseline[str(f)] = digest
        self.save_baseline()

    def start(self, paths: Iterable[str]):
        """Start monitoring the supplied paths."""
        if not HAS_WATCHDOG:
            return False

        self.load_baseline()

        class Handler(FileSystemEventHandler):
            outer = self

            def on_modified(self, event):
                if event.is_directory:
                    return
                Handler.outer._handle_change(Path(event.src_path))

            def on_created(self, event):
                if event.is_directory:
                    return
                Handler.outer._handle_change(Path(event.src_path))

        self.observer = Observer()
        for raw in paths:
            p = Path(raw)
            if p.exists():
                self.observer.schedule(Handler(), str(p), recursive=True)
        self.observer.start()
        return True

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2)
            self.observer = None

    def _handle_change(self, path: Path):
        digest = sha256_file(path)
        with self._lock:
            baseline_hash = self.baseline.get(str(path))
            if digest and baseline_hash and digest != baseline_hash:
                if self.logger:
                    self.logger.log_event(
                        SecurityEvent(
                            timestamp=self._now(),
                            event_type='FILE_INTEGRITY_CHANGED',
                            severity='HIGH',
                            details={
                                'file_path': str(path),
                                'previous_hash': baseline_hash,
                                'current_hash': digest
                            }
                        )
                    )
            if digest:
                self.baseline[str(path)] = digest
                self.save_baseline()

    def _now(self) -> float:
        import time
        return time.time()