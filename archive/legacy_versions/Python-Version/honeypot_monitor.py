#!/usr/bin/env python3
"""
Honeypot Monitor
================
Create and monitor decoy files (canary traps) in strategic locations
to detect early ransomware behavior.
"""

import os
import threading
from pathlib import Path
from typing import Callable, Iterable, Optional

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


class HoneypotMonitor:
    """Create and monitor canary files for ransomware detection."""

    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.logger = SecurityEventLogger() if HAS_LOGGER else None
        self.honeypots: list[Path] = []
        self.observer: Optional[Observer] = None
        self._lock = threading.Lock()

    def create_honeypots(self, base_dirs: Iterable[str]):
        """Create decoy files in specified directories."""
        names = [
            'Banking_Passwords.xlsx',
            'Crypto_Wallet_Keys.txt',
            'Company_Secrets.docx',
            '.honeypot_file',
        ]
        for base_dir in base_dirs:
            base = Path(base_dir)
            if not base.exists():
                continue
            for name in names:
                hp = base / name
                if hp.exists():
                    continue
                try:
                    hp.write_text("HONEYPOT: DO NOT ACCESS\nAccess will trigger security alert.\n", encoding='utf-8')
                    with self._lock:
                        self.honeypots.append(hp)
                except Exception:
                    continue

    def start(self):
        """Start monitoring created honeypots."""
        if not HAS_WATCHDOG:
            return False

        class Handler(FileSystemEventHandler):
            outer = self

            def on_any_event(self, event):
                if event.is_directory:
                    return
                p = Path(event.src_path)
                with Handler.outer._lock:
                    if p in Handler.outer.honeypots:
                        Handler.outer._trigger(p, event.event_type)

        self.observer = Observer()
        monitored_dirs = set()
        with self._lock:
            for hp in self.honeypots:
                parent = hp.parent
                if parent not in monitored_dirs:
                    self.observer.schedule(Handler(), str(parent), recursive=False)
                    monitored_dirs.add(parent)
        self.observer.start()
        return True

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2)
            self.observer = None

    def _trigger(self, path: Path, event_type: str):
        if self.logger:
            self.logger.log_event(
                SecurityEvent(
                    timestamp=self._now(),
                    event_type='HONEYPOT_TRIGGERED',
                    severity='CRITICAL',
                    details={
                        'file_accessed': str(path),
                        'action_attempted': event_type,
                        'threat_level': 'DEFINITE_MALWARE'
                    }
                )
            )
        if self.callback:
            self.callback({'honeypot_path': str(path), 'event_type': event_type})

    def _now(self) -> float:
        import time
        return time.time()
