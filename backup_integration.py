#!/usr/bin/env python3
"""
Backup Integration
==================
Create versioned backups of protected paths before granting access.

Notes:
- Designed to run right before ACLs are relaxed in token-gated access.
- Keeps the last N versions (default 10) per path.
"""

import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional


class BackupIntegration:
    """Automatic backup before granting access to protected resources."""

    def __init__(self, base_dir: Optional[Path] = None, keep: int = 10):
        self.base_dir = Path(base_dir or r"C:\\AntiRansomware\\Backups")
        self.keep = max(1, keep)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def backup_before_access(self, protected_path: str) -> Optional[Path]:
        """Create a versioned backup of the protected path.

        Returns the backup path, or None on failure.
        """
        try:
            src = Path(protected_path)
            if not src.exists():
                return None

            target_dir = self.base_dir / src.name
            target_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if src.is_file():
                backup_path = target_dir / f"{src.stem}_{timestamp}{src.suffix}"
                shutil.copy2(src, backup_path)
            else:
                backup_path = target_dir / f"{src.name}_{timestamp}"
                shutil.copytree(src, backup_path, dirs_exist_ok=False)

            self._cleanup_old_backups(target_dir)
            return backup_path

        except Exception:
            return None

    def _cleanup_old_backups(self, target_dir: Path):
        """Keep only the most recent N backups for the path."""
        backups = sorted(target_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in backups[self.keep:]:
            try:
                if old.is_dir():
                    shutil.rmtree(old, ignore_errors=True)
                else:
                    old.unlink(missing_ok=True)
            except Exception:
                continue