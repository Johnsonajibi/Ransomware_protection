#!/usr/bin/env python3
"""
Ransomware Decryptor Support
===========================
Identify ransomware family heuristically and call mapped decryptor helpers.

This module does not ship decryptor binaries; it dispatches to known tools
if present on disk or informs the operator.
"""

import subprocess
from pathlib import Path
from typing import Optional


class RansomwareDecryption:
    """Identify family and attempt decryptor invocation."""

    def __init__(self, decryptor_dir: Optional[str] = None):
        self.decryptor_dir = Path(decryptor_dir or r"C:\\AntiRansomware\\Decryptors")
        self.decryptor_dir.mkdir(parents=True, exist_ok=True)

        # Map families to expected decryptor executables
        self.decryptor_map = {
            'WannaCry': 'wannacry_decryptor.exe',
            'Locky': 'locky_decryptor.exe',
            'Cerber': 'cerber_decryptor.exe',
        }

    def identify_ransomware_family(self, encrypted_file: Path) -> str:
        ext = encrypted_file.suffix.lower()
        ransom_map = {
            '.wannacry': 'WannaCry',
            '.wcry': 'WannaCry',
            '.locked': 'Locky',
            '.cerber': 'Cerber',
            '.cryptolocker': 'CryptoLocker',
        }

        if ext in ransom_map:
            return ransom_map[ext]

        ransom_notes = [
            'README.txt', 'DECRYPT_INSTRUCTIONS.txt',
            'HOW_TO_DECRYPT.html', 'RESTORE_FILES.txt'
        ]

        for note in ransom_notes:
            note_path = encrypted_file.parent / note
            if note_path.exists():
                content = note_path.read_text(errors='ignore')
                if 'WannaCry' in content or 'Wana Decrypt0r' in content:
                    return 'WannaCry'
                if 'Locky' in content:
                    return 'Locky'
                if 'Cerber' in content:
                    return 'Cerber'

        return 'UNKNOWN'

    def attempt_decryption(self, encrypted_file: str) -> Optional[str]:
        target = Path(encrypted_file)
        if not target.exists():
            return None

        family = self.identify_ransomware_family(target)
        decryptor_exe = self.decryptor_map.get(family)
        if not decryptor_exe:
            return None

        candidate = self.decryptor_dir / decryptor_exe
        if not candidate.exists():
            return None

        try:
            result = subprocess.run(
                [str(candidate), str(target)],
                capture_output=True,
                text=True,
                timeout=300,
                shell=False
            )
            if result.returncode == 0:
                return f"Decryption attempted with {candidate.name}: {result.stdout.strip()}"
            return f"Decryptor exited with {result.returncode}: {result.stderr.strip()}"
        except Exception as e:
            return f"Decryption failed: {e}"