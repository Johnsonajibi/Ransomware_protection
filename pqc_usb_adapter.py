"""
PQC + USB token adapter using pqcualusb.
Falls back gracefully if library or device is unavailable.
"""

import logging
from typing import Optional

try:
    import pqcdualusb  # type: ignore
    PQCDUALUSB_AVAILABLE = True
except ImportError:
    pqcdualusb = None  # type: ignore
    PQCDUALUSB_AVAILABLE = False


class PQCUSBAdapter:
    """Thin wrapper around pqcdualusb for detection, signing, verification."""

    def __init__(self):
        self.device = None
        self.public_key: Optional[bytes] = None

    def detect(self) -> bool:
        """Detect and cache a PQC USB token if available."""
        if not PQCDUALUSB_AVAILABLE:
            return False
        try:
            # Try common entry points
            if hasattr(pqcdualusb, "list_tokens"):
                tokens = pqcdualusb.list_tokens()
                if tokens:
                    self.device = tokens[0]
            elif hasattr(pqcdualusb, "discover"):
                self.device = pqcdualusb.discover()
            elif hasattr(pqcdualusb, "get_default_token"):
                self.device = pqcdualusb.get_default_token()

            if self.device:
                # Best-effort to fetch public key
                self.public_key = self._get_public_key()
                logging.info("PQC USB token detected via pqcualusb")
                return True
        except Exception as e:
            logging.warning(f"pqcdualusb detection failed: {e}")
        return False

    def _get_public_key(self) -> Optional[bytes]:
        if not self.device:
            return None
        try:
            if hasattr(self.device, "get_public_key"):
                return self.device.get_public_key()
            if hasattr(self.device, "export_public_key"):
                return self.device.export_public_key()
        except Exception:
            return None
        return None

    def sign(self, data: bytes, algorithm: str = "dilithium2") -> Optional[bytes]:
        """Sign data using the PQC token."""
        if not self.device:
            return None
        try:
            if hasattr(self.device, "sign"):
                # Some libs accept algorithm kwarg
                try:
                    return self.device.sign(data, algorithm=algorithm)
                except TypeError:
                    return self.device.sign(data)
            if hasattr(self.device, "dilithium_sign"):
                return self.device.dilithium_sign(data)
        except Exception as e:
            logging.error(f"pqcdualusb signing failed: {e}")
            return None
        return None

    def verify(self, data: bytes, signature: bytes, public_key: Optional[bytes] = None, algorithm: str = "dilithium2") -> bool:
        if not PQCDUALUSB_AVAILABLE:
            return False
        pk = public_key or self.public_key
        if not pk:
            return False
        try:
            if hasattr(pqcdualusb, "verify"):
                try:
                    return bool(pqcdualusb.verify(data, signature, pk, algorithm=algorithm))
                except TypeError:
                    return bool(pqcdualusb.verify(data, signature, pk))
            if hasattr(pqcdualusb, "dilithium_verify"):
                return bool(pqcdualusb.dilithium_verify(data, signature, pk))
        except Exception as e:
            logging.error(f"pqcdualusb verification failed: {e}")
            return False
        return False


__all__ = ["PQCUSBAdapter", "PQCDUALUSB_AVAILABLE"]
