"""macOS token dropper for AntiRansomwareES.

- Generates Ed25519-signed token JSON files under /var/run/antiransomware/tokens/<pid>.json
- Reads protected paths from /etc/antiransomware/protected_paths for convenience (optional).
- Uses PyNaCl (`pip install pynacl`). Run with sudo: `sudo python3 macos_token_dropper.py --pid 1234 --path /Users/Shared/Protected/file.txt`.

Token JSON keys match driver_macos.swift expectations:
  file_id (uint64), process_id (pid_t), user_id (uid_t), allowed_ops (uint32),
  byte_quota (uint64), expiry (epoch seconds), nonce (base64), signature (base64)
"""

import argparse
import base64
import json
import os
import time
import secrets
import struct
from pathlib import Path

from nacl import signing

try:
    import pqcdualusb  # type: ignore
    PQC_AVAILABLE = True
except ImportError:
    pqcdualusb = None  # type: ignore
    PQC_AVAILABLE = False

TOKEN_PACK_FMT = "<QIIIQQ16s"  # file_id,pid,uid,allowed_ops,byte_quota,expiry,nonce


def load_private_key(key_path: Path) -> signing.SigningKey:
    data = key_path.read_bytes()
    if len(data) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes (seed)")
    return signing.SigningKey(data)


def write_token(pid: int, path: str, signer: signing.SigningKey, ops: int, quota: int, ttl: int):
    now = int(time.time())
    expiry = now + ttl
    uid = os.getuid()
    file_id = struct.unpack("<Q", os.urandom(8))[0]
    nonce = secrets.token_bytes(16)
    core = struct.pack(TOKEN_PACK_FMT, file_id, pid, uid, ops, quota, expiry, nonce)

    # Enforce PQC always
    if not PQC_AVAILABLE:
        raise RuntimeError("PQC required but pqcdualusb not available")
    pqc_sig = None
    try:
        dev = None
        if hasattr(pqcdualusb, "list_tokens"):
            tokens = pqcdualusb.list_tokens()
            if tokens:
                dev = tokens[0]
        elif hasattr(pqcdualusb, "get_default_token"):
            dev = pqcdualusb.get_default_token()
        if dev is None:
            raise RuntimeError("PQC token not found")
        if hasattr(dev, "sign"):
            pqc_sig = dev.sign(core)
        elif hasattr(dev, "dilithium_sign"):
            pqc_sig = dev.dilithium_sign(core)
        if not pqc_sig:
            raise RuntimeError("PQC signing failed")
    except Exception as e:
        raise RuntimeError(f"PQC enforcement failed: {e}")

    sig = signer.sign(core).signature

    token = {
        "file_id": file_id,
        "process_id": pid,
        "user_id": uid,
        "allowed_ops": ops,
        "byte_quota": quota,
        "expiry": expiry,
        "nonce": base64.b64encode(nonce).decode(),
        "signature": base64.b64encode(sig).decode(),
    }
    if pqc_sig:
        token["pqc_signature"] = base64.b64encode(pqc_sig).decode()

    out_dir = Path("/var/run/antiransomware/tokens")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{pid}.json"
    out_file.write_text(json.dumps(token))
    print(f"[dropper] wrote token for pid {pid} to {out_file}")

    # Optionally update protected paths sample
    policy = Path("/etc/antiransomware/protected_paths")
    if policy.exists():
        print("[dropper] protected paths found:")
        print(policy.read_text())


def main():
    parser = argparse.ArgumentParser(description="macOS token dropper")
    parser.add_argument("--key", type=Path, required=True, help="Path to 32-byte Ed25519 private key seed")
    parser.add_argument("--pid", type=int, required=True, help="Target process id")
    parser.add_argument("--path", type=str, required=True, help="Path being authorized (for reference only)")
    parser.add_argument("--ops", type=int, default=0xFFFFFFFF, help="Allowed ops mask")
    parser.add_argument("--quota", type=int, default=1_000_000_000, help="Byte quota")
    parser.add_argument("--ttl", type=int, default=300, help="Token lifetime seconds")
    args = parser.parse_args()

    signer = load_private_key(args.key)
    write_token(args.pid, args.path, signer, args.ops, args.quota, args.ttl)


+if __name__ == "__main__":
+    main()
