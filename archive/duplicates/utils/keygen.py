"""Key generation helper for Anti-Ransomware stack.

- Generates:
  * Ed25519 software keypair (private_key.pem, public_key.pem) for broker fallback.
  * 32-byte HMAC key for Windows minifilter (keys/hmac.key).
- Does NOT generate PQC private keys; use your hardware PQC USB token.

Usage:
  python keygen.py --out-dir keys
"""

import argparse
from pathlib import Path
import os

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import secrets

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=Path("keys"))
    args = parser.parse_args()

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    # Ed25519 keypair
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_path = out / "private_key.pem"
    pub_path = out / "public_key.pem"

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)

    # HMAC key for Windows minifilter
    hmac_key = secrets.token_bytes(32)
    (out / "hmac.key").write_bytes(hmac_key)

    print(f"Wrote Ed25519 private_key.pem/public_key.pem and hmac.key to {out}")
    print("Note: PQC private keys are hardware-backed; provision your USB token separately.")


+if __name__ == "__main__":
+    main()
