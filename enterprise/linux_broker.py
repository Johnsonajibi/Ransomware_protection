"""Minimal userspace netlink broker for the anti-ransomware LSM.

- Listens on NETLINK_USERSOCK, multicast group 1.
- Responds to requests {seq,u32 pid,char path[PATH_MAX]} with {seq,status,token}.
- Signs tokens with Ed25519 using the key in ./keys/ed25519_private.key (raw 32-byte seed) by default.
- Uses PyNaCl; install with `pip install pynacl` in the venv.
- Run as root: `sudo ./linux_broker.py --key ./keys/ed25519_private.key --paths /etc/antiransomware/protected_paths`.

Token layout matches driver_linux.c struct ar_token:
    u64 file_id;
    u32 process_id;
    u32 user_id;
    u32 allowed_ops;
    u64 byte_quota;
    u64 expiry;
    u8 nonce[16];
    u8 signature[64];

Signature is over the struct without the signature field, little-endian packing.
"""

import argparse
import os
import socket
import struct
import time
import secrets
from pathlib import Path

from nacl import signing

try:
    import pqcdualusb  # type: ignore
    PQC_AVAILABLE = True
except ImportError:
    pqcdualusb = None  # type: ignore
    PQC_AVAILABLE = False

# Netlink constants
NETLINK_USERSOCK = 2
NLMSG_DONE = 0x3
NLM_F_MULTI = 0x2
PATH_MAX = 4096

REQ_FMT = "<II{}s".format(PATH_MAX)  # seq,u32 pid,char path[PATH_MAX]
RESP_FMT = "<IiQIIIQQ16s"  # seq,status,file_id,process_id,user_id,allowed_ops,byte_quota,expiry,nonce
TOKEN_PACK_FMT = "<QIIIQQ16s"  # without signature


def load_private_key(key_path: Path) -> signing.SigningKey:
    data = key_path.read_bytes()
    if len(data) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes (seed)")
    return signing.SigningKey(data)


def derive_public_key_to_file(signing_key: signing.SigningKey, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(signing_key.verify_key.encode())


def handle_request(data: bytes, signer: signing.SigningKey, ops_mask: int, quota: int, ttl: int) -> bytes:
    if len(data) < struct.calcsize(REQ_FMT):
        return b""
    seq, pid, raw_path = struct.unpack(REQ_FMT, data[: struct.calcsize(REQ_FMT)])
    path = raw_path.split(b"\x00", 1)[0].decode(errors="ignore")

    # Build token
    now = int(time.time())
    expiry = now + ttl
    file_id = struct.unpack("<Q", os.urandom(8))[0]
    uid = os.getuid()
    nonce = secrets.token_bytes(16)
    token_core = struct.pack(TOKEN_PACK_FMT, file_id, pid, uid, ops_mask, quota, expiry, nonce)
    # Enforce PQC USB always
    try:
        if not PQC_AVAILABLE:
            return b""  # PQC required
        dev = None
        if hasattr(pqcdualusb, "list_tokens"):
            tokens = pqcdualusb.list_tokens()
            if tokens:
                dev = tokens[0]
        elif hasattr(pqcdualusb, "get_default_token"):
            dev = pqcdualusb.get_default_token()
        if dev is None:
            return b""  # no PQC device, deny
        pqc_sig = None
        if hasattr(dev, "sign"):
            try:
                pqc_sig = dev.sign(token_core)
            except TypeError:
                pqc_sig = dev.sign(token_core, algorithm="dilithium2")
        elif hasattr(dev, "dilithium_sign"):
            pqc_sig = dev.dilithium_sign(token_core)
        if not pqc_sig:
            return b""  # signing failed
    except Exception:
        return b""  # fail closed if PQC path errors

    signature = signer.sign(token_core).signature

    resp_hdr = struct.pack("<Ii", seq, 0)
    resp_body = struct.pack("<QIIIQQ16s", file_id, pid, uid, ops_mask, quota, expiry, nonce)
    return resp_hdr + resp_body + signature


def main():
    parser = argparse.ArgumentParser(description="Anti-ransomware netlink broker")
    parser.add_argument("--key", type=Path, required=True, help="Path to 32-byte Ed25519 private key seed")
    parser.add_argument("--ttl", type=int, default=300, help="Token lifetime seconds")
    parser.add_argument("--ops", type=int, default=0xFFFFFFFF, help="Allowed ops bitmask")
    parser.add_argument("--quota", type=int, default=1_000_000_000, help="Byte quota")
    args = parser.parse_args()

    signing_key = load_private_key(args.key)
    derive_public_key_to_file(signing_key, Path("./keys/ed25519_public.bin"))

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_USERSOCK)
    sock.bind((os.getpid(), 1))  # pid, groups

    print("[broker] listening on NETLINK_USERSOCK group 1; pid", os.getpid())

    while True:
        data, (nl_pid, nl_groups) = sock.recvfrom(65536)
        if len(data) < 16:
            continue
        nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack("<IHHII", data[:16])
        payload = data[16:nlmsg_len]
        resp_payload = handle_request(payload, signing_key, args.ops, args.quota, args.ttl)
        if not resp_payload:
            continue

        # Build netlink response
        resp = struct.pack(
            "<IHHII",
            16 + len(resp_payload),
            NLMSG_DONE,
            NLM_F_MULTI,
            nlmsg_seq,
            os.getpid(),
        ) + resp_payload
        sock.sendto(resp, (nlmsg_pid, 0))


+if __name__ == "__main__":
+    main()
