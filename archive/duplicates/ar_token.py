#!/usr/bin/env python3
"""
Anti-Ransomware Token System
Comprehensive token format, signing, and verification with Ed25519 and Dilithium support
"""

import os
import struct
import time
import hashlib
from typing import Optional, Tuple, Union
from dataclasses import dataclass, asdict
from enum import IntEnum

# Cryptography imports
import nacl.signing
import nacl.encoding
import nacl.utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Post-Quantum Cryptography (Dilithium)
try:
    import dilithium  # Hypothetical Dilithium implementation
    DILITHIUM_AVAILABLE = True
except ImportError:
    DILITHIUM_AVAILABLE = False
    # Dilithium is optional - system works without it

# Constants
ED25519_SIG_SIZE = 64
ED25519_KEY_SIZE = 32
DILITHIUM_SIG_SIZE = 2420  # CRYSTALS-Dilithium-3
DILITHIUM_KEY_SIZE = 1952
NONCE_SIZE = 16
TOKEN_VERSION = 1

class TokenOps(IntEnum):
    """Token operations flags"""
    READ = 1
    WRITE = 2
    RENAME = 4
    DELETE = 8
    TRUNCATE = 16
    ALL = READ | WRITE | RENAME | DELETE | TRUNCATE

class CryptoAlgorithm(IntEnum):
    """Supported cryptographic algorithms"""
    ED25519 = 1
    DILITHIUM = 2
    HYBRID = 3  # Both Ed25519 and Dilithium

@dataclass
class TokenHeader:
    """Token header with metadata"""
    version: int = TOKEN_VERSION
    algorithm: CryptoAlgorithm = CryptoAlgorithm.ED25519
    token_size: int = 0
    signature_size: int = ED25519_SIG_SIZE
    
    def serialize(self) -> bytes:
        return struct.pack(">I I I I", self.version, self.algorithm, self.token_size, self.signature_size)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'TokenHeader':
        version, algorithm, token_size, signature_size = struct.unpack(">I I I I", data[:16])
        return cls(version, CryptoAlgorithm(algorithm), token_size, signature_size)

@dataclass
class TokenPayload:
    """Token payload with access control information"""
    file_id: str
    pid: int
    user_sid: str
    allowed_ops: TokenOps
    byte_quota: int
    expiry: int  # Unix timestamp
    nonce: bytes
    
    def __post_init__(self):
        if isinstance(self.nonce, str):
            self.nonce = bytes.fromhex(self.nonce)
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")
    
    def serialize(self) -> bytes:
        """Serialize payload for signing"""
        file_id_hash = hashlib.sha256(self.file_id.encode()).digest()[:8]
        user_sid_hash = hashlib.sha256(self.user_sid.encode()).digest()[:4]
        
        return struct.pack(
            ">8s I 4s I Q Q 16s",
            file_id_hash,
            self.pid,
            user_sid_hash,
            self.allowed_ops,
            self.byte_quota,
            self.expiry,
            self.nonce
        )
    
    @classmethod
    def deserialize(cls, data: bytes, file_id: str, user_sid: str) -> 'TokenPayload':
        """Deserialize payload (requires original file_id and user_sid for verification)"""
        _, pid, _, allowed_ops, byte_quota, expiry, nonce = struct.unpack(">8s I 4s I Q Q 16s", data)
        
        return cls(
            file_id=file_id,
            pid=pid,
            user_sid=user_sid,
            allowed_ops=TokenOps(allowed_ops),
            byte_quota=byte_quota,
            expiry=expiry,
            nonce=nonce
        )

class ARToken:
    """Complete token with header, payload, and signatures"""
    
    def __init__(self, payload: TokenPayload, algorithm: CryptoAlgorithm = CryptoAlgorithm.ED25519):
        self.header = TokenHeader(algorithm=algorithm)
        self.payload = payload
        self.ed25519_signature: Optional[bytes] = None
        self.dilithium_signature: Optional[bytes] = None
        
        # Update header based on algorithm
        if algorithm == CryptoAlgorithm.ED25519:
            self.header.signature_size = ED25519_SIG_SIZE
        elif algorithm == CryptoAlgorithm.DILITHIUM:
            self.header.signature_size = DILITHIUM_SIG_SIZE
        elif algorithm == CryptoAlgorithm.HYBRID:
            self.header.signature_size = ED25519_SIG_SIZE + DILITHIUM_SIG_SIZE
    
    def serialize(self) -> bytes:
        """Serialize complete token"""
        payload_data = self.payload.serialize()
        self.header.token_size = len(payload_data)
        
        header_data = self.header.serialize()
        signature_data = b""
        
        if self.ed25519_signature:
            signature_data += self.ed25519_signature
        if self.dilithium_signature:
            signature_data += self.dilithium_signature
        
        return header_data + payload_data + signature_data
    
    @classmethod
    def deserialize(cls, data: bytes, file_id: str, user_sid: str) -> 'ARToken':
        """Deserialize token from bytes"""
        if len(data) < 16:
            raise ValueError("Invalid token data")
        
        header = TokenHeader.deserialize(data[:16])
        payload_end = 16 + (len(data) - 16 - header.signature_size)
        payload_data = data[16:payload_end]
        signature_data = data[payload_end:]
        
        payload = TokenPayload.deserialize(payload_data, file_id, user_sid)
        token = cls(payload, header.algorithm)
        token.header = header
        
        # Extract signatures based on algorithm
        if header.algorithm == CryptoAlgorithm.ED25519:
            token.ed25519_signature = signature_data[:ED25519_SIG_SIZE]
        elif header.algorithm == CryptoAlgorithm.DILITHIUM:
            token.dilithium_signature = signature_data[:DILITHIUM_SIG_SIZE]
        elif header.algorithm == CryptoAlgorithm.HYBRID:
            token.ed25519_signature = signature_data[:ED25519_SIG_SIZE]
            token.dilithium_signature = signature_data[ED25519_SIG_SIZE:ED25519_SIG_SIZE + DILITHIUM_SIG_SIZE]
        
        return token
    
    def is_expired(self) -> bool:
        """Check if token is expired"""
        return time.time() > self.payload.expiry
    
    def is_valid_for_operation(self, operation: TokenOps) -> bool:
        """Check if token allows specific operation"""
        return bool(self.payload.allowed_ops & operation)

class TokenSigner:
    """Token signing with Ed25519 and/or Dilithium"""
    
    def __init__(self):
        self.ed25519_private_key: Optional[Ed25519PrivateKey] = None
        self.ed25519_public_key: Optional[Ed25519PublicKey] = None
        self.dilithium_private_key: Optional[bytes] = None
        self.dilithium_public_key: Optional[bytes] = None
    
    def load_ed25519_keys(self, private_key_path: str, public_key_path: str):
        """Load Ed25519 keys from files"""
        try:
            with open(private_key_path, "rb") as f:
                key_data = f.read()
                if len(key_data) == 32:  # Raw key
                    self.ed25519_private_key = Ed25519PrivateKey.from_private_bytes(key_data)
                else:  # PEM format
                    self.ed25519_private_key = serialization.load_pem_private_key(key_data, password=None)
                    
            self.ed25519_public_key = self.ed25519_private_key.public_key()
            
        except Exception as e:
            raise ValueError(f"Failed to load Ed25519 keys: {e}")
    
    def load_dilithium_keys(self, private_key_path: str, public_key_path: str):
        """Load Dilithium keys from files"""
        if not DILITHIUM_AVAILABLE:
            raise ValueError("Dilithium library not available")
            
        try:
            with open(private_key_path, "rb") as f:
                self.dilithium_private_key = f.read()
            with open(public_key_path, "rb") as f:
                self.dilithium_public_key = f.read()
        except Exception as e:
            raise ValueError(f"Failed to load Dilithium keys: {e}")
    
    def generate_ed25519_keys(self) -> Tuple[bytes, bytes]:
        """Generate new Ed25519 key pair"""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        self.ed25519_private_key = private_key
        self.ed25519_public_key = public_key
        
        return private_bytes, public_bytes
    
    def generate_dilithium_keys(self) -> Tuple[bytes, bytes]:
        """Generate new Dilithium key pair"""
        if not DILITHIUM_AVAILABLE:
            raise ValueError("Dilithium library not available")
            
        # Hypothetical Dilithium key generation
        self.dilithium_private_key, self.dilithium_public_key = dilithium.generate_keypair()
        return self.dilithium_private_key, self.dilithium_public_key
    
    def sign_token(self, token: ARToken) -> ARToken:
        """Sign token with appropriate algorithm(s)"""
        payload_data = token.payload.serialize()
        
        if token.header.algorithm in (CryptoAlgorithm.ED25519, CryptoAlgorithm.HYBRID):
            if not self.ed25519_private_key:
                raise ValueError("Ed25519 private key not loaded")
            token.ed25519_signature = self.ed25519_private_key.sign(payload_data)
        
        if token.header.algorithm in (CryptoAlgorithm.DILITHIUM, CryptoAlgorithm.HYBRID):
            if not self.dilithium_private_key:
                raise ValueError("Dilithium private key not loaded")
            if DILITHIUM_AVAILABLE:
                token.dilithium_signature = dilithium.sign(self.dilithium_private_key, payload_data)
            else:
                raise ValueError("Dilithium library not available")
        
        return token

class TokenVerifier:
    """Token verification with constant-time operations"""
    
    def __init__(self):
        self.ed25519_public_key: Optional[Ed25519PublicKey] = None
        self.dilithium_public_key: Optional[bytes] = None
        self.nonce_cache: set = set()  # Simple nonce tracking (should use proper storage)
    
    def load_ed25519_public_key(self, public_key: Union[bytes, str]):
        """Load Ed25519 public key"""
        if isinstance(public_key, str):
            with open(public_key, "rb") as f:
                key_data = f.read()
        else:
            key_data = public_key
            
        if len(key_data) == 32:  # Raw key
            self.ed25519_public_key = Ed25519PublicKey.from_public_bytes(key_data)
        else:  # PEM format
            self.ed25519_public_key = serialization.load_pem_public_key(key_data)
    
    def load_dilithium_public_key(self, public_key: Union[bytes, str]):
        """Load Dilithium public key"""
        if not DILITHIUM_AVAILABLE:
            raise ValueError("Dilithium library not available")
            
        if isinstance(public_key, str):
            with open(public_key, "rb") as f:
                self.dilithium_public_key = f.read()
        else:
            self.dilithium_public_key = public_key
    
    def verify_token(self, token: ARToken) -> bool:
        """Verify token with constant-time operations"""
        try:
            # Check basic validity
            if token.is_expired():
                return False
            
            # Check nonce for replay protection
            nonce_hex = token.payload.nonce.hex()
            if nonce_hex in self.nonce_cache:
                return False  # Replay attack
            self.nonce_cache.add(nonce_hex)
            
            # Verify signatures
            payload_data = token.payload.serialize()
            
            if token.header.algorithm in (CryptoAlgorithm.ED25519, CryptoAlgorithm.HYBRID):
                if not self.ed25519_public_key or not token.ed25519_signature:
                    return False
                try:
                    self.ed25519_public_key.verify(token.ed25519_signature, payload_data)
                except Exception:
                    return False
            
            if token.header.algorithm in (CryptoAlgorithm.DILITHIUM, CryptoAlgorithm.HYBRID):
                if not self.dilithium_public_key or not token.dilithium_signature:
                    return False
                if DILITHIUM_AVAILABLE:
                    try:
                        if not dilithium.verify(self.dilithium_public_key, token.dilithium_signature, payload_data):
                            return False
                    except Exception:
                        return False
                else:
                    return False
            
            return True
            
        except Exception as e:
            print(f"Token verification error: {e}")
            return False
    
    def cleanup_nonce_cache(self, max_age: int = 3600):
        """Clean up old nonces (should be implemented with proper timestamp tracking)"""
        # This is a simplified implementation
        # In production, use proper timestamp-based cleanup
        if len(self.nonce_cache) > 10000:
            self.nonce_cache.clear()

# Utility functions
def create_token(file_id: str, pid: int, user_sid: str, allowed_ops: TokenOps,
                byte_quota: int = 1024*1024, lifetime_sec: int = 300,
                algorithm: CryptoAlgorithm = CryptoAlgorithm.ED25519) -> ARToken:
    """Create a new token with specified parameters"""
    expiry = int(time.time()) + lifetime_sec
    nonce = os.urandom(NONCE_SIZE)
    
    payload = TokenPayload(
        file_id=file_id,
        pid=pid,
        user_sid=user_sid,
        allowed_ops=allowed_ops,
        byte_quota=byte_quota,
        expiry=expiry,
        nonce=nonce
    )
    
    return ARToken(payload, algorithm)

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0

if __name__ == "__main__":
    # Example usage
    print("Anti-Ransomware Token System")
    
    # Create signer
    signer = TokenSigner()
    ed25519_private, ed25519_public = signer.generate_ed25519_keys()
    print(f"Generated Ed25519 keys: {len(ed25519_private)} bytes private, {len(ed25519_public)} bytes public")
    
    # Create token
    token = create_token(
        file_id="/protected/important.txt",
        pid=1234,
        user_sid="S-1-5-21-123456789-123456789-123456789-1000",
        allowed_ops=TokenOps.READ | TokenOps.WRITE,
        byte_quota=1024*1024,
        lifetime_sec=300
    )
    
    # Sign token
    signed_token = signer.sign_token(token)
    print(f"Token signed with {signed_token.header.algorithm.name}")
    
    # Serialize token
    token_data = signed_token.serialize()
    print(f"Serialized token: {len(token_data)} bytes")
    
    # Verify token
    verifier = TokenVerifier()
    verifier.load_ed25519_public_key(ed25519_public)
    
    # Deserialize and verify
    deserialized_token = ARToken.deserialize(token_data, "/protected/important.txt", "S-1-5-21-123456789-123456789-123456789-1000")
    is_valid = verifier.verify_token(deserialized_token)
    print(f"Token verification: {'VALID' if is_valid else 'INVALID'}")
    
    print(f"Token expires at: {time.ctime(deserialized_token.payload.expiry)}")
    print(f"Token allows operations: {deserialized_token.payload.allowed_ops}")
    print(f"Byte quota: {deserialized_token.payload.byte_quota}")
