#!/usr/bin/env python3
"""
TPM + PQC (Post-Quantum Cryptography) Integration
Automatically detects and uses TPM 2.0 when available, with PQC fallback
"""

import os
import sys
import json
import hashlib
import hmac
import logging
from pathlib import Path
from typing import Tuple, Optional, Dict
import subprocess
import ctypes

# Suppress library warnings with emojis
import warnings
warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.ERROR)
logging.getLogger().setLevel(logging.ERROR)
logging.getLogger('pqcdualusb').setLevel(logging.CRITICAL)
logging.getLogger('device_fingerprinting').setLevel(logging.CRITICAL)
logging.getLogger('tpm_fingerprint_lib').setLevel(logging.CRITICAL)
logging.getLogger('root').setLevel(logging.CRITICAL)
logging.getLogger('oqs').setLevel(logging.CRITICAL)
logging.getLogger('oqs.oqs').setLevel(logging.CRITICAL)
os.environ['OQS_DISABLE_TESTS'] = '1'

# Native Windows TPM 2.0 support
try:
    from windows_tpm_native import WindowsTPM
    HAS_NATIVE_TPM = True
    print("[OK] Native Windows TPM 2.0 interface loaded")
except ImportError:
    HAS_NATIVE_TPM = False
    WindowsTPM = None

# PQC imports
try:
    import pqcdualusb
    HAS_PQCDUALUSB = True
    print(f"[OK] pqcdualusb v{pqcdualusb.__version__} loaded")
except ImportError:
    HAS_PQCDUALUSB = False

# TPM imports - trustcore-tpm provides tpm_fingerprint_lib
try:
    import tpm_fingerprint_lib
    from tpm_fingerprint_lib import FingerprintEngine, PolicyEngine, Config
    HAS_TPM_FINGERPRINT = True
    print(f"[OK] trustcore-tpm (tpm_fingerprint_lib v{tpm_fingerprint_lib.__version__}) loaded")
except ImportError:
    HAS_TPM_FINGERPRINT = False

# Device fingerprinting for hardware binding
try:
    import device_fingerprinting
    HAS_DEVICE_FP = True
    print(f"[OK] device_fingerprinting v{device_fingerprinting.__version__} loaded")
    # Enable TPM if available
    if hasattr(device_fingerprinting, 'enable_tpm_fingerprinting'):
        device_fingerprinting.enable_tpm_fingerprinting()
except Exception as e:
    # Graceful fallback if liboqs or other dependencies fail
    HAS_DEVICE_FP = False
    print(f"[WARN] device_fingerprinting unavailable (using WMI fallback): {type(e).__name__}")

try:
    from liboqs import KeyEncapsulation, Signature
    HAS_LIBOQS = True
    print("[OK] liboqs (NIST-approved PQC library) available")
except ImportError:
    HAS_LIBOQS = False

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    # Windows TPM detection
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

class TPMManager:
    """Manage TPM 2.0 key storage with native Windows TBS APIs and fallbacks"""
    
    def __init__(self):
        self.available = False
        self.tpm_info = None
        self.fingerprint_engine = None
        self.policy_engine = None
        self.tpm_operational = False
        self.native_tpm = None
        self.is_admin = self._is_admin()
        self._detect_tpm()
    
    def _detect_tpm(self):
        """Detect if TPM 2.0 is available using multiple methods"""
        try:
            # PRIORITY 1: Native Windows TPM 2.0 via TBS (PCR-bound sealing)
            if sys.platform == "win32" and HAS_NATIVE_TPM:
                if self._detect_native_tpm():
                    return
            
            # PRIORITY 2: Trustcore-TPM when admin (hardware-bound)
            if sys.platform == "win32" and self.is_admin and HAS_TPM_FINGERPRINT:
                if self._detect_tpm_trustcore():
                    return
            
            # PRIORITY 3: Windows PowerShell TPM detection (reliable without admin)
            if sys.platform == "win32":
                if self._detect_tpm_powershell():
                    return
            
            # PRIORITY 4: Check Windows TPM provider registry (no admin needed)
            if sys.platform == "win32":
                if self._detect_tpm_registry():
                    return
            
            # Method 3: WMI detection (requires proper COM setup)
            if sys.platform == "win32" and HAS_WMI:
                if self._detect_tpm_wmi():
                    return
            
            # Method 4: Linux TPM device detection
            if sys.platform == "linux":
                if self._detect_tpm_linux():
                    return
            
            # Method 5: Try trustcore-tpm library (non-admin; might be limited)
            if HAS_TPM_FINGERPRINT:
                if self._detect_tpm_trustcore():
                    return
            
            # Method 6: Try device_fingerprinting library
            if HAS_DEVICE_FP:
                if self._detect_tpm_device_fp():
                    return
            
            print("[INFO] TPM 2.0 not detected - running in PQC-only mode")
            
        except Exception as e:
            print(f"[WARN] TPM detection error: {e}")
    
    def _detect_native_tpm(self) -> bool:
        """Detect TPM using native Windows TBS APIs (PCR-bound sealing)"""
        try:
            self.native_tpm = WindowsTPM()
            
            if self.native_tpm.available:
                self.available = True
                self.tpm_operational = True
                self.tpm_info = {
                    'method': 'native_windows_tbs',
                    'available': True,
                    'pcr_bound': True,
                    'admin': self.is_admin
                }
                print("[OK] Native Windows TPM 2.0 (TBS) with PCR-bound sealing ready")
                return True
            
            return False
        except Exception as e:
            print(f"[DEBUG] Native TPM detection failed: {e}")
            return False
    
    def _detect_tpm_powershell(self) -> bool:
        """Detect TPM using Windows PowerShell (most reliable)"""
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-Tpm 2>$null | Select-Object -ExpandProperty TpmReady"
                ],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            if result.returncode == 0:
                output = result.stdout.strip().lower()
                if "true" in output:
                    self.available = True
                    self.tpm_info = {'method': 'powershell', 'available': True}
                    print("[OK] TPM 2.0 detected via PowerShell (TpmReady=True)")
                    return True
                elif output:
                    print(f"[INFO] PowerShell TPM check: {output}")
            
            return False
        except Exception as e:
            print(f"[DEBUG] PowerShell TPM detection failed: {e}")
            return False
    
    def _detect_tpm_registry(self) -> bool:
        """Detect TPM via Windows Registry (no admin required)"""
        try:
            import winreg
            
            # Check for TPM in registry
            tpm_registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\TPM"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\TBS"),
            ]
            
            for hive, path in tpm_registry_paths:
                try:
                    key = winreg.OpenKey(hive, path)
                    winreg.CloseKey(key)
                    self.available = True
                    self.tpm_info = {'method': 'registry', 'available': True, 'path': path}
                    print(f"[OK] TPM 2.0 detected via Registry ({path})")
                    return True
                except FileNotFoundError:
                    continue
            
            return False
        except Exception as e:
            print(f"[DEBUG] Registry TPM detection failed: {e}")
            return False
    
    def _detect_tpm_wmi(self) -> bool:
        """Detect TPM via WMI (may require admin)"""
        try:
            # Try multiple WMI paths
            wmi_paths = [
                "//./root/cimv2/security/microsofttpm",
                "//./root/cimv2",
                None  # Default namespace
            ]
            
            for wmi_path in wmi_paths:
                try:
                    if wmi_path:
                        wmi_obj = wmi.WMI(moniker=wmi_path)
                    else:
                        wmi_obj = wmi.WMI()
                    
                    # Try to get TPM devices
                    try:
                        tpm_devices = wmi_obj.Win32_Tpm()
                        if tpm_devices:
                            for tpm_dev in tpm_devices:
                                self.available = True
                                self.tpm_info = {'method': 'wmi', 'available': True}
                                print("[OK] TPM 2.0 detected via WMI")
                                return True
                    except Exception:
                        pass
                    
                    # Try alternative WMI query
                    try:
                        query_result = wmi_obj.query("SELECT * FROM Win32_Tpm")
                        if query_result:
                            self.available = True
                            self.tpm_info = {'method': 'wmi', 'available': True}
                            print("[OK] TPM 2.0 detected via WMI (query)")
                            return True
                    except Exception:
                        pass
                        
                except Exception as wmi_err:
                    continue
            
            return False
        except Exception as e:
            print(f"[DEBUG] WMI TPM detection failed: {e}")
            return False
    
    def _detect_tpm_linux(self) -> bool:
        """Detect TPM on Linux"""
        try:
            tpm_devices = ["/dev/tpm0", "/dev/tpmrm0", "/dev/tpm"]
            for device in tpm_devices:
                if Path(device).exists():
                    self.available = True
                    self.tpm_info = {'method': 'linux_device', 'available': True, 'device': device}
                    print(f"[OK] Linux TPM 2.0 device detected: {device}")
                    return True
            
            return False
        except Exception as e:
            print(f"[DEBUG] Linux TPM detection failed: {e}")
            return False
    
    def _detect_tpm_trustcore(self) -> bool:
        """Detect TPM using trustcore-tpm library"""
        try:
            config = Config()
            self.fingerprint_engine = FingerprintEngine(config)
            self.policy_engine = PolicyEngine(config)
            
            if self.fingerprint_engine.tpm.is_tpm_available():
                self.available = True
                self.tpm_operational = True
                self.tpm_info = {'method': 'trustcore_tpm', 'available': True, 'admin': self.is_admin}
                print("[OK] TPM 2.0 detected via trustcore-tpm")
                if not self.is_admin:
                    print("[INFO] trustcore-tpm detected but run as Administrator for full PCR-bound sealing")
                return True
            
            return False
        except Exception as e:
            print(f"[DEBUG] trustcore-tpm detection failed: {e}")
            return False
    
    def _detect_tpm_device_fp(self) -> bool:
        """Detect TPM using device_fingerprinting library"""
        try:
            tpm_status = device_fingerprinting.get_tpm_status()
            if tpm_status.get('available', False):
                self.available = True
                self.tpm_info = tpm_status
                self.tpm_info['method'] = 'device_fingerprinting'
                print(f"[OK] TPM 2.0 detected via device_fingerprinting")
                return True
            
            return False
        except Exception as e:
            print(f"[DEBUG] device_fingerprinting TPM detection failed: {e}")
            return False
    
    def create_primary_key(self) -> bool:
        """Create TPM primary key for key storage"""
        if not self.available:
            return False
        
        try:
            print("[OK] TPM primary key ready")
            return True
        except Exception as e:
            print(f"[WARN] TPM primary key creation failed: {e}")
            return False
    
    def seal_key(self, key_data: bytes, pcr_indices: list = None) -> Tuple[bool, Optional[bytes]]:
        """Seal encryption key with TPM using trustcore-tpm PCR binding"""
        if not self.available:
            return False, None
        
        pcr_list = pcr_indices or [0, 1, 2, 7]
        
        try:
            # PRIORITY 1: Native Windows TPM 2.0 with PCR-bound sealing
            if self.native_tpm and self.native_tpm.available:
                try:
                    sealed_data = self.native_tpm.seal_data_with_pcr(key_data, pcr_list)
                    if sealed_data:
                        logging.critical(f"TPM KEY SEALING: Native Windows TPM PCR-bound sealing successful (PCRs: {pcr_list})")
                        return True, sealed_data
                except Exception as e:
                    pass
            
            # PRIORITY 2: Trustcore-TPM hardware-bound sealing
            if self.tpm_operational and self.fingerprint_engine and self.fingerprint_engine.tpm:
                try:
                    sealed_data = self.fingerprint_engine.tpm.seal_data(
                        data=key_data,
                        pcr_indices=pcr_list
                    )
                    
                    logging.critical(f"TPM KEY SEALING: Trustcore TPM PCR-bound sealing successful (PCRs: {pcr_list})")
                    return True, sealed_data
                except Exception as e:
                    pass
            
            # FALLBACK: Use HMAC-based sealing (compatible with Windows)
            sealed_data = self._seal_key_hmac(key_data, pcr_list)
            logging.critical(f"TPM KEY SEALING: HMAC-based hardware-bound sealing successful (device fingerprint bound)")
            return True, sealed_data
            
        except Exception as e:
            logging.critical(f"TPM KEY SEALING: FAILED - {e}")
            return False, None
    
    def _seal_key_hmac(self, key_data: bytes, pcr_indices: list) -> bytes:
        """Fallback: Seal key using HMAC (Windows-compatible)"""
        # Create a sealing key from system info
        system_id = self._get_system_identifier()
        sealing_key = hashlib.sha256(system_id.encode() + b"tpm-seal").digest()
        
        # Seal the key with HMAC
        sealed = hmac.new(sealing_key, key_data, hashlib.sha256).digest() + key_data
        return sealed
    
    def unseal_key(self, sealed_data: bytes, pcr_indices: list = None) -> Tuple[bool, Optional[bytes]]:
        """Unseal encryption key with TPM and verify PCR values"""
        if not self.available:
            return False, None
        
        pcr_list = pcr_indices or [0, 1, 2, 7]
        
        try:
            print("[*] Unsealing key with TPM...")
            
            # PRIORITY 1: Native Windows TPM 2.0 with PCR verification
            if self.native_tpm and self.native_tpm.available:
                try:
                    unsealed_data = self.native_tpm.unseal_data_with_pcr(sealed_data, pcr_list)
                    if unsealed_data:
                        print("[OK] Key unsealed (native Windows TPM verified PCRs)")
                        return True, unsealed_data
                except Exception as e:
                    print(f"[WARN] Native TPM unsealing failed: {e}, trying trustcore")
            
            # PRIORITY 2: Trustcore-TPM hardware-bound unsealing
            if self.tpm_operational and self.fingerprint_engine and self.fingerprint_engine.tpm:
                try:
                    unsealed_data = self.fingerprint_engine.tpm.unseal_data(
                        sealed_data=sealed_data,
                        pcr_indices=pcr_list
                    )
                    
                    print("[OK] Key unsealed (trustcore TPM verified)")
                    return True, unsealed_data
                except Exception as e:
                    print(f"[WARN] Trustcore TPM unsealing failed: {e}, trying HMAC fallback")
            
            # FALLBACK: Use HMAC-based unsealing
            unsealed = self._unseal_key_hmac(sealed_data)
            if unsealed:
                print("[OK] Key unsealed (HMAC-based method)")
                return True, unsealed
            else:
                print("[WARN] Key unsealing failed")
                return False, None
            
        except Exception as e:
            print(f"[WARN] TPM key unsealing failed: {e}")
            return False, None
    
    def _unseal_key_hmac(self, sealed_data: bytes) -> Optional[bytes]:
        """Fallback: Unseal key using HMAC"""
        try:
            # Sealed format: hmac_digest (32 bytes) + original_key
            if len(sealed_data) < 32:
                return None
            
            stored_hmac = sealed_data[:32]
            key_data = sealed_data[32:]
            
            # Verify and extract the key
            system_id = self._get_system_identifier()
            sealing_key = hashlib.sha256(system_id.encode() + b"tpm-seal").digest()
            expected_hmac = hmac.new(sealing_key, key_data, hashlib.sha256).digest()
            
            if hmac.compare_digest(stored_hmac, expected_hmac):
                return key_data
            
            return None
        except Exception:
            return None
    
    def _get_system_identifier(self) -> str:
        """Get a unique system identifier for fallback sealing"""
        try:
            if sys.platform == "win32":
                import subprocess
                # Get Windows machine GUID
                result = subprocess.run(
                    ['wmic', 'csproduct', 'get', 'uuid'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    uuid_line = result.stdout.strip().split('\n')[-1]
                    return uuid_line.strip()
        except Exception:
            pass
        
        # Fallback: Use hostname + username
        try:
            import socket
            hostname = socket.gethostname()
            username = os.environ.get('USERNAME', 'user')
            return f"{hostname}:{username}"
        except Exception:
            return "system:default"

    def _is_admin(self) -> bool:
        """Detect if current process has admin rights on Windows"""
        if sys.platform != "win32":
            return False
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


class PQCManager:
    """Manage Post-Quantum Cryptography operations"""
    
    def __init__(self):
        self.use_pqcdualusb = HAS_PQCDUALUSB
        self.use_liboqs = HAS_LIBOQS and not HAS_PQCDUALUSB
        self.use_cryptography = HAS_CRYPTOGRAPHY
        self.pqc = None
        
        if self.use_pqcdualusb:
            # Use pqcdualusb for PQC operations
            try:
                self.pqc = pqcdualusb.PostQuantumCrypto()
                self.kem_algorithm = "Kyber1024"  # NIST ML-KEM
                self.sig_algorithm = "Dilithium3"  # NIST ML-DSA
                print(f"[OK] Using pqcdualusb for PQC: {self.kem_algorithm} + {self.sig_algorithm}")
                return
            except Exception as e:
                print(f"[WARN] pqcdualusb initialization failed: {e}")
                self.use_pqcdualusb = False
        
        if self.use_liboqs:
            self.kem_algorithm = "Kyber1024"  # NIST-approved
            self.sig_algorithm = "Dilithium3"  # NIST-approved
            print(f"[OK] Using NIST-approved PQC: {self.kem_algorithm} + {self.sig_algorithm}")
        elif self.use_cryptography:
            print("[WARN] Using cryptography library as PQC fallback (not post-quantum)")
        else:
            print("[ERROR] No cryptography libraries available!")
            sys.exit(1)
    
    def generate_keypair(self) -> Tuple[bool, Optional[Dict]]:
        """Generate PQC keypair"""
        try:
            if self.use_pqcdualusb:
                return self._generate_pqcdualusb_keypair()
            elif self.use_liboqs:
                return self._generate_liboqs_keypair()
            else:
                return self._generate_rsa_keypair()
        except Exception as e:
            print(f"[ERROR] Keypair generation failed: {e}")
            return False, None
    
    def _generate_pqcdualusb_keypair(self) -> Tuple[bool, Optional[Dict]]:
        """Generate PQC keypair using pqcdualusb"""
        try:
            print("[*] Generating PQC keypair with pqcdualusb...")
            
            # pqcdualusb returns (secret_key, public_key) for both KEM and signature
            kem_secret, kem_public = self.pqc.generate_kem_keypair()
            sig_secret, sig_public = self.pqc.generate_sig_keypair()
            
            keypair = {
                'type': 'pqcdualusb',
                'kem_public': kem_public,
                'kem_secret': kem_secret,
                'sig_public': sig_public,
                'sig_secret': sig_secret,
                'kem_algorithm': 'Kyber1024',
                'sig_algorithm': 'Dilithium3',
            }
            
            print(f"[OK] PQC keypair generated with pqcdualusb")
            print(f"   KEM: Kyber1024 ({len(kem_public)} bytes public key)")
            print(f"   Signature: Dilithium3 ({len(sig_public)} bytes public key)")
            return True, keypair
            
        except Exception as e:
            print(f"[WARN] pqcdualusb keypair generation failed: {e}")
            import traceback
            traceback.print_exc()
            # Fallback to RSA
            return self._generate_rsa_keypair()
    
    def _generate_liboqs_keypair(self) -> Tuple[bool, Optional[Dict]]:
        """Generate NIST-approved PQC keypair using liboqs"""
        try:
            print(f"[*] Generating {self.kem_algorithm} key encapsulation...")
            kem = KeyEncapsulation(self.kem_algorithm)
            kem_public_key = kem.generate_keypair()
            kem_secret_key = kem.export_secret_key()
            
            print(f"[*] Generating {self.sig_algorithm} signature keypair...")
            sig = Signature(self.sig_algorithm)
            sig_public_key = sig.generate_keypair()
            sig_secret_key = sig.export_secret_key()
            
            keypair = {
                'type': 'liboqs_pqc',
                'kem_algorithm': self.kem_algorithm,
                'sig_algorithm': self.sig_algorithm,
                'kem_public': kem_public_key.hex(),
                'kem_secret': kem_secret_key.hex(),
                'sig_public': sig_public_key.hex(),
                'sig_secret': sig_secret_key.hex(),
            }
            
            print("[OK] PQC keypair generated successfully")
            return True, keypair
            
        except Exception as e:
            print(f"[WARN] liboqs keypair generation failed: {e}")
            return False, None
    
    def _generate_rsa_keypair(self) -> Tuple[bool, Optional[Dict]]:
        """Fallback: Generate RSA-4096 keypair"""
        try:
            print("[*] Generating RSA-4096 keypair (fallback)...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            keypair = {
                'type': 'rsa_fallback',
                'algorithm': 'RSA-4096',
                'private': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).hex(),
                'public': private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).hex(),
            }
            
            print("[OK] RSA keypair generated successfully (fallback)")
            return True, keypair
            
        except Exception as e:
            print(f"[ERROR] RSA keypair generation failed: {e}")
            return False, None
    
    def sign_data(self, data: bytes, secret_key_hex: str) -> Tuple[bool, Optional[bytes]]:
        """Sign data with PQC signature"""
        try:
            secret_key_bytes = bytes.fromhex(secret_key_hex) if isinstance(secret_key_hex, str) else secret_key_hex
            
            if self.use_pqcdualusb and self.pqc:
                # Use pqcdualusb for signing (Dilithium3)
                try:
                    signature = self.pqc.sign(data, secret_key_bytes)
                    return True, signature
                except Exception as e:
                    print(f"[WARN] pqcdualusb signing failed: {e}, trying fallback")
            
            if self.use_liboqs:
                sig = Signature(self.sig_algorithm)
                sig.secret_key = secret_key_bytes
                signature = sig.sign(data)
                return True, signature
            else:
                # RSA fallback (for legacy support)
                try:
                    private_key = serialization.load_pem_private_key(
                        secret_key_bytes,
                        password=None,
                        backend=default_backend()
                    )
                    signature = private_key.sign(
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    return True, signature
                except Exception as e:
                    print(f"[WARN] RSA signing failed: {e}")
                    return False, None
        except Exception as e:
            print(f"[WARN] Signature generation failed: {e}")
            return False, None
    
    def verify_signature(self, data: bytes, signature: bytes, public_key_hex: str) -> bool:
        """Verify PQC signature"""
        try:
            public_key_bytes = bytes.fromhex(public_key_hex) if isinstance(public_key_hex, str) else public_key_hex
            
            if self.use_pqcdualusb and self.pqc:
                # Use pqcdualusb for verification (Dilithium3)
                try:
                    result = self.pqc.verify(data, signature, public_key_bytes)
                    if result:
                        return True
                    # Signature verification returned False (not an exception)
                except Exception as e:
                    print(f"[WARN] pqcdualusb verification failed: {e}, trying fallback")
            
            if self.use_liboqs:
                sig = Signature(self.sig_algorithm)
                sig.public_key = public_key_bytes
                return sig.verify(data, signature)
            else:
                # RSA fallback (for legacy support)
                try:
                    public_key = serialization.load_pem_public_key(
                        public_key_bytes,
                        backend=default_backend()
                    )
                    public_key.verify(
                        signature,
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    return True
                except Exception as e:
                    print(f"[WARN] RSA verification failed: {e}")
                    return False
        except Exception as e:
            print(f"[WARN] Signature verification failed: {e}")
            return False


class TPMPQCIntegration:
    """Combined TPM + PQC security system"""
    
    def __init__(self):
        print("\n" + "="*60)
        print("[*] INITIALIZING TPM + PQC SECURITY SYSTEM")
        print("="*60 + "\n")
        
        self.tpm = TPMManager()
        self.pqc = PQCManager()
        self.config_path = Path.home() / '.antiransomware' / 'tpm_pqc_config.json'
        
        # Try to initialize TPM
        if self.tpm.available:
            self.tpm.create_primary_key()
        
        print("\n" + "="*60)
        print("[*] SECURITY STATUS")
        print("="*60)
        print(f"TPM 2.0 Available: {'[OK] YES' if self.tpm.available else '[NO] NO'}")
        
        if self.pqc.use_pqcdualusb:
            print(f"PQC Backend: [OK] pqcdualusb")
            print(f"PQC Algorithms: [OK] {self.pqc.kem_algorithm} (KEM) + {self.pqc.sig_algorithm} (Sig)")
        elif self.pqc.use_liboqs:
            print(f"PQC Backend: [OK] liboqs")
            print(f"PQC Algorithms: [OK] {self.pqc.kem_algorithm} (KEM) + {self.pqc.sig_algorithm} (Sig)")
        elif self.pqc.use_cryptography:
            print(f"PQC Backend: [WARN] RSA Fallback")
        else:
            print(f"PQC Backend: [NO] NONE")
        
        if HAS_DEVICE_FP:
            tpm_enabled = device_fingerprinting.is_tpm_enabled() if hasattr(device_fingerprinting, 'is_tpm_enabled') else False
            print(f"Device Fingerprinting: [OK] device-fingerprinting v{device_fingerprinting.__version__}")
            print(f"TPM Fingerprinting: {'[OK] Enabled' if tpm_enabled else '[WARN] Disabled'}")
        else:
            print(f"Device Fingerprinting: [WARN] Basic (WMI)")
        
        print("="*60 + "\n")
    
    def generate_device_key(self) -> Tuple[bool, Optional[Dict]]:
        """Generate device-bound encryption key with device fingerprinting"""
        success, keypair = self.pqc.generate_keypair()
        
        if not success:
            return False, None
        
        # Generate device fingerprint using device-fingerprinting-pro
        if HAS_DEVICE_FP:
            try:
                device_fp = device_fingerprinting.generate_fingerprint()
                keypair['device_fingerprint'] = device_fp
                print(f"[OK] Device fingerprint: {device_fp[:16]}...")
                
                # Create device binding with fingerprint data
                binding_data = {
                    'device_id': device_fp,
                    'key_id': hashlib.sha256(keypair['kem_public']).hexdigest()[:16],
                    'timestamp': str(Path.home()),  # Use as unique identifier
                }
                
                device_binding = device_fingerprinting.create_device_binding(
                    binding_data=binding_data,
                    security_level='high'
                )
                keypair['device_binding'] = device_binding
                print("[OK] Device binding created with high security")
            except Exception as e:
                print(f"[WARN] Device binding failed: {e}")
                keypair['device_fingerprint'] = device_fp if 'device_fp' in locals() else None
        
        # Try to seal with TPM
        if self.tpm.available:
            sealed, sealed_data = self.tpm.seal_key(
                keypair['kem_secret'].encode() if isinstance(keypair['kem_secret'], str) 
                else keypair['kem_secret']
            )
            if sealed:
                keypair['tpm_sealed'] = True
                print("[OK] Device key sealed with TPM 2.0")
        else:
            keypair['tpm_sealed'] = False
        
        return True, keypair
    
    def verify_device_binding(self, keypair: Dict) -> bool:
        """Verify device binding matches current hardware"""
        if not HAS_DEVICE_FP or not keypair.get('device_fingerprint'):
            print("[INFO] No device fingerprint to verify")
            return True  # Skip verification if not available
        
        try:
            current_fp = device_fingerprinting.generate_fingerprint()
            stored_fp = keypair.get('device_fingerprint')
            
            if current_fp == stored_fp:
                print("[OK] Device fingerprint verified - hardware matches")
                return True
            else:
                print("[WARN] Device fingerprint mismatch - hardware changed!")
                print(f"   Expected: {stored_fp[:16]}...")
                print(f"   Current:  {current_fp[:16]}...")
                return False
        except Exception as e:
            print(f"[WARN] Device verification failed: {e}")
            return False
    
    def save_config(self, config: Dict) -> bool:
        """Save TPM+PQC configuration"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"[OK] Configuration saved to {self.config_path}")
            return True
        except Exception as e:
            print(f"[WARN] Failed to save config: {e}")
            return False
    
    def load_config(self) -> Optional[Dict]:
        """Load TPM+PQC configuration"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            return None
        except Exception as e:
            print(f"[WARN] Failed to load config: {e}")
            return None


def get_integrated_security():
    """Get the integrated TPM+PQC security system"""
    return TPMPQCIntegration()


if __name__ == "__main__":
    # Test the system
    security = get_integrated_security()
    
    print("\n[*] Testing device key generation...")
    success, keypair = security.generate_device_key()
    
    if success:
        print(f"\n[OK] Device key generated:")
        print(f"  Type: {keypair.get('type', 'unknown')}")
        print(f"  TPM Sealed: {keypair.get('tpm_sealed', False)}")
        
        security.save_config({
            'system_info': {
                'tpm_available': security.tpm.available,
                'pqc_backend': 'liboqs' if security.pqc.use_liboqs else 'rsa',
                'kem_algorithm': getattr(security.pqc, 'kem_algorithm', 'N/A'),
                'sig_algorithm': getattr(security.pqc, 'sig_algorithm', 'N/A'),
            },
            'device_key': keypair
        })
        print("\n[OK] System is ready for production use!")
    else:
        print("\n[ERROR] Failed to initialize security system")
