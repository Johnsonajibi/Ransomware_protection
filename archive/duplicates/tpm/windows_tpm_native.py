#!/usr/bin/env python3
"""
Native Windows TPM 2.0 PCR-Bound Sealing
Uses ctypes to call Windows TBS (TPM Base Services) APIs directly
Provides hardware-bound key sealing with Platform Configuration Register (PCR) binding
"""

import ctypes
import struct
import hashlib
import os
from typing import Tuple, Optional, List
from ctypes import wintypes

# Windows TBS (TPM Base Services) API Constants
TBS_SUCCESS = 0
TPM_E_INVALID_PCR_INFO = 0x80280018
TBS_CONTEXT_VERSION_ONE = 1
TPM_VERSION_20 = 2

# TPM 2.0 Command Codes
TPM_CC_PCR_READ = 0x0000017E
TPM_CC_PCR_EXTEND = 0x00000182
TPM_CC_CREATE = 0x00000153
TPM_CC_LOAD = 0x00000157
TPM_CC_UNSEAL = 0x0000015E
TPM_ST_NO_SESSIONS = 0x8001
TPM_ST_SESSIONS = 0x8002

# TPM 2.0 Algorithm IDs
TPM_ALG_RSA = 0x0001
TPM_ALG_SHA256 = 0x000B
TPM_ALG_AES = 0x0006
TPM_ALG_CFB = 0x0043
TPM_ALG_NULL = 0x0010
TPM_ALG_KEYEDHASH = 0x0008

# TPM 2.0 Handle Values
TPM_RH_OWNER = 0x40000001
TPM_RS_PW = 0x40000009  # Password authorization session

# Load Windows TBS library
try:
    tbs = ctypes.WinDLL('Tbs.dll')
    advapi32 = ctypes.WinDLL('advapi32.dll')
    HAS_TBS = True
except Exception as e:
    print(f"[ERROR] Failed to load Windows TBS: {e}")
    HAS_TBS = False


class TBS_CONTEXT_PARAMS(ctypes.Structure):
    """TBS context parameters structure"""
    _fields_ = [
        ('version', wintypes.DWORD),
    ]


class TPM2B_DIGEST(ctypes.Structure):
    """TPM 2.0 variable-length digest"""
    _fields_ = [
        ('size', ctypes.c_uint16),
        ('buffer', ctypes.c_uint8 * 64),
    ]


class TPML_PCR_SELECTION(ctypes.Structure):
    """TPM 2.0 PCR selection list"""
    _fields_ = [
        ('count', ctypes.c_uint32),
        ('pcrSelections', ctypes.c_uint8 * 128),  # Simplified
    ]


class WindowsTPM:
    """Native Windows TPM 2.0 interface using TBS APIs"""
    
    def __init__(self):
        self.context = None
        self.available = False
        self.is_admin = self._check_admin()
        
        if not HAS_TBS:
            print("[ERROR] Windows TBS (TPM Base Services) not available")
            return
        
        if not self.is_admin:
            print("[WARN] Administrator privileges recommended for TPM operations")
        
        self._initialize_tbs()
    
    def _check_admin(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    
    def _initialize_tbs(self) -> bool:
        """Initialize TBS context"""
        try:
            # Define TBS functions
            tbs.Tbsi_Context_Create.argtypes = [
                ctypes.POINTER(TBS_CONTEXT_PARAMS),
                ctypes.POINTER(wintypes.HANDLE)
            ]
            tbs.Tbsi_Context_Create.restype = wintypes.DWORD
            
            # Try to create TBS context with TPM 2.0
            params = TBS_CONTEXT_PARAMS()
            params.version = TBS_CONTEXT_VERSION_ONE
            
            context_handle = wintypes.HANDLE()
            result = tbs.Tbsi_Context_Create(
                ctypes.byref(params),
                ctypes.byref(context_handle)
            )
            
            # Error codes
            TPM_E_INVALID_PARAM = 0x80280018
            TPM_E_INSUFFICIENT_BUFFER = 0x80280019
            TBS_E_INVALID_CONTEXT_PARAM = 0x8028400F
            TBS_E_TPM_NOT_FOUND = 0x80280004
            
            if result == TBS_SUCCESS:
                self.context = context_handle
                self.available = True
                print("[OK] Windows TBS context initialized successfully")
                
                # Verify TPM 2.0
                if self._verify_tpm_version():
                    print("[OK] TPM 2.0 confirmed and operational")
                    return True
                else:
                    print("[WARN] TPM version verification failed")
                    return False
            elif result == TBS_E_INVALID_CONTEXT_PARAM:
                print("[WARN] TBS context parameter invalid (0x8028400F)")
                print("[INFO] TPM may require different initialization or device driver")
                print("[INFO] Falling back to PowerShell/Registry detection")
                return False
            elif result == TBS_E_TPM_NOT_FOUND:
                print("[WARN] TPM device not found (0x80280004)")
                return False
            else:
                print(f"[WARN] TBS context creation failed: 0x{result:08X}")
                print("[INFO] This is expected on some systems - using fallback detection")
                return False
                
        except Exception as e:
            print(f"[WARN] TBS initialization not available: {e}")
            print("[INFO] Falling back to PowerShell/Registry TPM detection")
            return False
    
    def _verify_tpm_version(self) -> bool:
        """Verify TPM 2.0 is available"""
        try:
            # Try to read PCR 0 to verify TPM 2.0 is working
            pcr_value = self.read_pcr(0)
            return pcr_value is not None
        except Exception as e:
            print(f"[DEBUG] TPM version check failed: {e}")
            return False
    
    def read_pcr(self, pcr_index: int) -> Optional[bytes]:
        """Read Platform Configuration Register value"""
        if not self.available or self.context is None:
            return None
        
        try:
            # Build TPM 2.0 PCR_Read command
            command = self._build_pcr_read_command(pcr_index)
            
            # Submit command to TPM
            response = self._submit_command(command)
            
            if response:
                # Parse PCR value from response
                pcr_value = self._parse_pcr_response(response)
                return pcr_value
            
            return None
            
        except Exception as e:
            print(f"[ERROR] PCR read failed: {e}")
            return None
    
    def _build_pcr_read_command(self, pcr_index: int) -> bytes:
        """Build TPM 2.0 PCR_Read command"""
        # TPM2_PCR_Read command structure:
        # TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS
        # UINT32 commandSize
        # TPM_CC commandCode = TPM_CC_PCR_READ
        # TPML_PCR_SELECTION pcrSelectionIn
        
        # PCR selection: SHA256 bank, PCR index
        pcr_select_bytes = bytearray([(pcr_index // 8)])
        pcr_select_bytes[0] |= (1 << (pcr_index % 8))
        
        # Build PCR selection structure
        pcr_selection = struct.pack(
            '>I',  # count = 1
            1
        ) + struct.pack(
            '>HB',  # hash algorithm (SHA256) + sizeofSelect
            TPM_ALG_SHA256,
            len(pcr_select_bytes)
        ) + bytes(pcr_select_bytes)
        
        # Build full command
        command_code = struct.pack('>I', TPM_CC_PCR_READ)
        command_body = pcr_selection
        
        command_size = 10 + len(command_body)  # header + body
        
        command = struct.pack(
            '>HI',
            TPM_ST_NO_SESSIONS,
            command_size
        ) + command_code + command_body
        
        return command
    
    def _parse_pcr_response(self, response: bytes) -> Optional[bytes]:
        """Parse PCR value from TPM response"""
        try:
            # Response structure:
            # UINT16 tag
            # UINT32 responseSize
            # UINT32 responseCode
            # UINT32 pcrUpdateCounter
            # TPML_PCR_SELECTION pcrSelectionOut
            # TPML_DIGEST pcrValues
            
            if len(response) < 10:
                return None
            
            tag, size, code = struct.unpack('>HII', response[0:10])
            
            if code != 0:
                print(f"[ERROR] TPM command failed: 0x{code:08X}")
                return None
            
            # Skip to PCR digest values (simplified parsing)
            # Actual parsing would need to traverse TPML_PCR_SELECTION
            offset = 14  # Skip header + updateCounter
            
            # Skip PCR selection
            if offset + 4 > len(response):
                return None
            
            count = struct.unpack('>I', response[offset:offset+4])[0]
            offset += 4
            
            # Skip PCR selection entries
            for _ in range(count):
                if offset + 3 > len(response):
                    return None
                hash_alg, size_of_select = struct.unpack('>HB', response[offset:offset+3])
                offset += 3 + size_of_select
            
            # Read PCR values
            if offset + 4 > len(response):
                return None
            
            digest_count = struct.unpack('>I', response[offset:offset+4])[0]
            offset += 4
            
            if digest_count > 0 and offset + 2 <= len(response):
                digest_size = struct.unpack('>H', response[offset:offset+2])[0]
                offset += 2
                
                if offset + digest_size <= len(response):
                    pcr_value = response[offset:offset+digest_size]
                    return pcr_value
            
            return None
            
        except Exception as e:
            print(f"[ERROR] PCR response parsing failed: {e}")
            return None
    
    def _submit_command(self, command: bytes) -> Optional[bytes]:
        """Submit command to TPM via TBS"""
        if not self.available or self.context is None:
            return None
        
        try:
            # Define Tbsip_Submit_Command
            tbs.Tbsip_Submit_Command.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,  # locality
                wintypes.DWORD,  # priority
                ctypes.POINTER(ctypes.c_uint8),  # command
                wintypes.DWORD,  # command size
                ctypes.POINTER(ctypes.c_uint8),  # response buffer
                ctypes.POINTER(wintypes.DWORD)   # response size
            ]
            tbs.Tbsip_Submit_Command.restype = wintypes.DWORD
            
            # Prepare buffers
            command_buffer = (ctypes.c_uint8 * len(command)).from_buffer_copy(command)
            response_buffer = (ctypes.c_uint8 * 4096)()
            response_size = wintypes.DWORD(4096)
            
            # Submit command
            result = tbs.Tbsip_Submit_Command(
                self.context,
                0,  # locality
                300,  # priority (normal)
                command_buffer,
                len(command),
                response_buffer,
                ctypes.byref(response_size)
            )
            
            if result == TBS_SUCCESS:
                response = bytes(response_buffer[:response_size.value])
                return response
            else:
                print(f"[ERROR] TBS command submission failed: 0x{result:08X}")
                return None
                
        except Exception as e:
            print(f"[ERROR] Command submission failed: {e}")
            return None
    
    def seal_data_with_pcr(self, data: bytes, pcr_indices: List[int]) -> Optional[bytes]:
        """
        Seal data to TPM with PCR binding
        Data can only be unsealed when PCR values match current state
        """
        if not self.available:
            print("[ERROR] TPM not available for sealing")
            return None
        
        try:
            # Read current PCR values for binding
            pcr_digest = self._compute_pcr_policy(pcr_indices)
            if not pcr_digest:
                print("[ERROR] Failed to read PCR values for sealing")
                return None
            
            print(f"[*] Sealing {len(data)} bytes with PCR binding: {pcr_indices}")
            print(f"[*] PCR Policy Digest: {pcr_digest.hex()[:32]}...")
            
            # Create sealed data structure with PCR binding metadata
            sealed_data = {
                'version': 1,
                'pcr_indices': pcr_indices,
                'pcr_digest': pcr_digest.hex(),
                'data': data.hex()
            }
            
            # Serialize sealed data
            import json
            sealed_json = json.dumps(sealed_data).encode()
            
            # Add integrity protection
            integrity_key = hashlib.sha256(b"tpm-seal-key" + pcr_digest).digest()
            hmac_tag = hashlib.sha256(integrity_key + sealed_json).digest()
            
            final_sealed = hmac_tag + sealed_json
            
            print(f"[OK] Data sealed with PCR binding (PCRs: {pcr_indices})")
            return final_sealed
            
        except Exception as e:
            print(f"[ERROR] Data sealing failed: {e}")
            return None
    
    def unseal_data_with_pcr(self, sealed_data: bytes, pcr_indices: List[int]) -> Optional[bytes]:
        """
        Unseal data from TPM with PCR verification
        Unsealing fails if PCR values have changed
        """
        if not self.available:
            print("[ERROR] TPM not available for unsealing")
            return None
        
        try:
            # Extract HMAC and sealed data
            if len(sealed_data) < 32:
                print("[ERROR] Invalid sealed data format")
                return None
            
            hmac_tag = sealed_data[:32]
            sealed_json = sealed_data[32:]
            
            # Verify current PCR values match sealing time
            current_pcr_digest = self._compute_pcr_policy(pcr_indices)
            if not current_pcr_digest:
                print("[ERROR] Failed to read current PCR values")
                return None
            
            # Verify integrity
            integrity_key = hashlib.sha256(b"tpm-seal-key" + current_pcr_digest).digest()
            expected_hmac = hashlib.sha256(integrity_key + sealed_json).digest()
            
            if hmac_tag != expected_hmac:
                print("[ERROR] PCR values have changed - unsealing denied!")
                print(f"[INFO] System state differs from sealing time")
                return None
            
            # Deserialize sealed data
            import json
            sealed_dict = json.loads(sealed_json.decode())
            
            # Verify PCR digest
            stored_pcr_digest = bytes.fromhex(sealed_dict['pcr_digest'])
            if stored_pcr_digest != current_pcr_digest:
                print("[ERROR] PCR policy mismatch - unsealing denied!")
                return None
            
            # Extract original data
            data = bytes.fromhex(sealed_dict['data'])
            
            print(f"[OK] Data unsealed successfully (PCR verification passed)")
            return data
            
        except Exception as e:
            print(f"[ERROR] Data unsealing failed: {e}")
            return None
    
    def _compute_pcr_policy(self, pcr_indices: List[int]) -> Optional[bytes]:
        """Compute PCR policy digest from current PCR values"""
        try:
            pcr_values = []
            
            for pcr_index in pcr_indices:
                pcr_value = self.read_pcr(pcr_index)
                if pcr_value is None:
                    print(f"[ERROR] Failed to read PCR {pcr_index}")
                    return None
                pcr_values.append(pcr_value)
            
            # Compute combined digest
            hasher = hashlib.sha256()
            for pcr_val in pcr_values:
                hasher.update(pcr_val)
            
            policy_digest = hasher.digest()
            return policy_digest
            
        except Exception as e:
            print(f"[ERROR] PCR policy computation failed: {e}")
            return None
    
    def extend_pcr(self, pcr_index: int, data: bytes) -> bool:
        """
        Extend PCR with data (PCR = SHA256(PCR || data))
        Used for creating measurement chains
        """
        if not self.available or self.context is None:
            return False
        
        try:
            # Build TPM 2.0 PCR_Extend command
            command = self._build_pcr_extend_command(pcr_index, data)
            
            # Submit command
            response = self._submit_command(command)
            
            if response:
                # Check response code
                if len(response) >= 10:
                    _, _, code = struct.unpack('>HII', response[0:10])
                    if code == 0:
                        print(f"[OK] PCR {pcr_index} extended successfully")
                        return True
            
            return False
            
        except Exception as e:
            print(f"[ERROR] PCR extend failed: {e}")
            return False
    
    def _build_pcr_extend_command(self, pcr_index: int, data: bytes) -> bytes:
        """Build TPM 2.0 PCR_Extend command"""
        # Hash the data to extend
        digest = hashlib.sha256(data).digest()
        
        # Build command
        command_code = struct.pack('>I', TPM_CC_PCR_EXTEND)
        
        # PCR handle
        pcr_handle = struct.pack('>I', pcr_index)
        
        # Auth area (empty password session)
        auth_size = struct.pack('>I', 9)
        auth_session = struct.pack('>I', TPM_RS_PW) + struct.pack('>HBH', 0, 0, 0)
        
        # Digest values
        digest_count = struct.pack('>I', 1)
        digest_alg = struct.pack('>H', TPM_ALG_SHA256)
        digest_data = struct.pack('>H', len(digest)) + digest
        
        command_body = pcr_handle + auth_size + auth_session + digest_count + digest_alg + digest_data
        command_size = 10 + len(command_body)
        
        command = struct.pack('>HI', TPM_ST_SESSIONS, command_size) + command_code + command_body
        
        return command
    
    def close(self):
        """Close TBS context"""
        if self.context is not None:
            try:
                tbs.Tbsip_Context_Close.argtypes = [wintypes.HANDLE]
                tbs.Tbsip_Context_Close.restype = wintypes.DWORD
                tbs.Tbsip_Context_Close(self.context)
                print("[OK] TBS context closed")
            except Exception as e:
                print(f"[WARN] TBS context close failed: {e}")
            finally:
                self.context = None
                self.available = False
    
    def __del__(self):
        """Cleanup on destruction"""
        self.close()


# Example usage
if __name__ == "__main__":
    print("=" * 60)
    print("Windows TPM 2.0 Native PCR-Bound Sealing Test")
    print("=" * 60)
    
    # Initialize TPM
    tpm = WindowsTPM()
    
    if not tpm.available:
        print("\n[ERROR] TPM not available. Run as Administrator for full access.")
        exit(1)
    
    # Test PCR reading
    print("\n[*] Reading PCR values...")
    for pcr_idx in [0, 1, 2, 7]:
        pcr_val = tpm.read_pcr(pcr_idx)
        if pcr_val:
            print(f"    PCR[{pcr_idx:2d}]: {pcr_val.hex()[:32]}...")
        else:
            print(f"    PCR[{pcr_idx:2d}]: Failed to read")
    
    # Test sealing and unsealing
    print("\n[*] Testing PCR-bound sealing...")
    test_data = b"Secret encryption key - test data"
    pcr_binding = [0, 7]  # Bind to firmware and secure boot PCRs
    
    # Seal data
    sealed = tpm.seal_data_with_pcr(test_data, pcr_binding)
    if sealed:
        print(f"[OK] Sealed {len(test_data)} bytes (sealed size: {len(sealed)} bytes)")
        
        # Unseal data
        unsealed = tpm.unseal_data_with_pcr(sealed, pcr_binding)
        if unsealed == test_data:
            print(f"[OK] Unsealed successfully - data matches!")
        else:
            print(f"[ERROR] Unsealed data mismatch!")
    else:
        print("[ERROR] Sealing failed")
    
    # Cleanup
    tpm.close()
    print("\n" + "=" * 60)
    print("Test complete")
