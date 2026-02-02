"""
Full Memory Dump Module
Complete process memory dumping using Windows Debugging APIs
"""

import os
import sys
import logging
import ctypes
from ctypes import wintypes
from datetime import datetime
from typing import Optional, List
import struct

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = 0x1F0FFF

# MiniDumpWriteDump flags
MiniDumpNormal = 0x00000000
MiniDumpWithDataSegs = 0x00000001
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpFilterMemory = 0x00000008
MiniDumpScanMemory = 0x00000010
MiniDumpWithUnloadedModules = 0x00000020
MiniDumpWithIndirectlyReferencedMemory = 0x00000040
MiniDumpFilterModulePaths = 0x00000080
MiniDumpWithProcessThreadData = 0x00000100
MiniDumpWithPrivateReadWriteMemory = 0x00000200
MiniDumpWithoutOptionalData = 0x00000400
MiniDumpWithFullMemoryInfo = 0x00000800
MiniDumpWithThreadInfo = 0x00001000
MiniDumpWithCodeSegs = 0x00002000
MiniDumpWithoutAuxiliaryState = 0x00004000
MiniDumpWithFullAuxiliaryState = 0x00008000

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load Windows APIs
try:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    dbghelp = ctypes.WinDLL('dbghelp', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    HAS_WIN32_API = True
except Exception as e:
    HAS_WIN32_API = False
    logger.error(f"Failed to load Windows APIs: {e}")


class MINIDUMP_EXCEPTION_INFORMATION(ctypes.Structure):
    """Exception information for minidump"""
    _fields_ = [
        ("ThreadId", wintypes.DWORD),
        ("ExceptionPointers", ctypes.c_void_p),
        ("ClientPointers", wintypes.BOOL)
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Memory region information"""
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]


class MemoryDumper:
    """
    Complete memory dump functionality using Windows Debugging APIs
    """
    
    def __init__(self, dump_dir: str = "C:\\ProgramData\\AntiRansomware\\dumps"):
        """
        Initialize memory dumper
        
        Args:
            dump_dir: Directory for memory dumps
        """
        self.dump_dir = dump_dir
        os.makedirs(dump_dir, exist_ok=True)
        
        if not HAS_WIN32_API:
            logger.error("Windows APIs not available")
            raise RuntimeError("Windows APIs required for memory dumping")
    
    def create_minidump(self, process_id: int, 
                       dump_type: str = 'full',
                       include_handles: bool = True,
                       include_threads: bool = True) -> Optional[str]:
        """
        Create a minidump of a process
        
        Args:
            process_id: Target process ID
            dump_type: Type of dump ('mini', 'full', 'heap', 'custom')
            include_handles: Include handle information
            include_threads: Include thread information
            
        Returns:
            Path to dump file or None on failure
        """
        try:
            # Open process
            h_process = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                process_id
            )
            
            if not h_process:
                error = ctypes.get_last_error()
                logger.error(f"Failed to open process {process_id}: Error {error}")
                return None
            
            try:
                # Generate dump filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dump_filename = f"memdump_pid{process_id}_{timestamp}.dmp"
                dump_path = os.path.join(self.dump_dir, dump_filename)
                
                # Determine dump flags
                dump_flags = self._get_dump_flags(dump_type, include_handles, include_threads)
                
                logger.info(f"Creating {dump_type} memory dump for PID {process_id}...")
                logger.info(f"Dump path: {dump_path}")
                
                # Create dump file
                h_file = kernel32.CreateFileW(
                    dump_path,
                    0x40000000,  # GENERIC_WRITE
                    0,  # No sharing
                    None,
                    2,  # CREATE_ALWAYS
                    0x80,  # FILE_ATTRIBUTE_NORMAL
                    None
                )
                
                if h_file == -1:
                    error = ctypes.get_last_error()
                    logger.error(f"Failed to create dump file: Error {error}")
                    return None
                
                try:
                    # Call MiniDumpWriteDump
                    result = dbghelp.MiniDumpWriteDump(
                        h_process,
                        process_id,
                        h_file,
                        dump_flags,
                        None,  # No exception info
                        None,  # No user stream
                        None   # No callback
                    )
                    
                    if result:
                        file_size = os.path.getsize(dump_path)
                        logger.info(f"✓ Memory dump created successfully")
                        logger.info(f"  Size: {file_size / (1024*1024):.2f} MB")
                        return dump_path
                    else:
                        error = ctypes.get_last_error()
                        logger.error(f"MiniDumpWriteDump failed: Error {error}")
                        return None
                
                finally:
                    kernel32.CloseHandle(h_file)
            
            finally:
                kernel32.CloseHandle(h_process)
        
        except Exception as e:
            logger.error(f"Error creating memory dump: {e}")
            return None
    
    def _get_dump_flags(self, dump_type: str, 
                       include_handles: bool,
                       include_threads: bool) -> int:
        """Get MiniDumpWriteDump flags based on dump type"""
        
        if dump_type == 'mini':
            flags = MiniDumpNormal
        
        elif dump_type == 'full':
            flags = (
                MiniDumpWithFullMemory |
                MiniDumpWithFullMemoryInfo |
                MiniDumpWithUnloadedModules |
                MiniDumpWithProcessThreadData
            )
        
        elif dump_type == 'heap':
            flags = (
                MiniDumpWithDataSegs |
                MiniDumpWithPrivateReadWriteMemory |
                MiniDumpWithProcessThreadData
            )
        
        else:  # custom
            flags = (
                MiniDumpWithDataSegs |
                MiniDumpWithFullMemoryInfo |
                MiniDumpWithThreadInfo
            )
        
        # Add optional components
        if include_handles:
            flags |= MiniDumpWithHandleData
        
        if include_threads:
            flags |= MiniDumpWithProcessThreadData | MiniDumpWithThreadInfo
        
        return flags
    
    def enumerate_memory_regions(self, process_id: int) -> List[dict]:
        """
        Enumerate memory regions of a process
        
        Args:
            process_id: Target process ID
            
        Returns:
            List of memory region info dictionaries
        """
        regions = []
        
        try:
            # Open process
            h_process = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                process_id
            )
            
            if not h_process:
                return regions
            
            try:
                address = 0
                mbi = MEMORY_BASIC_INFORMATION()
                
                while True:
                    # Query memory region
                    result = kernel32.VirtualQueryEx(
                        h_process,
                        ctypes.c_void_p(address),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi)
                    )
                    
                    if result == 0:
                        break
                    
                    # Save region info
                    regions.append({
                        'base_address': hex(mbi.BaseAddress) if mbi.BaseAddress else '0x0',
                        'region_size': mbi.RegionSize,
                        'state': self._get_memory_state(mbi.State),
                        'protect': self._get_memory_protection(mbi.Protect),
                        'type': self._get_memory_type(mbi.Type)
                    })
                    
                    # Move to next region
                    address = mbi.BaseAddress + mbi.RegionSize
                
                logger.info(f"Enumerated {len(regions)} memory regions for PID {process_id}")
                
            finally:
                kernel32.CloseHandle(h_process)
        
        except Exception as e:
            logger.error(f"Error enumerating memory regions: {e}")
        
        return regions
    
    def _get_memory_state(self, state: int) -> str:
        """Convert memory state to string"""
        states = {
            0x1000: 'MEM_COMMIT',
            0x2000: 'MEM_RESERVE',
            0x10000: 'MEM_FREE'
        }
        return states.get(state, f'UNKNOWN({state})')
    
    def _get_memory_protection(self, protect: int) -> str:
        """Convert memory protection to string"""
        protections = {
            0x01: 'PAGE_NOACCESS',
            0x02: 'PAGE_READONLY',
            0x04: 'PAGE_READWRITE',
            0x08: 'PAGE_WRITECOPY',
            0x10: 'PAGE_EXECUTE',
            0x20: 'PAGE_EXECUTE_READ',
            0x40: 'PAGE_EXECUTE_READWRITE',
            0x80: 'PAGE_EXECUTE_WRITECOPY'
        }
        return protections.get(protect, f'0x{protect:X}')
    
    def _get_memory_type(self, mem_type: int) -> str:
        """Convert memory type to string"""
        types = {
            0x1000000: 'MEM_IMAGE',
            0x40000: 'MEM_MAPPED',
            0x20000: 'MEM_PRIVATE'
        }
        return types.get(mem_type, f'UNKNOWN({mem_type})')
    
    def dump_memory_region(self, process_id: int, 
                          base_address: int, 
                          size: int) -> Optional[bytes]:
        """
        Dump a specific memory region
        
        Args:
            process_id: Target process ID
            base_address: Starting address
            size: Number of bytes to read
            
        Returns:
            Memory content or None
        """
        try:
            # Open process
            h_process = kernel32.OpenProcess(
                PROCESS_VM_READ,
                False,
                process_id
            )
            
            if not h_process:
                return None
            
            try:
                # Allocate buffer
                buffer = ctypes.create_string_buffer(size)
                bytes_read = ctypes.c_size_t()
                
                # Read memory
                result = kernel32.ReadProcessMemory(
                    h_process,
                    ctypes.c_void_p(base_address),
                    buffer,
                    size,
                    ctypes.byref(bytes_read)
                )
                
                if result:
                    return buffer.raw[:bytes_read.value]
                else:
                    error = ctypes.get_last_error()
                    logger.error(f"ReadProcessMemory failed: Error {error}")
                    return None
            
            finally:
                kernel32.CloseHandle(h_process)
        
        except Exception as e:
            logger.error(f"Error dumping memory region: {e}")
            return None
    
    def analyze_dump(self, dump_path: str) -> dict:
        """
        Analyze a memory dump file
        
        Args:
            dump_path: Path to dump file
            
        Returns:
            Analysis results dictionary
        """
        analysis = {
            'file_path': dump_path,
            'file_size': 0,
            'timestamp': datetime.now().isoformat(),
            'strings_found': [],
            'suspicious_patterns': []
        }
        
        try:
            if not os.path.exists(dump_path):
                return analysis
            
            analysis['file_size'] = os.path.getsize(dump_path)
            
            # Extract strings (simplified)
            with open(dump_path, 'rb') as f:
                content = f.read(1024 * 1024)  # First 1MB
                
                # Find printable strings
                strings = []
                current_string = b''
                
                for byte in content:
                    if 32 <= byte < 127:
                        current_string += bytes([byte])
                    else:
                        if len(current_string) >= 4:
                            strings.append(current_string.decode('ascii', errors='ignore'))
                        current_string = b''
                
                analysis['strings_found'] = strings[:100]  # Top 100
                
                # Look for suspicious patterns
                suspicious = []
                patterns = [
                    b'encrypt',
                    b'decrypt',
                    b'ransom',
                    b'bitcoin',
                    b'wallet',
                    b'.onion',
                    b'tor2web'
                ]
                
                for pattern in patterns:
                    if pattern in content:
                        suspicious.append(pattern.decode('ascii'))
                
                analysis['suspicious_patterns'] = suspicious
            
            logger.info(f"Dump analysis complete: {len(analysis['strings_found'])} strings, "
                       f"{len(analysis['suspicious_patterns'])} suspicious patterns")
        
        except Exception as e:
            logger.error(f"Error analyzing dump: {e}")
        
        return analysis


if __name__ == "__main__":
    # Test memory dumper
    print("Testing Memory Dumper...")
    
    if not HAS_WIN32_API:
        print("ERROR: Windows APIs not available")
        exit(1)
    
    try:
        dumper = MemoryDumper()
        
        # Get current process ID for testing
        current_pid = os.getpid()
        print(f"\nTesting with current process (PID: {current_pid})")
        
        # Enumerate memory regions
        print("\n=== Enumerating Memory Regions ===")
        regions = dumper.enumerate_memory_regions(current_pid)
        print(f"Found {len(regions)} memory regions")
        
        if regions:
            print("\nFirst 5 regions:")
            for region in regions[:5]:
                print(f"  {region['base_address']}: {region['region_size']} bytes, "
                      f"{region['state']}, {region['protect']}")
        
        # Create mini dump
        print("\n=== Creating Mini Dump ===")
        dump_path = dumper.create_minidump(current_pid, dump_type='mini')
        
        if dump_path:
            print(f"✓ Dump created: {dump_path}")
            
            # Analyze dump
            print("\n=== Analyzing Dump ===")
            analysis = dumper.analyze_dump(dump_path)
            print(f"File size: {analysis['file_size'] / 1024:.2f} KB")
            print(f"Strings found: {len(analysis['strings_found'])}")
            print(f"Suspicious patterns: {analysis['suspicious_patterns']}")
        
        print("\n✓ Memory dumper test complete!")
    
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
