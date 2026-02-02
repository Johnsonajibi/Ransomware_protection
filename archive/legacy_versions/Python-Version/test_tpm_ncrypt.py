"""
Test TPM access using NCrypt Provider (alternative to TBS)
"""
import ctypes
from ctypes import wintypes
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# NCrypt constants
NCRYPT_SILENT_FLAG = 0x00000040
NCRYPT_MACHINE_KEY_FLAG = 0x00000020
MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"

# Load NCrypt
try:
    ncrypt = ctypes.WinDLL('ncrypt.dll', use_last_error=True)
    
    # NCryptOpenStorageProvider
    ncrypt.NCryptOpenStorageProvider.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),  # phProvider
        wintypes.LPCWSTR,                  # pszProviderName
        wintypes.DWORD                     # dwFlags
    ]
    ncrypt.NCryptOpenStorageProvider.restype = wintypes.LONG
    
    logger.info("NCrypt DLL loaded successfully")
    
    # Try to open the Platform Crypto Provider (TPM-backed)
    provider_handle = wintypes.HANDLE()
    
    logger.info(f"Attempting to open provider: {MS_PLATFORM_CRYPTO_PROVIDER}")
    result = ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(provider_handle),
        MS_PLATFORM_CRYPTO_PROVIDER,
        0  # dwFlags
    )
    
    logger.info(f"NCryptOpenStorageProvider returned: 0x{result:08X}")
    
    if result == 0:
        logger.info("✓ Successfully opened Platform Crypto Provider (TPM)")
        logger.info(f"Provider handle: {provider_handle.value}")
        
        # Clean up
        ncrypt.NCryptFreeObject(provider_handle)
        logger.info("✓ TPM is accessible via NCrypt API")
    else:
        last_error = ctypes.get_last_error()
        logger.error(f"Failed to open provider. Error: 0x{result:08X}, LastError: {last_error}")
        
        # Try software provider as comparison
        logger.info("Trying Microsoft Software Key Storage Provider...")
        sw_provider = wintypes.HANDLE()
        result2 = ncrypt.NCryptOpenStorageProvider(
            ctypes.byref(sw_provider),
            "Microsoft Software Key Storage Provider",
            0
        )
        if result2 == 0:
            logger.info("✓ Software provider works (no TPM issue)")
            ncrypt.NCryptFreeObject(sw_provider)
        else:
            logger.error(f"Software provider also failed: 0x{result2:08X}")
    
except Exception as e:
    logger.error(f"Exception: {e}")
    import traceback
    logger.error(traceback.format_exc())
