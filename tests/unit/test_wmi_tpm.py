#!/usr/bin/env python3
"""Quick test: Can we access TPM via WMI?"""

import sys

print("Testing WMI TPM Access...")
print("=" * 60)

try:
    import wmi
    print("✓ WMI library imported")
    
    print("\nConnecting to TPM namespace...")
    c = wmi.WMI(namespace='root\\cimv2\\Security\\MicrosoftTpm')
    print("✓ Connected to TPM namespace")
    
    print("\nQuerying Win32_Tpm...")
    tpm_list = c.Win32_Tpm()
    
    if tpm_list:
        tpm = tpm_list[0]
        print("✓ TPM device found!\n")
        
        print("TPM Status:")
        print(f"  IsActivated: {tpm.IsActivated_InitialValue}")
        print(f"  IsEnabled:   {tpm.IsEnabled_InitialValue}")
        print(f"  IsOwned:     {tpm.IsOwned_InitialValue}")
        
        try:
            print(f"  SpecVersion: {tpm.SpecVersion}")
        except:
            pass
        
        # Check if ready for use
        if tpm.IsActivated_InitialValue and tpm.IsEnabled_InitialValue:
            print("\n✅ SUCCESS: TPM is READY for tri-factor authentication!")
            sys.exit(0)
        else:
            print("\n⚠️  TPM found but not fully activated/enabled")
            sys.exit(1)
    else:
        print("❌ No TPM device found in WMI")
        sys.exit(1)
        
except ImportError:
    print("❌ WMI library not available (pip install wmi)")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    
    error_str = str(e).lower()
    if "access" in error_str or "denied" in error_str:
        print("\n⚠️  Access denied - need Administrator privileges")
        print("   Run this script as Administrator")
    
    sys.exit(1)
