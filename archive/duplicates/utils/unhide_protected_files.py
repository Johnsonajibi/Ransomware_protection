#!/usr/bin/env python3
"""
Unhide Protected Files
======================
Make all protected files visible again while keeping security protection
"""

import os
import ctypes
from pathlib import Path

try:
    from unified_antiransomware import UnifiedDatabase
    
    print("="*70)
    print("UNHIDING PROTECTED FILES")
    print("="*70)
    print()
    
    # Get protected paths
    db = UnifiedDatabase()
    paths = db.get_protected_paths()
    
    if not paths:
        print("No protected paths found")
        exit(0)
    
    print(f"Found {len(paths)} protected paths")
    print()
    
    # Windows API constants
    FILE_ATTRIBUTE_HIDDEN = 0x2
    FILE_ATTRIBUTE_SYSTEM = 0x4
    FILE_ATTRIBUTE_READONLY = 0x1
    
    kernel32 = ctypes.windll.kernel32
    
    total_unhidden = 0
    
    for p in paths:
        path = Path(p['path'])
        if not path.exists():
            print(f"⚠️  Path not found: {path}")
            continue
        
        print(f"Processing: {path}")
        
        # Process all files in path
        if path.is_dir():
            files = list(path.rglob('*'))
        else:
            files = [path]
        
        for file in files:
            if not file.is_file():
                continue
            
            try:
                # Get current attributes
                current_attrs = kernel32.GetFileAttributesW(str(file))
                if current_attrs == -1:
                    continue
                
                # Check if hidden
                if current_attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
                    # Remove HIDDEN and SYSTEM flags but keep READONLY for security
                    new_attrs = current_attrs & ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
                    new_attrs |= FILE_ATTRIBUTE_READONLY  # Ensure read-only
                    
                    if kernel32.SetFileAttributesW(str(file), new_attrs):
                        print(f"  ✓ Unhidden: {file.name}")
                        total_unhidden += 1
                    else:
                        print(f"  ✗ Failed: {file.name}")
            except Exception as e:
                print(f"  ✗ Error with {file.name}: {e}")
        
        print()
    
    print("="*70)
    print(f"COMPLETE: {total_unhidden} files made visible")
    print("="*70)
    print()
    print("Files are now visible but still protected with ACL security!")
    print("To see them in File Explorer, refresh the view (F5)")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
