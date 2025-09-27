#!/usr/bin/env python3
"""Test CLI functionality"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test CLI
if __name__ == "__main__":
    try:
        from unified_antiransomware import UnifiedCLI
        
        print("🛡️ UNIFIED ANTI-RANSOMWARE CLI TEST")
        print("=" * 40)
        
        cli = UnifiedCLI()
        
        # Mock args object
        class Args:
            def __init__(self):
                self.command = 'status'
                self.folder = None
                self.files = None
        
        args = Args()
        success = cli.run_cli(args)
        
        print(f"\n✅ CLI test {'PASSED' if success else 'FAILED'}")
        
    except Exception as e:
        print(f"❌ CLI test error: {e}")
        import traceback
        traceback.print_exc()
