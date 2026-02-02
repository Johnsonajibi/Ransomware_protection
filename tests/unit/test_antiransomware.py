#!/usr/bin/env python3
"""
Anti-Ransomware Test & Demo Script
Test the functional anti-ransomware system with real threat simulations
"""

import os
import sys
import time
import requests
from pathlib import Path

def test_threat_detection():
    """Test the anti-ransomware system with various threats"""
    
    print("🧪 TESTING Anti-Ransomware Protection System")
    print("=" * 50)
    
    # Check if protection system is running
    try:
        response = requests.get("http://localhost:8080/api/status", timeout=5)
        if response.status_code == 200:
            status = response.json()
            print(f"✅ Protection system is running (Active: {status.get('active', False)})")
        else:
            print("❌ Protection system not responding")
            return False
    except requests.exceptions.RequestException:
        print("❌ Protection system not running")
        print("   Start it with: python functional_antiransomware.py")
        return False
    
    # Create test directory
    test_dir = Path("./demo_files")
    test_dir.mkdir(exist_ok=True)
    
    print("\n🦠 Creating test threats...")
    
    # Test 1: Ransomware extension
    print("\n1. Testing ransomware extension detection...")
    ransomware_file = test_dir / "important_document.txt.encrypted"
    ransomware_file.write_text("This file has been encrypted by ransomware!")
    print(f"   Created: {ransomware_file}")
    time.sleep(2)
    
    # Test 2: Ransom note
    print("\n2. Testing ransom note detection...")
    ransom_note = test_dir / "readme_for_decrypt.txt"
    ransom_note.write_text("""
    YOUR FILES HAVE BEEN ENCRYPTED!
    
    To decrypt your files, you need to pay 0.5 BTC to the following address:
    1A2B3C4D5E6F7G8H9I0J
    
    After payment, send email to: decrypt@ransomware.com
    """)
    print(f"   Created: {ransom_note}")
    time.sleep(2)
    
    # Test 3: Multiple suspicious extensions
    print("\n3. Testing multiple ransomware variants...")
    variants = ['.locked', '.crypto', '.vault', '.xxx', '.cerber', '.locky']
    for ext in variants:
        variant_file = test_dir / f"test_file{ext}"
        variant_file.write_text(f"Encrypted content with {ext} extension")
        print(f"   Created: test_file{ext}")
        time.sleep(0.5)
    
    # Test 4: Use API to create test threat
    print("\n4. Testing via API...")
    try:
        response = requests.post("http://localhost:8080/api/test-threat")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ API test: {result.get('message', 'Success')}")
        else:
            print("   ❌ API test failed")
    except Exception as e:
        print(f"   ❌ API test error: {e}")
    
    # Check threat detection results
    print("\n📊 Checking threat detection results...")
    time.sleep(3)
    
    try:
        response = requests.get("http://localhost:8080/api/threats")
        if response.status_code == 200:
            threats = response.json().get('threats', [])
            print(f"   Detected threats: {len(threats)}")
            
            if threats:
                print("\n   Recent threats:")
                for threat in threats[-5:]:  # Show last 5 threats
                    timestamp = time.strftime('%H:%M:%S', time.localtime(threat['timestamp']))
                    print(f"   [{timestamp}] {threat['threat_level']} - {threat['reason']}")
                    if threat['blocked']:
                        print(f"             🛡️ BLOCKED: {threat['action_taken']}")
            else:
                print("   ⚠️ No threats detected - check if monitoring is active")
                
    except Exception as e:
        print(f"   Error checking threats: {e}")
    
    # Get final system status
    print("\n🛡️ Final system status...")
    try:
        response = requests.get("http://localhost:8080/api/status")
        if response.status_code == 200:
            status = response.json()
            print(f"   Total threats detected: {status.get('total_threats', 0)}")
            print(f"   Threats blocked: {status.get('blocked_threats', 0)}")
            print(f"   Protected paths: {status.get('protected_paths', 0)}")
            print(f"   System active: {status.get('active', False)}")
            
            if status.get('threat_levels'):
                print("   Threat breakdown:")
                for level, count in status['threat_levels'].items():
                    print(f"     {level}: {count}")
        
    except Exception as e:
        print(f"   Error getting status: {e}")
    
    print(f"\n🌐 View detailed results at: http://localhost:8080")
    print("✅ Test completed!")
    
    return True

def cleanup_test_files():
    """Clean up test threat files"""
    print("\n🧹 Cleaning up test files...")
    
    test_dir = Path("./demo_files")
    if not test_dir.exists():
        return
    
    # Remove test threat files
    patterns = [
        "*.encrypted", "*.locked", "*.crypto", "*.vault", 
        "*.xxx", "*.cerber", "*.locky", "readme_for_decrypt.txt",
        "test_ransomware_*"
    ]
    
    removed = 0
    for pattern in patterns:
        for file_path in test_dir.glob(pattern):
            try:
                file_path.unlink()
                removed += 1
                print(f"   Removed: {file_path.name}")
            except Exception as e:
                print(f"   Error removing {file_path.name}: {e}")
    
    print(f"✅ Cleaned up {removed} test files")

def interactive_test():
    """Interactive testing mode"""
    print("🎮 INTERACTIVE TESTING MODE")
    print("=" * 40)
    
    while True:
        print("\n📋 Test Options:")
        print("  1. Run full threat detection test")
        print("  2. Create single ransomware file")
        print("  3. Create ransom note")
        print("  4. Check system status")
        print("  5. View web dashboard")
        print("  6. Clean up test files")
        print("  9. Exit")
        
        try:
            choice = input("\nSelect option (1-9): ").strip()
            
            if choice == '1':
                test_threat_detection()
            elif choice == '2':
                test_dir = Path("./demo_files")
                test_dir.mkdir(exist_ok=True)
                filename = input("Enter filename (without extension): ").strip()
                ext = input("Enter extension (.encrypted, .locked, etc.): ").strip()
                if not ext.startswith('.'):
                    ext = '.' + ext
                threat_file = test_dir / (filename + ext)
                threat_file.write_text("Test ransomware content")
                print(f"✅ Created: {threat_file}")
            elif choice == '3':
                test_dir = Path("./demo_files")
                test_dir.mkdir(exist_ok=True)
                ransom_file = test_dir / "readme_for_decrypt.txt"
                ransom_file.write_text("YOUR FILES HAVE BEEN ENCRYPTED! Pay ransom to decrypt.")
                print(f"✅ Created ransom note: {ransom_file}")
            elif choice == '4':
                try:
                    response = requests.get("http://localhost:8080/api/status", timeout=5)
                    if response.status_code == 200:
                        status = response.json()
                        print("\n🛡️ System Status:")
                        print(f"   Active: {status.get('active', False)}")
                        print(f"   Total threats: {status.get('total_threats', 0)}")
                        print(f"   Blocked threats: {status.get('blocked_threats', 0)}")
                        print(f"   Protected paths: {status.get('protected_paths', 0)}")
                    else:
                        print("❌ Could not get system status")
                except Exception as e:
                    print(f"❌ Error: {e}")
            elif choice == '5':
                print("🌐 Opening web dashboard...")
                print("   URL: http://localhost:8080")
                import webbrowser
                try:
                    webbrowser.open("http://localhost:8080")
                except Exception:
                    print("   (Open manually in your browser)")
            elif choice == '6':
                cleanup_test_files()
            elif choice == '9':
                break
            else:
                print("Invalid option")
                
        except KeyboardInterrupt:
            break
        except EOFError:
            break
    
    print("\n👋 Exiting interactive test mode")

def main():
    """Main function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--test':
            test_threat_detection()
        elif sys.argv[1] == '--cleanup':
            cleanup_test_files()
        elif sys.argv[1] == '--interactive':
            interactive_test()
        elif sys.argv[1] == '--help':
            print("""
Anti-Ransomware Test Script

Usage:
  python test_antiransomware.py [option]

Options:
  --test         Run full threat detection test
  --interactive  Interactive testing mode
  --cleanup      Clean up test files
  --help         Show this help

No options:     Interactive mode (default)
            """)
        else:
            print("Unknown option. Use --help for usage.")
    else:
        interactive_test()

if __name__ == "__main__":
    main()
