"""Test desktop app with console output"""
import sys
sys.stdout = open('app_console.txt', 'w', encoding='utf-8', buffering=1)
sys.stderr = sys.stdout

print("Starting desktop app...")

# Now import and run
from desktop_app import main

if __name__ == "__main__":
    main()
