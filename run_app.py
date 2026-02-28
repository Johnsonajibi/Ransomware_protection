import sys
import os
from pathlib import Path

# Fix console encoding for emojis
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Add src/python to path
sys.path.append(str(Path(__file__).parent / "src" / "python"))

# Import and run the main app
from desktop_app import main

if __name__ == "__main__":
    main()
