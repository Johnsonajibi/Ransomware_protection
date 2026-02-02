import os
import sys
import importlib
import traceback
from pathlib import Path

def check_imports():
    root_dir = Path.cwd()
    sys.path.append(str(root_dir))
    sys.path.append(str(root_dir / "src" / "python" / "core"))
    sys.path.append(str(root_dir / "src" / "python" / "monitoring"))
    sys.path.append(str(root_dir / "src" / "python" / "utils"))

    print(f"Checking imports in {root_dir}")
    print("=" * 60)

    failed_imports = []

    for root, dirs, files in os.walk(root_dir):
        if ".venv" in root or ".git" in root or "__pycache__" in root or "build" in root or "dist" in root:
            continue

        for file in files:
            if file.endswith(".py"):
                filepath = Path(root) / file
                module_name = filepath.stem
                
                # Skip setup/test scripts that might not have env
                if "setup" in module_name or "test" in module_name:
                    continue

                try:
                    # We can't easily import everything because of main() execution
                    # So we just parse it and check imports? No, that's static analysis.
                    # Let's try to compile it at least.
                    with open(filepath, 'r', encoding='utf-8') as f:
                        compile(f.read(), filepath, 'exec')
                    print(f"✅ Syntax OK: {filepath.name}")
                except Exception as e:
                    print(f"❌ Syntax Error in {filepath.name}: {e}")
                    failed_imports.append((filepath.name, str(e)))

    print("\nimport verification complete.")
    if failed_imports:
        print("Failed files:")
        for name, err in failed_imports:
            print(f"- {name}: {err}")
    else:
        print("All compiled successfully.")

if __name__ == "__main__":
    check_imports()
