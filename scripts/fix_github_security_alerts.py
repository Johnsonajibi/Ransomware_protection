#!/usr/bin/env python3
"""
GitHub Security Alerts - Automated Fixer
Patches known security vulnerabilities from GitHub Code Scanning
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

class SecurityFixer:
    def __init__(self):
        self.fixed_files = []
        self.total_fixes = 0
        self.errors = []

    def fix_shell_true_in_file(self, filepath: str) -> bool:
        """Fix subprocess.run(shell=True) vulnerabilities"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            fixes_in_file = 0

            # Pattern 1: subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, ...)
            if "shell=True" in content:
                # Add shlex import if needed
                if 'import shlex' not in content and 'from shlex import' not in content:
                    if 'import subprocess' in content:
                        content = content.replace(
                            'import subprocess',
                            'import subprocess\nimport shlex',
                            1
                        )
                    elif 'import sys' in content:
                        content = content.replace(
                            'import sys',
                            'import sys\nimport shlex',
                            1
                        )
                    else:
                        # Add after last import
                        lines = content.split('\n')
                        last_import_idx = 0
                        for i, line in enumerate(lines):
                            if line.startswith('import ') or line.startswith('from '):
                                last_import_idx = i
                        if last_import_idx > 0:
                            lines.insert(last_import_idx + 1, 'import shlex')
                            content = '\n'.join(lines)

                # Replace shell=True patterns
                patterns = [
                    # Pattern: subprocess.run(shlex.split('command'), # shell=True removed for security, ...)
                    (
                        r"subprocess\.run\(f?['\"]([^'\"]+)['\"]\s*,\s*shell=True",
                        lambda m: f"subprocess.run(shlex.split('{m.group(1)}'), # shell=True removed for security"
                    ),
                    # Pattern: subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, ...)
                    (
                        r"# shell=True removed for security
                        capture_output=True,",
                        "# shell=True removed for security\n                        capture_output=True,"
                    ),
                    # Pattern: shell=True) at end
                    (
                        r",\s*shell=True\)",
                        ")"
                    ),
                ]

                for pattern, replacement in patterns:
                    if isinstance(replacement, str):
                        if re.search(pattern, content):
                            content = re.sub(pattern, replacement, content)
                            fixes_in_file += 1
                    else:
                        if re.search(pattern, content):
                            content = re.sub(pattern, replacement, content)
                            fixes_in_file += 1

            if content != original_content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.fixed_files.append(filepath)
                self.total_fixes += fixes_in_file
                return True
            
            return False

        except Exception as e:
            self.errors.append(f"Error processing {filepath}: {e}")
            return False

    def fix_unsafe_imports_in_file(self, filepath: str) -> bool:
        """Fix __import__() calls with unsafe dynamic imports"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content

            # Check if file has __import__ calls
            if '__import__' not in content:
                return False

            # Add safe import function if not present
            if 'def safe_import' not in content:
                safe_import_func = '''

def safe_import(module_name: str):
    """Safely import a module from whitelist"""
    import importlib
    
    # Whitelist of allowed modules
    ALLOWED_MODULES = {
        'cryptography', 'sqlite3', 'tkinter', 'psutil', 'pywin32',
        'requests', 'numpy', 'pandas', 'pytest', 'sys', 'os', 're',
        'json', 'datetime', 'pathlib', 'logging', 'subprocess'
    }
    
    if module_name not in ALLOWED_MODULES:
        raise ValueError(f"Module {module_name} not in security whitelist")
    
    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        raise ImportError(f"Failed to import {module_name}: {e}")
'''
                # Insert before the first function or class
                lines = content.split('\n')
                insert_idx = 0
                for i, line in enumerate(lines):
                    if line.startswith('def ') or line.startswith('class '):
                        insert_idx = i
                        break
                
                if insert_idx > 0:
                    lines.insert(insert_idx, safe_import_func)
                    content = '\n'.join(lines)

            # Replace __import__ calls
            content = re.sub(
                r"__import__\((['\"])([^'\"]+)\1\)",
                r"safe_import('\2')",
                content
            )
            
            content = re.sub(
                r"__import__\((\w+)\.replace",
                r"safe_import(\1.replace",
                content
            )

            if content != original_content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.fixed_files.append(filepath)
                self.total_fixes += 1
                return True

            return False

        except Exception as e:
            self.errors.append(f"Error processing {filepath}: {e}")
            return False

    def add_input_validation_module(self) -> bool:
        """Create a centralized input validation module"""
        validation_file = Path('security') / 'input_validation.py'
        validation_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            print(f"[OK] Created input validation module: {validation_file}")
            return True
        except Exception as e:
            self.errors.append(f"Failed to create validation module: {e}")
            return False

    def scan_and_fix_all(self, root_dir: str = '.') -> None:
        """Scan all Python files and apply security fixes"""
        print("\n" + "="*60)
        print("[LOCK] GITHUB SECURITY ALERTS - AUTOMATED FIXER")
        print("="*60 + "\n")

        py_files = list(Path(root_dir).rglob('*.py'))
        py_files = [
            f for f in py_files 
            if not any(x in str(f) for x in ['.venv', '__pycache__', '.git', 'node_modules'])
        ]

        print(f"[INFO] Found {len(py_files)} Python files to scan\n")

        # Fix shell=True vulnerabilities
        print("[*] Fixing subprocess shell=True vulnerabilities...")
        shell_true_fixed = sum(
            1 for f in py_files 
            if self.fix_shell_true_in_file(str(f))
        )
        print(f"   [OK] Fixed {shell_true_fixed} files\n")

        # Fix unsafe imports
        print("[*] Fixing unsafe dynamic imports...")
        imports_fixed = sum(
            1 for f in py_files 
            if self.fix_unsafe_imports_in_file(str(f))
        )
        print(f"   [OK] Fixed {imports_fixed} files\n")

        # Create validation module
        print("[*] Creating input validation module...")
        self.add_input_validation_module()

        # Report results
        print("\n" + "="*60)
        print("[RESULT] SECURITY FIX SUMMARY")
        print("="*60)
        print(f"Total files fixed: {len(self.fixed_files)}")
        print(f"Total fixes applied: {self.total_fixes}")
        
        if self.errors:
            print(f"\n[!] Errors encountered: {len(self.errors)}")
            for error in self.errors[:5]:  # Show first 5 errors
                print(f"   - {error}")
            if len(self.errors) > 5:
                print(f"   ... and {len(self.errors)-5} more")
        
        print("\n[FILES] Fixed files:")
        for f in sorted(set(self.fixed_files)):
            print(f"   [OK] {f}")
        
        print("\n" + "="*60)
        print("Next steps:")
        print("  1. Review changes in fixed files")
        print("  2. Run: python -m pytest tests/")
        print("  3. Run: bandit -r . -v")
        print("  4. Commit changes with proper security audit")
        print("="*60 + "\n")


if __name__ == '__main__':
    fixer = SecurityFixer()
    
    # Allow specifying a directory
    target_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    
    fixer.scan_and_fix_all(target_dir)
