import os
import ast
import sys
import re
from pathlib import Path

def scan_file(filepath):
    """Scan a single file for issues."""
    issues = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # 1. Syntax Check
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            return [f"SYNTAX ERROR: {e}"]
            
        # 2. Check imports
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                # Advanced import checking could go here
                pass

        # 3. Check for TODO/FIXME
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if "TODO" in line:
                issues.append(f"Line {i+1}: TODO found: {line.strip()}")
            if "FIXME" in line:
                issues.append(f"Line {i+1}: FIXME found: {line.strip()}")
                
    except Exception as e:
        issues.append(f"Error scanning file: {e}")
        
    return issues

def main():
    root_dir = os.getcwd()
    print(f"Scanning directory: {root_dir}")
    print("=" * 60)
    
    found_issues = False
    
    for root, dirs, files in os.walk(root_dir):
        if ".venv" in root or ".git" in root or "__pycache__" in root:
            continue
            
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, root_dir)
                
                issues = scan_file(filepath)
                if issues:
                    found_issues = True
                    print(f"\n📄 {rel_path}")
                    for issue in issues:
                        print(f"  - {issue}")
                        
    if not found_issues:
        print("\n✅ No obvious issues found!")
    else:
        print("\n⚠️  Issues found. Please review above.")

if __name__ == "__main__":
    main()
