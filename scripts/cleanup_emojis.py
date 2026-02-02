#!/usr/bin/env python3
"""Remove all emojis from source files intelligently"""

import re
import os

def clean_file(filepath):
    """Remove all non-ASCII emoji characters from file while preserving code structure"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        original_length = len(content)
        
        # Remove all non-ASCII characters (emojis and garbled text)
        # Keep newlines and basic whitespace intact
        cleaned_lines = []
        for line in content.split('\n'):
            # Keep line structure, just remove emoji bytes
            cleaned_line = re.sub(r'[^\x00-\x7F]', '', line)
            cleaned_lines.append(cleaned_line)
        
        cleaned_content = '\n'.join(cleaned_lines)
        
        if len(cleaned_content) != original_length:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(cleaned_content)
            removed_chars = original_length - len(cleaned_content)
            return True, removed_chars
        return False, 0
    except Exception as e:
        return None, str(e)

# Find all Python and PowerShell files
extensions = ['.py', '.ps1']
files_to_clean = []

for root, dirs, filenames in os.walk('.'):
    # Skip virtual environments and build directories
    dirs[:] = [d for d in dirs if d not in ['.venv', 'venv', 'build', '__pycache__', '.git']]
    
    for filename in filenames:
        if any(filename.endswith(ext) for ext in extensions):
            filepath = os.path.join(root, filename)
            files_to_clean.append(filepath)

print("=" * 60)
print("EMOJI CLEANUP UTILITY")
print("=" * 60)
print(f"Found {len(files_to_clean)} source files to scan\n")

cleaned_count = 0
total_chars_removed = 0

for filepath in sorted(files_to_clean):
    result, info = clean_file(filepath)
    
    if result is True:
        cleaned_count += 1
        total_chars_removed += info
        print(f" {filepath}")
        print(f"  Removed: {info} emoji/non-ASCII characters")
    elif result is False:
        pass  # No changes needed
    else:
        print(f" {filepath}")
        print(f"  Error: {info}")

print("\n" + "=" * 60)
print(f"SUMMARY:")
print(f"Files cleaned: {cleaned_count}")
print(f"Total characters removed: {total_chars_removed}")
print("=" * 60)
