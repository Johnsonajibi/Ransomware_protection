import re
import os

def clean_file(filepath):
    with open(filepath, 'rb') as f:
        content = f.read()
    
    # Decode with replacement for problematic bytes
    text = content.decode('utf-8', errors='replace')
    
    # Remove all non-ASCII characters
    cleaned = re.sub(r'[^\x00-\x7F]', '', text)
    
    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(cleaned)
    
    removed = len(text) - len(cleaned)
    return removed > 0, removed

files = ['desktop_app.py', 'brutal_truth.py', 'boot_persistence_protection.py', 'Build-Driver-Direct.ps1']

for f in files:
    if os.path.exists(f):
        changed, removed = clean_file(f)
        status = 'CLEANED' if changed else 'OK'
        print(f'{status}: {f} ({removed} chars removed)' if changed else f'{status}: {f}')
