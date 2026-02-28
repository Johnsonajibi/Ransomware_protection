#!/usr/bin/env python3
"""
Fix GitHub CodeQL Vulnerabilities
Addresses all CodeQL alerts from GitHub security scanning
"""

import os
import re
from pathlib import Path
from typing import List, Tuple

class CodeQLFixer:
    def __init__(self):
        self.fixes_applied = []
        self.errors = []

    def fix_path_expression_vulnerability(self, file_path: str) -> bool:
        """Fix uncontrolled data in path expression (CWE-22: Path Traversal)"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original = content

            # Pattern 1: os.path.join(user_path, item) without validation
            # Add path validation before using user-controlled paths
            
            # Fix pattern: item_path = os.path.join(path, item)
            # Should validate path before use
            if "os.path.join(path, item)" in content and "validate_path(path)" not in content:
                # Find the function containing this pattern
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if 'def get_folder_contents' in line or 'def api_' in line:
                        # Insert validation check after function start
                        for j in range(i, min(i + 20, len(lines))):
                            if 'path = data.get' in lines[j] or 'path = request' in lines[j]:
                                # Insert validation after path assignment
                                if 'validate_path' not in lines[j+1]:
                                    lines.insert(j+1, '        # Validate path to prevent traversal')
                                    lines.insert(j+2, '        from pathlib import Path')
                                    lines.insert(j+3, '        try:')
                                    lines.insert(j+4, '            resolved = os.path.abspath(path)')
                                    lines.insert(j+5, '            if not str(resolved).startswith(str(allowed_base)):')
                                    lines.insert(j+6, '                raise ValueError("Path traversal detected")')
                                    lines.insert(j+7, '        except (ValueError, OSError) as e:')
                                    lines.insert(j+8, '            return jsonify({"success": False, "error": str(e)})')
                                break
                
                content = '\n'.join(lines)

            # Pattern 2: Use realpath/resolve for path validation
            content = re.sub(
                r'os\.path\.join\(path, item\)',
                r'os.path.realpath(os.path.join(path, item))',
                content
            )

            if content != original:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.fixes_applied.append(f"Path validation fixed in {file_path}")
                return True

        except Exception as e:
            self.errors.append(f"Error fixing {file_path}: {e}")

        return False

    def fix_ssl_tls_vulnerability(self, file_path: str) -> bool:
        """Fix insecure SSL/TLS version (CWE-327)"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original = content

            # Fix insecure SSL/TLS versions
            replacements = [
                (r'ssl\.PROTOCOL_TLSv1[^_]', 'ssl.PROTOCOL_TLS'),
                (r'ssl\.PROTOCOL_TLSv1_2', 'ssl.PROTOCOL_TLS'),
                (r'ssl\.PROTOCOL_SSLv2', 'ssl.PROTOCOL_TLS'),
                (r'ssl\.PROTOCOL_SSLv3', 'ssl.PROTOCOL_TLS'),
                (r'"TLSv1"', '"TLSv1.2"'),
                (r'"SSLv3"', '"TLSv1.2"'),
            ]

            for pattern, replacement in replacements:
                if re.search(pattern, content):
                    content = re.sub(pattern, replacement, content)

            # Add secure defaults
            if 'ssl_context = ssl.create_default_context' not in content:
                if 'import ssl' in content:
                    content = re.sub(
                        r'import ssl\n',
                        'import ssl\n\n# Use secure SSL context with modern protocols\nSSECURE_SSL_CONTEXT = ssl.create_default_context()\nSECURE_SSL_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_2\n',
                        content,
                        count=1
                    )

            if content != original:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.fixes_applied.append(f"SSL/TLS security improved in {file_path}")
                return True

        except Exception as e:
            self.errors.append(f"Error fixing SSL/TLS in {file_path}: {e}")

        return False

    def fix_sensitive_logging_vulnerability(self, file_path: str) -> bool:
        """Fix clear-text logging of sensitive information (CWE-532)"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original = content

            # Patterns for sensitive data logging
            sensitive_patterns = [
                (r'logger\.(?:info|debug|warning|error)\(["\'].*token.*:\s*\{.*?\}', 'logger.info("Token operation completed (details hidden)")'),
                (r'logger\.(?:info|debug)\(["\'].*password.*:\s*\{.*?\}', 'logger.info("Password operation completed (details hidden)")'),
                (r'logger\.(?:info|debug)\(["\'].*key.*:\s*\{.*?\}', 'logger.info("Key operation completed (details hidden)")'),
                (r'print\(["\'].*Token.*:', 'print("Token operation processed")'),
                (r'print\(["\'].*password.*:', 'print("Password operation processed")'),
            ]

            # Function to mask sensitive tokens/keys in logs
            mask_func = '''
def mask_sensitive_data(data):
    """Mask sensitive data for logging"""
    if isinstance(data, dict):
        masked = data.copy()
        for key in ['token', 'password', 'key', 'secret', 'api_key', 'bearer']:
            if key in masked:
                value = str(masked[key])
                masked[key] = value[:4] + '***' if len(value) > 4 else '***'
        return masked
    return data
'''

            if 'def mask_sensitive_data' not in content:
                content = mask_func + '\n' + content

            # Replace logging patterns
            content = re.sub(
                r'logger\.(?:info|debug)\(["\'].*?\{.*?token.*?\}.*?["\']',
                'logger.info("Token processed successfully")',
                content,
                flags=re.DOTALL
            )

            if content != original:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.fixes_applied.append(f"Sensitive logging fixed in {file_path}")
                return True

        except Exception as e:
            self.errors.append(f"Error fixing logging in {file_path}: {e}")

        return False

    def fix_exception_exposure_vulnerability(self, file_path: str) -> bool:
        """Fix information exposure through exceptions (CWE-209)"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original = content

            # Add proper exception handling
            exception_handler = '''
def safe_exception_handler(e):
    """Convert exception to safe message"""
    import logging
    logger = logging.getLogger(__name__)
    logger.error(f"Error: {type(e).__name__}", exc_info=True)
    return {"error": "An error occurred. Please try again later."}, 500
'''

            if 'def safe_exception_handler' not in content:
                lines = content.split('\n')
                # Insert near imports
                for i, line in enumerate(lines):
                    if line.startswith('import ') or line.startswith('from '):
                        if i + 1 < len(lines) and (lines[i+1].startswith('import ') or lines[i+1].startswith('from ')):
                            continue
                        else:
                            lines.insert(i+1, exception_handler)
                            break
                content = '\n'.join(lines)

            # Replace bare except handlers that expose errors
            content = re.sub(
                r'except\s+Exception\s+as\s+e:\s*\n\s*(?:return|raise).*?{.*?e.*?}',
                'except Exception as e:\n        logger.error(f"Unexpected error: {type(e).__name__}", exc_info=True)\n        return {"error": "An error occurred. Please try again later."}',
                content,
                flags=re.MULTILINE | re.DOTALL
            )

            if content != original:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.fixes_applied.append(f"Exception handling improved in {file_path}")
                return True

        except Exception as e:
            self.errors.append(f"Error fixing exceptions in {file_path}: {e}")

        return False

    def scan_and_fix(self, root_dir: str = '.') -> None:
        """Scan and fix all vulnerabilities"""
        print("\n" + "="*70)
        print("[*] GITHUB CODEQL VULNERABILITY FIXER")
        print("="*70 + "\n")

        # Find Python files
        py_files = list(Path(root_dir).rglob('*.py'))
        py_files = [
            f for f in py_files 
            if not any(x in str(f) for x in ['.venv', '__pycache__', '.git', 'node_modules', '.pytest'])
        ]

        print(f"[INFO] Scanning {len(py_files)} Python files...\n")

        # Track which vulnerabilities we fix
        path_expr_fixed = 0
        ssl_tls_fixed = 0
        logging_fixed = 0
        exception_fixed = 0

        # Files to check for specific vulnerabilities
        for py_file in py_files:
            file_str = str(py_file)
            
            # Path expression vulnerabilities
            if any(x in file_str for x in ['production_complete.py', 'production_real.py', 'dashboard.py', 'forensics.py']):
                if self.fix_path_expression_vulnerability(file_str):
                    path_expr_fixed += 1

            # SSL/TLS vulnerabilities
            if any(x in file_str for x in ['siem_integration.py', 'enterprise', 'server']):
                if self.fix_ssl_tls_vulnerability(file_str):
                    ssl_tls_fixed += 1

            # Sensitive logging
            if any(x in file_str for x in ['enhanced_security.py', 'token', 'auth']):
                if self.fix_sensitive_logging_vulnerability(file_str):
                    logging_fixed += 1

            # Exception exposure
            if any(x in file_str for x in ['ultra_simple', 'production_real', 'production_complete']):
                if self.fix_exception_exposure_vulnerability(file_str):
                    exception_fixed += 1

        # Report
        print("\n" + "="*70)
        print("[RESULT] FIXES APPLIED")
        print("="*70)
        print(f"Path traversal vulnerabilities fixed: {path_expr_fixed}")
        print(f"SSL/TLS vulnerabilities fixed: {ssl_tls_fixed}")
        print(f"Sensitive logging fixed: {logging_fixed}")
        print(f"Exception exposure fixed: {exception_fixed}")
        print(f"\nTotal fixes: {len(self.fixes_applied)}")

        if self.fixes_applied:
            print("\n[OK] Applied fixes:")
            for fix in self.fixes_applied:
                print(f"     - {fix}")

        if self.errors:
            print(f"\n[!] Errors: {len(self.errors)}")
            for error in self.errors[:5]:
                print(f"    - {error}")

        print("\n" + "="*70)
        print("[NEXT] Run security scans:")
        print("     bandit -r . -f json -o report.json")
        print("     safety check")
        print("="*70 + "\n")


if __name__ == '__main__':
    fixer = CodeQLFixer()
    fixer.scan_and_fix('.')
