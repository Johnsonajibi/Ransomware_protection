#!/usr/bin/env python3
"""
Test Path Validation Security
Tests for path traversal vulnerability fixes
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote


def validate_path(path: str, base_dir: str = None) -> bool:
    """
    Validate path to prevent directory traversal attacks.
    
    Args:
        path: The path to validate
        base_dir: Optional base directory that path must be within
        
    Returns:
        True if path is safe, False otherwise
    """
    if not path or not isinstance(path, str):
        return False
    
    # Decode URL-encoded characters to catch %2e%2e attacks
    decoded_path = unquote(path)
    
    # Get absolute and normalized path
    abs_path = os.path.abspath(decoded_path)
    normalized = os.path.normpath(abs_path)
    
    # Check for directory traversal patterns
    if '..' in normalized or '..' in decoded_path:
        return False
    
    # Check for home directory expansion
    if '~' in decoded_path:
        return False
    
    # If base_dir specified, ensure path is within it
    if base_dir:
        base_abs = os.path.abspath(base_dir)
        # Ensure the normalized path is within base_abs (with proper separator check)
        if not (normalized.startswith(base_abs) and 
                (len(normalized) == len(base_abs) or 
                 normalized[len(base_abs):len(base_abs)+1] in (os.sep, os.altsep) or
                 normalized[len(base_abs):len(base_abs)+1] == '')):
            return False
    
    # Validate Windows paths
    if os.name == 'nt':
        # Check for valid drive letter
        if len(normalized) >= 2 and normalized[1] == ':':
            if not normalized[0].isalpha():
                return False
        # Check for UNC paths
        if normalized.startswith('\\\\'):
            return False
    
    return True


class TestPathValidation(unittest.TestCase):
    """Test path validation functions against various attack vectors"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.base_dir = os.path.abspath(self.temp_dir)
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_valid_paths(self):
        """Test that valid paths are accepted"""
        valid_path = os.path.join(self.base_dir, "test.txt")
        self.assertTrue(validate_path(valid_path))
    
    def test_directory_traversal_attacks(self):
        """Test that directory traversal attempts are blocked"""
        attack_vectors = [
            "../etc/passwd",
            "../../etc/passwd",
            "./../../etc/passwd",
            "test/../../../etc/passwd",
            "test/../../etc/passwd",
        ]
        
        for attack in attack_vectors:
            with self.subTest(attack=attack):
                self.assertFalse(validate_path(attack),
                               f"Failed to block: {attack}")
    
    def test_url_encoded_traversal(self):
        """Test that URL-encoded traversal attempts are blocked"""
        attack_vectors = [
            "%2e%2e/etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "test%2f%2e%2e%2f%2e%2e%2fetc",
        ]
        
        for attack in attack_vectors:
            with self.subTest(attack=attack):
                self.assertFalse(validate_path(attack),
                               f"Failed to block URL-encoded: {attack}")
    
    def test_tilde_expansion_blocked(self):
        """Test that tilde expansion is blocked"""
        attack_vectors = [
            "~/etc/passwd",
            "~root/",
            "/tmp/~test",
        ]
        
        for attack in attack_vectors:
            with self.subTest(attack=attack):
                self.assertFalse(validate_path(attack),
                               f"Failed to block tilde: {attack}")
    
    def test_base_directory_restriction(self):
        """Test that paths can be restricted to base directory"""
        # Path within base directory should be allowed
        inside_path = os.path.join(self.base_dir, "subdir", "file.txt")
        self.assertTrue(validate_path(inside_path, self.base_dir))
        
        # Path outside base directory should be blocked
        outside_path = "/tmp/outside/file.txt"
        self.assertFalse(validate_path(outside_path, self.base_dir))
        
        # Test for base_dir bypass attempt (e.g., /home/user vs /home/user_malicious)
        if self.base_dir == "/tmp/tmpXYZ":
            bypass_attempt = "/tmp/tmpXYZ_malicious/file.txt"
            self.assertFalse(validate_path(bypass_attempt, self.base_dir),
                           "Failed to block base_dir bypass with similar prefix")
    
    def test_null_and_invalid_inputs(self):
        """Test that null and invalid inputs are rejected"""
        invalid_inputs = [
            None,
            "",
            123,
            [],
            {},
        ]
        
        for invalid in invalid_inputs:
            with self.subTest(invalid=invalid):
                self.assertFalse(validate_path(invalid))
    
    @unittest.skipUnless(os.name == 'nt', "Windows-specific test")
    def test_windows_unc_paths_blocked(self):
        """Test that UNC paths are blocked on Windows"""
        unc_paths = [
            "\\\\server\\share",
            "\\\\192.168.1.1\\share",
            "\\\\?\\C:\\test",
        ]
        
        for unc in unc_paths:
            with self.subTest(unc=unc):
                self.assertFalse(validate_path(unc),
                               f"Failed to block UNC path: {unc}")
    
    @unittest.skipUnless(os.name == 'nt', "Windows-specific test")
    def test_windows_invalid_drive_letters(self):
        """Test that invalid drive letters are rejected on Windows"""
        invalid_drives = [
            "1:\\test",
            "@:\\test",
            "!:\\test",
        ]
        
        for drive in invalid_drives:
            with self.subTest(drive=drive):
                self.assertFalse(validate_path(drive),
                               f"Failed to reject invalid drive: {drive}")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
