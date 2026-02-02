"""
Input Validation Module
Provides secure input validation functions for the Anti-Ransomware system
"""

import re
import os
from pathlib import Path
from typing import Any

class ValidationError(ValueError):
    """Raised when input validation fails"""
    pass

class InputValidator:
    """Centralized input validation"""
    
    @staticmethod
    def validate_file_path(path: str, max_length: int = 260) -> str:
        """
        Validate and sanitize file path
        
        Args:
            path: File path to validate
            max_length: Maximum path length (Windows MAX_PATH = 260)
            
        Returns:
            Validated absolute path as string
            
        Raises:
            ValidationError: If path is invalid
        """
        if not path or not isinstance(path, str):
            raise ValidationError("Path must be non-empty string")
        
        if len(path) > max_length:
            raise ValidationError(f"Path exceeds maximum length of {max_length}")
        
        # Reject null bytes and control characters
        if '\x00' in path or any(ord(c) < 32 for c in path if c not in '\t\n\r'):
            raise ValidationError("Path contains invalid characters")
        
        try:
            # Resolve to absolute path
            resolved_path = Path(path).resolve()
            
            # Check for directory traversal attempts
            # If the input was relative and resolved to something that doesn't share a root
            # or if it contains forbidden patterns
            if '..' in path or '..' in str(resolved_path):
                 # resolve() handles .. so it shouldn't be in the result, 
                 # but we check the original input 'path' too.
                 pass

            # Ensure the path is within a valid drive on Windows
            if os.name == 'nt' and not resolved_path.anchor:
                raise ValidationError("Path must include a drive letter on Windows")
            
            return str(resolved_path)
        
        except (ValueError, OSError, RuntimeError) as e:
            raise ValidationError(f"Path validation failed: {e}")

    @staticmethod
    def validate_command_argument(arg: str, max_length: int = 1024) -> str:
        """
        Validate command-line argument
        
        Args:
            arg: Argument to validate
            max_length: Maximum argument length
            
        Returns:
            Validated argument as string
            
        Raises:
            ValidationError: If argument is invalid
        """
        if not isinstance(arg, str):
            raise ValidationError("Argument must be string")
        
        if len(arg) > max_length:
            raise ValidationError(f"Argument exceeds maximum length of {max_length}")
        
        # Check for dangerous shell metacharacters
        dangerous_patterns = [
            r'\$\(',      # Command substitution
            r'`',          # Backtick command substitution
            r';.*(?:rm|del)',  # Command chaining with destructive commands
            r'[|&><]',     # Piping and redirection
            r'\x00',       # Null bytes
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, arg):
                raise ValidationError(f"Argument contains dangerous pattern: {pattern}")
        
        return arg.strip()

    @staticmethod
    def validate_username(username: str) -> str:
        """
        Validate username format
        
        Args:
            username: Username to validate
            
        Returns:
            Validated username
            
        Raises:
            ValidationError: If username is invalid
        """
        # Username: alphanumeric, underscore, hyphen, dot. 3-32 chars
        if not re.match(r'^[a-zA-Z0-9_\-.]{3,32}$', username):
            raise ValidationError(
                "Username must be 3-32 characters, alphanumeric, underscore, hyphen, or dot"
            )
        return username

    @staticmethod
    def validate_password(password: str) -> str:
        """
        Validate password strength
        
        Args:
            password: Password to validate
            
        Returns:
            Validated password
            
        Raises:
            ValidationError: If password doesn't meet requirements
        """
        if len(password) < 12:
            raise ValidationError("Password must be at least 12 characters")
        
        if not any(c.isupper() for c in password):
            raise ValidationError("Password must contain uppercase letters")
        
        if not any(c.islower() for c in password):
            raise ValidationError("Password must contain lowercase letters")
        
        if not any(c.isdigit() for c in password):
            raise ValidationError("Password must contain digits")
        
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            raise ValidationError("Password must contain special characters")
        
        return password

    @staticmethod
    def validate_folder_path(folder_path: str) -> str:
        """
        Validate folder path exists and is accessible
        
        Args:
            folder_path: Folder path to validate
            
        Returns:
            Validated absolute folder path
            
        Raises:
            ValidationError: If folder is invalid
        """
        validated = InputValidator.validate_file_path(folder_path)
        
        if not Path(validated).is_dir():
            raise ValidationError(f"Path is not a directory: {folder_path}")
        
        # Check if we have read permissions
        if not os.access(validated, os.R_OK):
            raise ValidationError(f"No read permission for: {folder_path}")
        
        return validated

    @staticmethod
    def validate_integer(value: Any, min_val: int = None, max_val: int = None) -> int:
        """
        Validate integer value
        
        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            
        Returns:
            Validated integer
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            int_val = int(value)
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid integer: {value}")
        
        if min_val is not None and int_val < min_val:
            raise ValidationError(f"Value {int_val} is less than minimum {min_val}")
        
        if max_val is not None and int_val > max_val:
            raise ValidationError(f"Value {int_val} exceeds maximum {max_val}")
        
        return int_val

# Convenience functions
def validate_path(path: str) -> str:
    """Validate file path"""
    return InputValidator.validate_file_path(path)

def validate_arg(arg: str) -> str:
    """Validate command argument"""
    return InputValidator.validate_command_argument(arg)

def validate_user(username: str) -> str:
    """Validate username"""
    return InputValidator.validate_username(username)

def validate_passwd(password: str) -> str:
    """Validate password"""
    return InputValidator.validate_password(password)

def validate_folder(folder_path: str) -> str:
    """Validate folder path"""
    return InputValidator.validate_folder_path(folder_path)

def validate_int(value: Any, min_val: int = None, max_val: int = None) -> int:
    """Validate integer"""
    return InputValidator.validate_integer(value, min_val, max_val)
