"""Test database path resolution"""
import os
from pathlib import Path

def _get_secure_app_dir():
    """Get secure application directory with fallback"""
    try:
        # Try ProgramData first (requires admin)
        program_data = Path(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'))
        app_dir = program_data / "AntiRansomware"
        app_dir.mkdir(parents=True, exist_ok=True)
        print(f"✅ Using system directory: {app_dir}")
        return app_dir
    except PermissionError:
        # Fallback to user directory if no admin rights
        print("⚠️  Admin rights required for system-wide protection. Using user directory.")
        user_dir = Path(os.path.expanduser("~")) / "AppData" / "Local" / "UnifiedAntiRansomware"
        user_dir.mkdir(parents=True, exist_ok=True)
        print(f"✅ Using user directory: {user_dir}")
        return user_dir

if __name__ == "__main__":
    app_dir = _get_secure_app_dir()
    db_path = app_dir / "protection.db"
    print(f"Final database path: {db_path}")
    print(f"Directory exists: {app_dir.exists()}")
    print(f"Directory writable: {os.access(app_dir, os.W_OK)}")
