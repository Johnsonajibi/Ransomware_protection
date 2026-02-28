#!/usr/bin/env python3
"""
Build EXE
Build Windows executables from Python scripts using PyInstaller.
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from pathlib import Path
from typing import Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ExeBuilder:
    def __init__(self):
        self.scripts = {
            'trifactor_auth': 'trifactor_auth_manager.py',
            'desktop_gui': 'desktop_app.py',
            'admin_dashboard': 'admin_dashboard.py',
            'unified': 'unified_antiransomware.py',
            'deployment': 'deployment.py',
            'service_manager': 'service_manager.py'
        }
        self.output_dir = Path('dist')
        self.output_dir.mkdir(exist_ok=True)

    def build_exe(self, script_name: str, icon: str = None) -> bool:
        """Build a single EXE from Python script"""
        try:
            if script_name not in self.scripts:
                logger.error(f'Unknown script: {script_name}')
                return False
            
            py_file = self.scripts[script_name]
            if not Path(py_file).exists():
                logger.error(f'Python file not found: {py_file}')
                return False
            
            logger.info(f'Building {script_name} from {py_file}...')
            
            # PyInstaller command
            cmd = [
                sys.executable,
                '-m',
                'PyInstaller',
                '--onefile',
                '--windowed',
                '--name', script_name,
                '--distpath', str(self.output_dir),
                py_file
            ]
            
            if icon and Path(icon).exists():
                cmd.extend(['--icon', icon])
            
            logger.info(f'Running: {" ".join(cmd)}')
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                exe_path = self.output_dir / f'{script_name}.exe'
                logger.info(f'Successfully built: {exe_path}')
                return True
            else:
                logger.error(f'Build failed: {result.stderr}')
                return False
                
        except Exception as e:
            logger.error(f'Build error: {e}')
            return False

    def build_all(self) -> Dict:
        """Build all executables"""
        results = {}
        for script_key in self.scripts.keys():
            logger.info(f'Building {script_key}...')
            ok = self.build_exe(script_key)
            results[script_key] = 'success' if ok else 'failed'
        return results

    def list_outputs(self) -> list:
        """List built executables"""
        exes = list(self.output_dir.glob('*.exe'))
        return [{'name': e.name, 'size_mb': round(e.stat().st_size / (1024**2), 2)} for e in exes]


def main():
    parser = argparse.ArgumentParser(description='Build EXE')
    sub = parser.add_subparsers(dest='command')

    build = sub.add_parser('build', help='Build single executable')
    build.add_argument('script', choices=['trifactor_auth', 'desktop_gui', 'admin_dashboard', 'unified', 'deployment', 'service_manager'])
    build.add_argument('--icon')

    sub.add_parser('all', help='Build all executables')
    sub.add_parser('list', help='List built executables')

    args = parser.parse_args()
    builder = ExeBuilder()

    if args.command == 'build':
        ok = builder.build_exe(args.script, args.icon)
        return 0 if ok else 1

    if args.command == 'all':
        results = builder.build_all()
        print(json.dumps(results, indent=2))
        return 0

    if args.command == 'list':
        outputs = builder.list_outputs()
        print(json.dumps(outputs, indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
