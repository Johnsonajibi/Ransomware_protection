import sys, os, pathlib, traceback, sqlite3, tempfile

LOG = r'C:\Users\ajibi\AppData\Local\Temp\ar_admin_crash.log'

def _reset_path_acls(path_str):
    import subprocess as _sp
    try:
        _sp.run(['takeown', '/F', path_str, '/R', '/D', 'Y'],
                capture_output=True, timeout=30)
        _sp.run(['icacls', path_str, '/grant:r', 'Administrators:F',
                 '/T', '/C', '/Q'], capture_output=True, timeout=30)
        _sp.run(['icacls', path_str, '/remove:d', 'Everyone',
                 '/T', '/C', '/Q'], capture_output=True, timeout=30)
        _sp.run(['icacls', path_str, '/reset', '/T', '/C', '/Q'],
                capture_output=True, timeout=30)
        _sp.run(['attrib', '-H', '-S', path_str, '/S', '/D'],
                capture_output=True, timeout=30)
    except Exception:
        pass

def main():
    os.environ['PYTHONUTF8'] = '1'
    os.environ['PYTHONIOENCODING'] = 'utf-8'

    # Reconfigure stdout/stderr to UTF-8 so unicode chars don't crash on Windows consoles
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        try:
            if hasattr(_stream, 'reconfigure'):
                _stream.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass


    def sqlite_works(d):
        p = d / 'protection.db'
        try:
            d.mkdir(parents=True, exist_ok=True)
            c = sqlite3.connect(str(p))
            c.execute('CREATE TABLE IF NOT EXISTS t (id INTEGER)')
            c.close()
            return True
        except Exception:
            try: p.unlink()
            except: pass
            return False

    appdata = pathlib.Path(os.environ.get('LOCALAPPDATA', '')) / 'AntiRansomware'
    tmpdir  = pathlib.Path(tempfile.gettempdir()) / 'AntiRansomware'

    for _candidate in [appdata, tmpdir]:
        _reset_path_acls(str(_candidate))

    # Also explicitly reset known config files that may retain DENY ACEs from a previous protection session
    _known_config_files = [
        'email_config.json', 'protected_paths.json',
        'siem_config.json', 'signed_events.jsonl',
        'protection.db', 'ar_config.json',
    ]
    for _fname in _known_config_files:
        _reset_path_acls(str(appdata / _fname))

    _db_path = appdata / 'protection.db'
    try:
        if os.path.exists(str(_db_path)):
            _conn = sqlite3.connect(str(_db_path))
            try:
                _rows = _conn.execute(
                    "SELECT DISTINCT details FROM activity_log WHERE event_type='FOLDER_PROTECTED'"
                ).fetchall()
                for (_detail,) in _rows:
                    if _detail and len(_detail) < 300:
                        _reset_path_acls(_detail)
            except Exception:
                pass
            try:
                _rows = _conn.execute(
                    'SELECT DISTINCT folder_path FROM protected_folders'
                ).fetchall()
                for (_p,) in _rows:
                    if _p and len(_p) < 300:
                        _reset_path_acls(_p)
            except Exception:
                pass
            _conn.close()
    except Exception:
        pass

    if sqlite_works(appdata):
        data_dir = appdata
    else:
        tmpdir.mkdir(parents=True, exist_ok=True)
        data_dir = tmpdir
    os.environ['AR_DATA_DIR'] = str(data_dir)
    print(f'[launcher] data dir: {data_dir}')

    base = r'c:\Users\ajibi\Music\Anti-Ransomeware'
    sys.path.insert(0, os.path.join(base, 'src', 'python', 'core'))
    sys.path.insert(0, os.path.join(base, 'src', 'python', 'enterprise'))
    sys.path.insert(0, os.path.join(base, 'src', 'python', 'monitoring'))
    sys.path.insert(0, os.path.join(base, 'src', 'python', 'utils'))
    sys.path.insert(0, os.path.join(base, 'src', 'python', 'auth'))
    sys.path.insert(0, os.path.join(base, 'src', 'python'))

    _orig = pathlib.Path.exists
    def _safe(self, **kw):
        try: return _orig(self, **kw)
        except PermissionError: return False
    pathlib.Path.exists = _safe

    os.chdir(base)
    import runpy
    runpy.run_path(os.path.join(base, 'src', 'python', 'gui', 'desktop_app.py'), run_name='__main__')

try:
    main()
except Exception:
    with open(LOG, 'w') as f:
        traceback.print_exc(file=f)
    import subprocess
    subprocess.run(['notepad.exe', LOG])
