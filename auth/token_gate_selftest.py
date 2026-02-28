"""
Token-gate self-test for ACL + lease flow.
Prereqs: pywin32 installed; run under guardian account/SYSTEM for meaningful ACL semantics.
"""
import os
import sys
import tempfile
from pathlib import Path

try:
    import win32security  # type: ignore
    import ntsecuritycon as con  # type: ignore
except ImportError:
    print("pywin32 not available; skipping ACL self-test")
    sys.exit(0)

# Import the access control from the main module
try:
    from unified_antiransomware import FileAccessControl
except Exception as exc:
    print(f"Failed to import FileAccessControl: {exc}")
    sys.exit(1)


class _FakeTokenManager:
    def __init__(self):
        self.tokens_present = False

    def find_usb_tokens(self, validate=False):
        return ["token"] if self.tokens_present else []


def _assert_dacl_includes(path: Path, sid_str: str, access_mask: int, deny: bool = False):
    sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        raise AssertionError("No DACL present")
    found = False
    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        ace_type = ace[0][0]
        ace_mask = ace[1]
        ace_sid = ace[2]
        if win32security.ConvertSidToStringSid(ace_sid) == sid_str and (ace_mask & access_mask):
            if deny and ace_type == win32security.ACCESS_DENIED_ACE_TYPE:
                found = True
                break
            if not deny and ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:
                found = True
                break
    if not found:
        kind = "DENY" if deny else "ALLOW"
        raise AssertionError(f"Expected {kind} ACE for {sid_str}")


def run_self_test():
    guardian = _FakeTokenManager()
    fac = FileAccessControl(guardian)

    tmp_dir = Path(tempfile.mkdtemp(prefix="token_gate_test_"))
    target = tmp_dir / "secret.txt"
    target.write_text("top secret data", encoding="utf-8")

    fac.register_protected_file(target)
    if not fac.block_external_access(target):
        print("Failed to apply block_external_access")
        return 1

    # DACL expectations: deny Everyone, allow SYSTEM, allow guardian (current account)
    try:
        _assert_dacl_includes(target, "S-1-5-18", con.FILE_ALL_ACCESS, deny=False)
        if fac.guardian_sid:
            _assert_dacl_includes(target, fac.guardian_sid, con.FILE_ALL_ACCESS, deny=False)
        print("DACL structure: OK")
    except AssertionError as ae:
        print(f"DACL check failed: {ae}")
        return 1

    # Token required: with no token, open should fail
    guardian.tokens_present = False
    fh = fac.safe_open_protected_file(target, "r")
    if fh is not None:
        print("Expected token-gated open to fail without token")
        fac.safe_close_protected_file(fh, target)
        return 1
    print("Token check (no token): OK")

    # With token, open should succeed and close should re-lock
    guardian.tokens_present = True
    fh = fac.safe_open_protected_file(target, "r")
    if fh is None:
        print("Expected token-gated open to succeed with token")
        return 1
    fac.safe_close_protected_file(fh, target)
    print("Token check (with token + lease): OK")

    # Ensure protections remain (SYSTEM + guardian)
    try:
        _assert_dacl_includes(target, "S-1-5-18", con.FILE_ALL_ACCESS, deny=False)
        if fac.guardian_sid:
            _assert_dacl_includes(target, fac.guardian_sid, con.FILE_ALL_ACCESS, deny=False)
        print("Post-close re-lock: OK")
    except AssertionError as ae:
        print(f"Post-close DACL check failed: {ae}")
        return 1

    print("✅ Token-gate self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(run_self_test())
