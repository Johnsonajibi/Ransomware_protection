
import unittest
import pickle
import os
import sys

# Mocking the safe_load logic to test isolation
class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow safe modules
        if module in ['numpy', 'sklearn.ensemble._iforest', 'sklearn.preprocessing._data', 
                    'datetime', 'collections', 'sklearn.tree._classes']:
            return super().find_class(module, name)
        # Block everything else to prevent RCE
        raise pickle.UnpicklingError(f"Unsafe global '{module}.{name}' detected")

def safe_load(file_obj):
    return SafeUnpickler(file_obj).load()

class TestSafePickle(unittest.TestCase):
    def test_block_os_system(self):
        """Test that os.system cannot be unpickled"""
        # Create a malicious payload
        class Malicious:
            def __reduce__(self):
                return (os.system, ('echo hacked',))
        
        # We can't actually pickle os.system easily like this in a simple script without it executing during pickling sometimes
        # typically exploits construct the bytes directly or use valid reduce instructions.
        # A simpler way is to try to unpickle a reference to os.system
        
        payload = b'\x80\x03cos\nsystem\nq\x00X\x0b\x00\x00\x00echo hackedq\x01\x85q\x02Rq\x03.'
        
        with self.assertRaises(pickle.UnpicklingError) as cm:
            safe_load(io.BytesIO(payload))
        
        self.assertIn("Unsafe global", str(cm.exception))
        print("✅ SafeUnpickler correctly blocked os.system")

if __name__ == "__main__":
    import io
    # Initializing manually to run specific test logic inline
    try:
        t = TestSafePickle()
        t.test_block_os_system()
    except Exception as e:
        print(f"Test failed: {e}")
