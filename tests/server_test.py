import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import launch

class LaunchTests(unittest.TestCase):
    def test_find_no_install(self):
        self.assertIsNone(launch.find_ghidra('/path/that/does/not/exist'))
    def test_magic(self):
        self.assertTrue(launch.is_executable(b'\x7fELF......'))
        self.assertTrue(launch.is_executable(b'MZ' + b'\x00'*60))
        self.assertFalse(launch.is_executable(b'\x55\x48\x89\xe5'))
    def test_reject_raw(self):
        with self.assertRaisesRegex(ValueError, 'recognized executable'):
            launch.analyze(b'\x55\x48\x89\xe5', 'raw.bin', Path('/not/installed'))

if __name__ == '__main__':
    unittest.main()
