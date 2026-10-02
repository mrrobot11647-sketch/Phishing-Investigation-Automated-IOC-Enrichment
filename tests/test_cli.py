import unittest
import sys
from io import StringIO
from ioc_enrichment_tool.cli import main

class TestCLI(unittest.TestCase):
    def test_help(self):
        # Test that help exits with 0
        test_args = ["prog", "--help"]
        sys.argv = test_args
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 0)

    def test_missing_email_file(self):
        # Test that missing file gives error
        test_args = ["prog", "nonexistent.eml"]
        sys.argv = test_args
        # Capture stderr
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 1)
            output = sys.stderr.getvalue()
            self.assertIn("Error: File 'nonexistent.eml' not found.", output)
        finally:
            sys.stderr = old_stderr

if __name__ == '__main__':
    unittest.main()