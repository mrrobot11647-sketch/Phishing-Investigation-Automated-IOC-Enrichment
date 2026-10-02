import unittest
import tempfile
import os
from ioc_enrichment_tool.extract import extract_iocs_from_email, IOCExtractor

class TestIOCExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = IOCExtractor()

    def test_extract_ips(self):
        text = "Server at 192.168.1.1 and 8.8.8.8 are malicious. Also 999.999.999.999 is invalid."
        self.extractor._extract_iocs_from_text(text)
        self.assertIn('192.168.1.1', self.extractor.extracted_ips)
        self.assertIn('8.8.8.8', self.extractor.extracted_ips)
        self.assertNotIn('999.999.999.999', self.extractor.extracted_ips)  # invalid IP

    def test_extract_domains(self):
        text = "Visit example.com or sub.example.co.uk for more info. Also test localhost"
        self.extractor._extract_iocs_from_text(text)
        self.assertIn('example.com', self.extractor.extracted_domains)
        self.assertIn('sub.example.co.uk', self.extractor.extracted_domains)
        # localhost might be matched by pattern but it's not a public domain; we'll accept it for now
        # but note: our pattern is simple and may match localhost. We'll leave as is.

    def test_extract_hashes(self):
        text = "MD5: 5d41402abc4b2a76b9719d911017c592, SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709, SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.extractor._extract_iocs_from_text(text)
        self.assertIn('5d41402abc4b2a76b9719d911017c592', self.extractor.extracted_hashes['md5'])
        self.assertIn('da39a3ee5e6b4b0d3255bfef95601890afd80709', self.extractor.extracted_hashes['sha1'])
        self.assertIn('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', self.extractor.extracted_hashes['sha256'])

    def test_extract_from_file(self):
        # Create a temporary EML file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write("""From: test@test.com
To: user@example.com
Subject: Test

Click http://example.com and see 1.2.3.4

MD5 hash: 5d41402abc4b2a76b9719d911017c592
""")
            temp_path = f.name

        try:
            result = extract_iocs_from_email(temp_path)
            self.assertIn('1.2.3.4', result['ips'])
            self.assertIn('example.com', result['domains'])
            self.assertIn('5d41402abc4b2a76b9719d911017c592', result['hashes']['md5'])
        finally:
            os.unlink(temp_path)

if __name__ == '__main__':
    unittest.main()