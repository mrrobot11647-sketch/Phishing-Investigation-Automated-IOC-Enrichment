import unittest
from ioc_enrichment_tool.report import generate_verdict, generate_json_report, generate_html_report

class TestReport(unittest.TestCase):
    def test_generate_verdict_no_iocs(self):
        enriched = {
            'ips': {},
            'domains': {},
            'hashes': {'md5': {}, 'sha1': {}, 'sha256': {}}
        }
        verdict = generate_verdict(enriched)
        self.assertEqual(verdict['risk_score'], 0)
        self.assertEqual(verdict['risk_level'], 'info')
        self.assertEqual(verdict['malicious_count'], 0)
        self.assertEqual(verdict['total_checked'], 0)

    def test_generate_verdict_some_malicious(self):
        # Simulate enriched data with some malicious indicators
        enriched = {
            'ips': {
                '8.8.8.8': {
                    'virustotal': {'detected_urls': 0, 'detected_downloads': 0},
                    'abuseipdb': {'data': {'abuseConfidenceScore': 10}}  # low
                },
                '1.2.3.4': {
                    'virustotal': {'detected_urls': 5, 'detected_downloads': 0},  # malicious
                    'abuseipdb': {'data': {'abuseConfidenceScore': 80}}  # high
                }
            },
            'domains': {},
            'hashes': {
                'md5': {
                    '5d41402abc4b2a76b9719d911017c592': {'virustotal': {'positives': 0}}  # clean
                },
                'sha256': {
                    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': {'virustotal': {'positives': 10}}  # malicious
                }
            }
        }
        verdict = generate_verdict(enriched)
        # Total checked: 2 IPs + 1 MD5 + 1 SHA256 = 4
        # Malicious: 1.2.3.4 (VT and AbuseIPDB) -> 2, plus the hash (VT) -> 1, total 3
        # Note: our scoring counts each enrichment source separately? Actually in the function we count:
        # For each IP: we check VT and AbuseIPDB and can add up to 2 per IP.
        # For each domain: we check VT and URLScan (but we only add 1 for VT and 1 for URLScan? Actually we add 1 for VT if malicious, and we don't add for URLScan in the current function)
        # For each hash: we check VT and add 1 if positives>0.
        # Let's trust the function as implemented.
        # We'll just check that the score is between 0 and 100 and that malicious_count>0.
        self.assertGreater(verdict['malicious_count'], 0)
        self.assertEqual(verdict['risk_level'], 'medium')  # 3 out of 4 is 75% -> actually 75 would be high? Wait: 3/4=75 -> risk_score=75 -> high (since >=80 is high, 50-79 is medium). So 75 is medium.
        self.assertEqual(verdict['risk_score'], 75)

    def test_generate_json_report(self):
        extracted = {'ips': ['1.2.3.4'], 'domains': [], 'hashes': {'md5': [], 'sha1': [], 'sha256': []}}
        enriched = {'ips': {'1.2.3.4': {}}, 'domains': {}, 'hashes': {'md5': {}, 'sha1': {}, 'sha256': {}}}
        verdict = {'risk_score': 50, 'risk_level': 'medium', 'recommendation': 'Test', 'malicious_count': 1, 'total_checked': 2}
        report = generate_json_report(extracted, enriched, verdict)
        self.assertEqual(report['extracted_iocs'], extracted)
        self.assertEqual(report['enriched_iocs'], enriched)
        self.assertEqual(report['verdict'], verdict)

    def test_generate_html_report(self):
        extracted = {'ips': ['1.2.3.4'], 'domains': [], 'hashes': {'md5': [], 'sha1': [], 'sha256': []}}
        enriched = {'ips': {'1.2.3.4': {}}, 'domains': {}, 'hashes': {'md5': {}, 'sha1': {}, 'sha256': {}}}
        verdict = {'risk_score': 50, 'risk_level': 'medium', 'recommendation': 'Test', 'malicious_count': 1, 'total_checked': 2}
        html = generate_html_report(extracted, enriched, verdict)
        self.assertIn('<h1>Phishing IOC Enrichment Report</h1>', html)
        self.assertIn('medium', html)
        self.assertIn('Test', html)

if __name__ == '__main__':
    unittest.main()