import re
import email
from email import policy
from email.parser import BytesParser
from typing import List, Set, Dict, Any
import hashlib
import os


class IOCExtractor:
    """Extract Indicators of Compromise (IOCs) from email files."""

    # Regex patterns for IOCs
    IPV4_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    # Simple domain pattern (can be improved)
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    # Hash patterns: MD5, SHA1, SHA256
    HASH_PATTERNS = {
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    }

    def __init__(self):
        self.extracted_ips: Set[str] = set()
        self.extracted_domains: Set[str] = set()
        self.extracted_hashes: Dict[str, Set[str]] = {
            'md5': set(),
            'sha1': set(),
            'sha256': set(),
        }

    def extract_from_file(self, file_path: str) -> Dict[str, Any]:
        """
        Extract IOCs from an email file (EML or MSG).
        Returns a dictionary with lists of IPs, domains, and hashes.
        """
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # Extract from headers, body, and attachments
        self._extract_from_headers(msg)
        self._extract_from_body(msg)
        self._extract_from_attachments(msg)

        return {
            'ips': list(self.extracted_ips),
            'domains': list(self.extracted_domains),
            'hashes': {
                'md5': list(self.extracted_hashes['md5']),
                'sha1': list(self.extracted_hashes['sha1']),
                'sha256': list(self.extracted_hashes['sha256']),
            }
        }

    def _extract_from_headers(self, msg: email.message.EmailMessage):
        """Extract IOCs from email headers."""
        for header, value in msg.items():
            if value:
                self._extract_iocs_from_text(value)

    def _extract_from_body(self, msg: email.message.EmailMessage):
        """Extract IOCs from email body (plain text and HTML)."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain' or content_type == 'text/html':
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            text = payload.decode('utf-8', errors='ignore')
                            self._extract_iocs_from_text(text)
                        except UnicodeDecodeError:
                            pass
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    text = payload.decode('utf-8', errors='ignore')
                    self._extract_iocs_from_text(text)
                except UnicodeDecodeError:
                    pass

    def _extract_from_attachments(self, msg: email.message.EmailMessage):
        """Extract IOCs from attachment filenames and optionally contents."""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        self._extract_iocs_from_text(filename)
                    # Optionally, we could extract hashes from attachment payload
                    # but for simplicity, we skip content extraction for attachments.
                    # In a more advanced version, we could compute hash of attachment.

    def _extract_iocs_from_text(self, text: str):
        """Extract IOCs from a given text string using regex patterns."""
        # IPs
        ips = self.IPV4_PATTERN.findall(text)
        self.extracted_ips.update(ips)

        # Domains
        domains = self.DOMAIN_PATTERN.findall(text)
        # Filter out common false positives (optional)
        self.extracted_domains.update(domains)

        # Hashes
        for hash_type, pattern in self.HASH_PATTERNS.items():
            matches = pattern.findall(text)
            self.extracted_hashes[hash_type].update(matches)


def extract_iocs_from_email(file_path: str) -> Dict[str, Any]:
    """
    Convenience function to extract IOCs from an email file.
    """
    extractor = IOCExtractor()
    return extractor.extract_from_file(file_path)


if __name__ == '__main__':
    # Simple test
    import sys
    if len(sys.argv) > 1:
        result = extract_iocs_from_email(sys.argv[1])
        print(result)
    else:
        print("Usage: python extract.py <email_file>")