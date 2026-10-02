import os
import requests
import time
from typing import Dict, Any, List, Optional
from urllib.parse import quote, urljoin
import logging

logger = logging.getLogger(__name__)

class VirusTotalEnricher:
    """Enrich IOCs using VirusTotal API."""

    BASE_URL = 'https://www.virustotal.com/vtapi/v2/'

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        if not self.api_key:
            logger.warning("VirusTotal API key not provided.")

    def _get_params(self) -> Dict[str, str]:
        return {'apikey': self.api_key}

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Get IP address report from VirusTotal."""
        if not self.api_key:
            return {'error': 'API key not configured'}
        url = urljoin(self.BASE_URL, 'ip-address/report')
        params = self._get_params()
        params['ip'] = ip
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"VirusTotal IP request failed: {e}")
            return {'error': str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Get domain report from VirusTotal."""
        if not self.api_key:
            return {'error': 'API key not configured'}
        url = urljoin(self.BASE_URL, 'domain/report')
        params = self._get_params()
        params['domain'] = domain
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"VirusTotal domain request failed: {e}")
            return {'error': str(e)}

    def enrich_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Get file hash report from VirusTotal."""
        if not self.api_key:
            return {'error': 'API key not configured'}
        url = urljoin(self.BASE_URL, 'file/report')
        params = self._get_params()
        params['resource'] = file_hash
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"VirusTotal hash request failed: {e}")
            return {'error': str(e)}


class AbuseIPDBEnricher:
    """Enrich IP addresses using AbuseIPDB API."""

    BASE_URL = 'https://api.abuseipdb.com/api/v2/'

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('ABUSEIPDB_API_KEY')
        if not self.api_key:
            logger.warning("AbuseIPDB API key not provided.")

    def _get_headers(self) -> Dict[str, str]:
        return {
            'Key': self.api_key,
            'Accept': 'application/json'
        }

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP address in AbuseIPDB."""
        if not self.api_key:
            return {'error': 'API key not configured'}
        url = urljoin(self.BASE_URL, 'check')
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        try:
            response = requests.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"AbuseIPDB request failed: {e}")
            return {'error': str(e)}


class URLScanEnricher:
    """Enrich URLs and domains using URLScan.io API."""

    BASE_URL = 'https://urlscan.io/api/v1/'

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('URLSCAN_API_KEY')
        # Note: URLScan API key is optional for some endpoints, but we'll use it if available.

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        if self.api_key:
            headers['API-Key'] = self.api_key
        return headers

    def scan_url(self, url: str) -> Dict[str, Any]:
        """Submit a URL for scanning."""
        if not self.api_key:
            return {'error': 'API key not configured (required for scanning)'}
        endpoint = urljoin(self.BASE_URL, 'scan/')
        data = {
            "url": url,
            "visibility": "public"
        }
        try:
            response = requests.post(endpoint, headers=self._get_headers(), json=data)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"URLScan scan request failed: {e}")
            return {'error': str(e)}

    def get_result(self, uuid: str) -> Dict[str, Any]:
        """Get scan result by UUID."""
        endpoint = urljoin(self.BASE_URL, f'result/{uuid}/')
        try:
            response = requests.get(endpoint, headers=self._get_headers())
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"URLScan result request failed: {e}")
            return {'error': str(e)}

    def search_domain(self, domain: str) -> Dict[str, Any]:
        """Search for scans of a domain."""
        endpoint = urljoin(self.BASE_URL, 'search/')
        params = {'q': f'domain:{domain}'}
        try:
            response = requests.get(endpoint, headers=self._get_headers(), params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"URLScan search request failed: {e}")
            return {'error': str(e)}


class IOCEnricher:
    """Main enrichment class that uses all enrichment services."""

    def __init__(self,
                 vt_api_key: Optional[str] = None,
                 abuseipdb_api_key: Optional[str] = None,
                 urlscan_api_key: Optional[str] = None):
        self.vt = VirusTotalEnricher(vt_api_key)
        self.abuseipdb = AbuseIPDBEnricher(abuseipdb_api_key)
        self.urlscan = URLScanEnricher(urlscan_api_key)

    def enrich_iocs(self, iocs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich the provided IOCs using all available services.
        Returns a dictionary with enrichment results.
        """
        enriched = {
            'ips': {},
            'domains': {},
            'hashes': {
                'md5': {},
                'sha1': {},
                'sha256': {}
            }
        }

        # Enrich IPs
        for ip in iocs.get('ips', []):
            enriched_ip = {}
            # VirusTotal
            vt_result = self.vt.enrich_ip(ip)
            enriched_ip['virustotal'] = vt_result
            # AbuseIPDB
            abuse_result = self.abuseipdb.enrich_ip(ip)
            enriched_ip['abuseipdb'] = abuse_result
            enriched['ips'][ip] = enriched_ip

        # Enrich Domains
        for domain in iocs.get('domains', []):
            enriched_domain = {}
            # VirusTotal
            vt_result = self.vt.enrich_domain(domain)
            enriched_domain['virustotal'] = vt_result
            # URLScan (search for domain)
            urlscan_result = self.urlscan.search_domain(domain)
            enriched_domain['urlscan'] = urlscan_result
            enriched['domains'][domain] = enriched_domain

        # Enrich Hashes
        for hash_type in ['md5', 'sha1', 'sha256']:
            for file_hash in iocs.get('hashes', {}).get(hash_type, []):
                vt_result = self.vt.enrich_file_hash(file_hash)
                enriched['hashes'][hash_type][file_hash] = {'virustotal': vt_result}

        return enriched


def enrich_iocs(iocs: Dict[str, Any],
                vt_api_key: Optional[str] = None,
                abuseipdb_api_key: Optional[str] = None,
                urlscan_api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to enrich IOCs.
    """
    enricher = IOCEnricher(vt_api_key, abuseipdb_api_key, urlscan_api_key)
    return enricher.enrich_iocs(iocs)


if __name__ == '__main__':
    # Simple test (requires API keys set as environment variables)
    import sys
    if len(sys.argv) < 2:
        print("Usage: python enrich.py <ioc_json_file>")
        sys.exit(1)

    import json
    with open(sys.argv[1], 'r') as f:
        iocs = json.load(f)

    enriched = enrich_iocs(iocs)
    print(json.dumps(enriched, indent=2))