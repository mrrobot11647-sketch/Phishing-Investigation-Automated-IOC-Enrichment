import json
import html
from typing import Dict, Any, Optional
from datetime import datetime


def generate_verdict(enriched_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a verdict based on enriched IOC data.
    Returns a dictionary with risk level, score, and recommendation.
    """
    # Simple scoring: count malicious indicators from each source
    malicious_score = 0
    total_checked = 0

    # Check IPs
    for ip, data in enriched_data.get('ips', {}).items():
        total_checked += 1
        # VirusTotal: check if malicious count > 0
        vt = data.get('virustotal', {})
        if vt.get('detected_urls') or vt.get('detected_downloads'):
            # Actually, we need to look at the response structure.
            # For simplicity, we'll check if there are any detections.
            # In VT ip-address/report, 'detected_urls' and 'detected_downloads' indicate malicious.
            if vt.get('detected_urls', 0) > 0 or vt.get('detected_downloads', 0) > 0:
                malicious_score += 1
        # AbuseIPDB: check if abuseConfidenceScore > threshold (e.g., 50)
        abuse = data.get('abuseipdb', {})
        if abuse.get('data', {}).get('abuseConfidenceScore', 0) > 50:
            malicious_score += 1

    # Check Domains
    for domain, data in enriched_data.get('domains', {}).items():
        total_checked += 1
        vt = data.get('virustotal', {})
        if vt.get('detected_urls', 0) > 0 or vt.get('detected_downloads', 0) > 0:
            malicious_score += 1
        urlscan = data.get('urlscan', {})
        # URLScan search result: if there are any results, we might consider it suspicious.
        # But for simplicity, we'll just note that it was seen in URLScan.
        # We could check the verdict of the scans, but that requires more complex parsing.
        # We'll leave it as informational for now.

    # Check Hashes
    for hash_type in ['md5', 'sha1', 'sha256']:
        for file_hash, data in enriched_data.get('hashes', {}).get(hash_type, {}).items():
            total_checked += 1
            vt = data.get('virustotal', {})
            if vt.get('positives', 0) > 0:
                malicious_score += 1

    # Calculate risk level (0-100 scale)
    if total_checked == 0:
        risk_score = 0
        risk_level = 'info'
        recommendation = 'No IOCs found or unable to check.'
    else:
        risk_score = int((malicious_score / total_checked) * 100)
        if risk_score >= 80:
            risk_level = 'high'
            recommendation = 'High risk: Strong indicators of malicious activity. Consider blocking and further investigation.'
        elif risk_score >= 50:
            risk_level = 'medium'
            recommendation = 'Medium risk: Some indicators of suspicious activity. Monitor and investigate.'
        elif risk_score > 0:
            risk_level = 'low'
            recommendation = 'Low risk: Minimal indicators of malicious activity. Log for awareness.'
        else:
            risk_level = 'info'
            recommendation = 'No malicious indicators detected. Likely benign.'

    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'recommendation': recommendation,
        'malicious_count': malicious_score,
        'total_checked': total_checked,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }


def generate_json_report(extracted_iocs: Dict[str, Any],
                         enriched_iocs: Dict[str, Any],
                         verdict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a comprehensive JSON report.
    """
    return {
        'extracted_iocs': extracted_iocs,
        'enriched_iocs': enriched_iocs,
        'verdict': verdict
    }


def generate_html_report(extracted_iocs: Dict[str, Any],
                         enriched_iocs: Dict[str, Any],
                         verdict: Dict[str, Any]) -> str:
    """
    Generate an HTML report.
    """
    # We'll create a simple HTML template.
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Phishing IOC Enrichment Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1, h2 {{ color: #2c3e50; }}
            .verdict {{ padding: 20px; background-color: #ecf0f1; border-radius: 5px; margin-bottom: 30px; }}
            .high {{ background-color: #ffdddd; border-left: 5px solid #e74c3c; }}
            .medium {{ background-color: #ffffcc; border-left: 5px solid #f1c40f; }}
            .low {{ background-color: #ddffdd; border-left: 5px solid #2ecc71; }}
            .info {{ background-color: #ddddff; border-left: 5px solid #3498db; }}
            .section {{ margin-bottom: 30px; }}
            .ioc-list {{ colonnes: 2; }}
            pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>Phishing IOC Enrichment Report</h1>
        <div class="verdict {risk_level_class}">
            <h2>Verdict: {risk_level}</h2>
            <p><strong>Risk Score:</strong> {risk_score}/100</p>
            <p><strong>Recommendation:</strong> {recommendation}</p>
            <p><strong>Malicious Indicators:</strong> {malicious_count} out of {total_checked} checked</p>
            <p><strong>Timestamp:</strong> {timestamp}</p>
        </div>

        <div class="section">
            <h2>Extracted IOCs</h2>
            <h3>IP Addresses ({ip_count})</h3>
            <ul class="ioc-list">
                {ip_list}
            </ul>
            <h3>Domains ({domain_count})</h3>
            <ul class="ioc-list">
                {domain_list}
            </ul>
            <h3>Hashes</h3>
            <ul class="ioc-list">
                {hash_list}
            </ul>
        </div>

        <div class="section">
            <h2>Enrichment Details (JSON)</h2>
            <pre>{enriched_json}</pre>
        </div>
    </body>
    </html>
    """

    # Helper to format lists
    def format_list(items):
        if not items:
            return '<li>None</li>'
        return ''.join([f'<li>{html.escape(str(item))}</li>' for item in items])

    ip_list = format_list(extracted_iocs.get('ips', []))
    domain_list = format_list(extracted_iocs.get('domains', []))
    hash_list = format_list(
        extracted_iocs.get('hashes', {}).get('md5', []) +
        extracted_iocs.get('hashes', {}).get('sha1', []) +
        extracted_iocs.get('hashes', {}).get('sha256', [])
    )

    # Enriched data as JSON string (pretty printed)
    enriched_json = json.dumps(enriched_iocs, indent=2)

    # Determine CSS class for risk level
    risk_level_class = verdict.get('risk_level', 'info')
    return html_template.format(
        risk_level_class=risk_level_class,
        risk_level=verdict.get('risk_level', 'unknown').upper(),
        risk_score=verdict.get('risk_score', 0),
        recommendation=verdict.get('recommendation', 'No recommendation'),
        malicious_count=verdict.get('malicious_count', 0),
        total_checked=verdict.get('total_checked', 0),
        timestamp=verdict.get('timestamp', ''),
        ip_count=len(extracted_iocs.get('ips', [])),
        domain_count=len(extracted_iocs.get('domains', [])),
        ip_list=ip_list,
        domain_list=domain_list,
        hash_list=hash_list,
        enriched_json=enriched_json
    )


def save_report(report: Dict[str, Any], output_dir: str, prefix: str = 'report'):
    """
    Save JSON and HTML reports to files.
    """
    import os
    from datetime import datetime

    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    json_path = os.path.join(output_dir, f'{prefix}_{timestamp}.json')
    html_path = os.path.join(output_dir, f'{prefix}_{timestamp}.html')

    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    # Generate HTML from the report data
    html_content = generate_html_report(
        report['extracted_iocs'],
        report['enriched_iocs'],
        report['verdict']
    )
    with open(html_path, 'w') as f:
        f.write(html_content)

    return json_path, html_path


if __name__ == '__main__':
    # Example usage (requires data)
    print("Report module - to be used with extract and enrich modules")