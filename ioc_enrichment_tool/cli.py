import argparse
import sys
import os
from typing import Dict, Any

from .extract import extract_iocs_from_email
from .enrich import enrich_iocs
from .report import generate_json_report, save_report, generate_verdict


def main():
    parser = argparse.ArgumentParser(
        description='Extract and enrich IOCs from phishing emails.'
    )
    parser.add_argument(
        'email_file',
        help='Path to the email file (EML or MSG) to analyze.'
    )
    parser.add_argument(
        '-o', '--output',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )
    parser.add_argument(
        '--vt-key',
        help='VirusTotal API key (can also be set via VIRUSTOTAL_API_KEY env var)'
    )
    parser.add_argument(
        '--abuseipdb-key',
        help='AbuseIPDB API key (can also be set via ABUSEIPDB_API_KEY env var)'
    )
    parser.add_argument(
        '--urlscan-key',
        help='URLScan API key (can also be set via URLSCAN_API_KEY env var)'
    )
    parser.add_argument(
        '--no-enrich',
        action='store_true',
        help='Skip enrichment and only extract IOCs'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'html', 'both'],
        default='both',
        help='Report format to generate (default: both)'
    )

    args = parser.parse_args()

    # Check if email file exists
    if not os.path.isfile(args.email_file):
        print(f"Error: File '{args.email_file}' not found.", file=sys.stderr)
        sys.exit(1)

    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)

    # Step 1: Extract IOCs
    print(f"Extracting IOCs from {args.email_file}...")
    try:
        extracted_iocs = extract_iocs_from_email(args.email_file)
    except Exception as e:
        print(f"Error during extraction: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Found: {len(extracted_iocs.get('ips', []))} IPs, "
          f"{len(extracted_iocs.get('domains', []))} domains, "
          f"{sum(len(v) for v in extracted_iocs.get('hashes', {}).values())} hashes")

    # Step 2: Enrich IOCs (if not skipped)
    if args.no_enrich:
        enriched_iocs = {}
        verdict = {'risk_score': 0, 'risk_level': 'info', 'recommendation': 'Enrichment skipped.',
                   'malicious_count': 0, 'total_checked': 0}
    else:
        print("Enriching IOCs...")
        try:
            enriched_iocs = enrich_iocs(
                extracted_iocs,
                vt_api_key=args.vt_key,
                abuseipdb_api_key=args.abuseipdb_key,
                urlscan_api_key=args.urlscan_key
            )
        except Exception as e:
            print(f"Error during enrichment: {e}", file=sys.stderr)
            sys.exit(1)

        # Generate verdict
        verdict = generate_verdict(enriched_iocs)
        print(f"Verdict: {verdict['risk_level'].upper()} (Score: {verdict['risk_score']})")

    # Step 3: Generate report
    report_data = {
        'extracted_iocs': extracted_iocs,
        'enriched_iocs': enriched_iocs,
        'verdict': verdict
    }

    # Save reports based on format
    if args.format in ['json', 'both']:
        json_path, _ = save_report(report_data, args.output, prefix='ioc_report')
        print(f"JSON report saved to: {json_path}")

    if args.format in ['html', 'both']:
        _, html_path = save_report(report_data, args.output, prefix='ioc_report')
        print(f"HTML report saved to: {html_path}")

    # Also print verdict to console
    print("\n=== VERDICT ===")
    print(f"Risk Level: {verdict['risk_level'].upper()}")
    print(f"Risk Score: {verdict['risk_score']}/100")
    print(f"Recommendation: {verdict['recommendation']}")


if __name__ == '__main__':
    main()