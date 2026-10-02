# Phishing Investigation & Automated IOC Enrichment Tool

A Python-based tool for extracting Indicators of Compromise (IOCs) from phishing emails and enriching them using VirusTotal, AbuseIPDB, and URLScan APIs. The tool generates a verdict report to assist in incident response and reduce manual triage effort.

## Features

- Extract IOCs (IP addresses, domains, file hashes) from email files (EML, MSG)
- Enrich IOCs with threat intelligence from:
  - VirusTotal (file, domain, IP reputation)
  - AbuseIPDB (IP reputation)
  - URLScan (URL and domain scanning)
- Automated verdict generation based on enrichment results
- JSON and HTML report generation
- Command-line interface for easy integration into IR workflows

## Project Structure

```
ioc_enrichment_tool/
├── extract.py          # IOC extraction logic
├── enrich.py           # API enrichment logic
├── report.py           # Report generation and verdict
├── cli.py              # Command-line interface
├── __init__.py
docs/
├── playbook.md         # Phishing response playbook
└── incident_report_template.md  # Incident report template
tests/                  # Unit tests
```

## Installation

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd ioc_enrichment_tool
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure API keys:
   - Copy `.env.example` to `.env` and fill in your API keys, or
   - Set the environment variables directly:
     ```bash
     export VIRUSTOTAL_API_KEY=your_key_here
     export ABUSEIPDB_API_KEY=your_key_here
     export URLSCAN_API_KEY=your_key_here
     ```

## Usage

Analyze an email file:

```bash
python -m ioc_enrichment_tool.cli path/to/email.eml
```

### Options

- `-o, --output`: Specify output directory for reports (default: `./reports`)
- `--vt-key`, `--abuseipdb-key`, `--urlscan-key`: Provide API keys as command-line options (overrides environment variables)
- `--no-enrich`: Skip enrichment and only extract IOCs
- `--format`: Choose report format (`json`, `html`, or `both`; default: `both`)

### Example

```bash
python -m ioc_enrichment_tool.cli samples/phishing_email.eml -o ./reports --format both
```

## Output

The tool generates JSON and/or HTML reports in the specified output directory. Reports include:

- Extracted IOCs
- Enrichment results from each API
- Verdict with risk score, level, and recommendations

## Phishing Response Playbook

See `docs/playbook.md` for a detailed phishing incident response playbook covering:
1. Identification
2. Containment
3. Eradication
4. Reporting

## Incident Report Template

See `docs/incident_report_template.md` for a template to document phishing incidents.

## Testing

Run unit tests with:

```bash
pytest
```

## Requirements

- Python 3.7+
- Internet access for API queries
- API keys for VirusTotal, AbuseIPDB, and URLScan (free tiers available)

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Disclaimer

This tool is for defensive security and incident response purposes only. Users must comply with the terms of service of the respective APIs and ensure they have authorization to analyze the email content.

## Acknowledgments

- Inspired by real-world phishing investigation workflows
- Built with the `requests` library