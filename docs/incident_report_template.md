# Phishing Incident Report

**Incident ID:** [Unique Identifier]  
**Date/Time Detected:** [YYYY-MM-DD HH:MM:SS]  
**Reported By:** [Name/Team]  
**Classification:** [Phishing - Spearphishing/Whaling/Clone/etc.]  
**Severity:** [Low/Medium/High/Critical]  
**Status:** [Open/Under Investigation/Contained/Eradicated/Recovered/Closed]

## Executive Summary
[Brief overview of the incident: what happened, impact, and current status.]

## Timeline of Events
| Date/Time (UTC) | Activity | Performed By | Notes |
|-----------------|----------|--------------|-------|
| [YYYY-MM-DD HH:MM:SS] | Initial detection (user report/alert) | [Analyst] | [e.g., User reported suspicious email] |
| [YYYY-MM-DD HH:MM:SS] | IOC extraction completed | [Tool/Analyst] | [Number of IPs, domains, hashes found] |
| [YYYY-MM-DD HH:MM:SS] | Enrichment initiated | [Tool] | [APIs used] |
| [YYYY-MM-DD HH:MM:SS] | Verdict generated | [Tool] | [Risk level: X] |
| [YYYY-MM-DD HH:MM:SS] | Containment actions started | [Team] | [e.g., Blocked IP at firewall] |
| ... | ... | ... | ... |

## Detailed Findings

### Email Analysis
- **Sender:** [Email address]
- **Recipient(s):** [Email addresses]
- **Subject:** [Email subject]
- **Headers:** 
  - SPF: [Result]
  - DKIM: [Result]
  - DMARC: [Result]
- **Attachments:** 
  - [Filename] (SHA256: [hash])
  - [Filename] (SHA256: [hash])
- **URLs Found:** 
  - [URL1]
  - [URL2]

### Extracted IOCs
| Type | Indicator | Count |
|------|-----------|-------|
| IP Addresses | [list] | [X] |
| Domains | [list] | [X] |
| File Hashes (MD5) | [list] | [X] |
| File Hashes (SHA1) | [list] | [X] |
| File Hashes (SHA256) | [list] | [X] |

### Enrichment Results
#### VirusTotal
- [Summary of notable detections]
#### AbuseIPDB
- [Summary of high-confidence abusive IPs]
#### URLScan
- [Summary of suspicious URL scans]

### Verdict
- **Risk Score:** [X]/100
- **Risk Level:** [Low/Medium/High]
- **Recommendation:** [Text from tool]

## Impact Assessment
- **Users Affected:** [Number]
- **Systems Compromised:** [Number/List]
- **Data Exfiltrated:** [Yes/No/Unknown - Details]
- **Credentials Exposed:** [Yes/Number/Unknown]
- **Financial Impact:** [Estimated or Known]
- **Operational Impact:** [Downtime, productivity loss, etc.]

## Actions Taken

### Containment
- [List of containment actions with timestamps]

### Eradication
- [List of eradication actions with timestamps]

### Recovery
- [List of recovery actions with timestamps]

## Evidence Collected
- Original email file: [path/to/email.eml]
- Enrichment reports: [paths to JSON/HTML reports]
- Firewall/proxy logs: [references]
- Endpoint scan reports: [references]
- Other: [specify]

## Lessons Learned
- What worked well:
  - [Point 1]
  - [Point 2]
- What could be improved:
  - [Point 1]
  - [Point 2]
- Gaps identified:
  - [Gap 1]
  - [Gap 2]

## Recommendations
### Short-term
- [Action 1]
- [Action 2]

### Long-term
- [Action 1]
- [Action 2]

## Approval
**Analyst:** [Name]  
**Date:** [YYYY-MM-DD]  
**Reviewer:** [Name]  
**Date:** [YYYY-MM-DD]

---
*Report generated using the Phishing Investigation & Automated IOC Enrichment Tool*