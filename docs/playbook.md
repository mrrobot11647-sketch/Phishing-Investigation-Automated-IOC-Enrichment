# Phishing Response Playbook

This playbook outlines the steps for responding to phishing incidents, aligned with industry best practices (NIST, SANS, etc.).

## 1. Identification

### Objectives
- Detect and confirm phishing attempts
- Gather initial evidence
- Determine scope and impact

### Activities
- Monitor email security gateways, user reports, and threat intelligence feeds
- Analyze email headers (SPF, DKIM, DMARC) for spoofing indicators
- Extract IOCs (IPs, domains, hashes) from suspicious emails
- Preserve original email as evidence (EML/MSG format)
- Check URLs and attachments in sandbox environment
- Identify targeted users and systems

### Tools
- Email security gateway logs
- Phishing analysis tools (this IOC enrichment tool)
- Sandbox (e.g., Cuckoo, Hybrid Analysis)
- Threat intelligence platforms

### Output
- Initial incident ticket with collected evidence
- List of IOCs for enrichment
- Timeline of events

## 2. Containment

### Objectives
- Prevent further damage
- Stop the spread of the phishing campaign
- Isolate affected systems

### Activities
- Block malicious IPs and domains at firewall/proxy
- Quarantine or delete malicious emails from user mailboxes
- Disable compromised user accounts if credentials were entered
- Block malicious URLs at web proxy
- Notify users to avoid interacting with the phishing email
- Apply email filtering rules to block similar messages

### Tools
- Firewall/IPS
- Email gateway administration
- Endpoint detection and response (EDR)
- Identity and access management (IAM)

### Output
- Updated incident ticket with containment actions
- Confirmation of blocked IOCs
- List of affected users/systems

## 3. Eradication

### Objectives
- Remove threats from the environment
- Remediate vulnerabilities exploited
- Ensure complete removal of artifacts

### Activities
- Scan and clean malware from endpoints using AV/EDR
- Remove malicious registry keys, files, and services
- Reset passwords for potentially compromised accounts
- Apply security patches if vulnerability was exploited
- Hunt for persistence mechanisms (e.g., scheduled tasks, startup items)
- Verify removal of all IOCs from the environment

### Tools
- Antivirus/EDR
- Forensic analysis tools
- Patch management systems
- Scripts for bulk remediation

### Output
- Updated incident ticket with eradication actions
- Confirmation of threat removal
- Vulnerability remediation records

## 4. Recovery

### Objectives
- Restore normal operations
- Confirm system integrity
- Prevent recurrence

### Activities
- Restore systems from clean backups if necessary
- Monitor for re-infection or residual threats
- Validate authentication mechanisms
- Conduct user awareness training for targeted individuals
- Update email filtering rules based on new IOCs
- Implement additional security controls if gaps identified

### Tools
- Backup and recovery systems
- Monitoring tools (SIEM, EDR)
- Security awareness platforms

### Output
- Systems restored to operational state
- Monitoring logs showing no persistent threats
- Updated security policies and filters

## 5. Lessons Learned & Reporting

### Objectives
- Document the incident thoroughly
- Identify areas for improvement
- Share knowledge to prevent future incidents

### Activities
- Complete incident report (see template)
- Conduct post-incident review meeting
- Update incident response plan based on findings
- Share indicators with information sharing communities (e.g., ISACs)
- Archive evidence for legal and compliance requirements
- Measure effectiveness of response (MTTR, etc.)

### Tools
- Incident reporting template
- Collaboration tools (conference, document sharing)
- Threat intelligence sharing platforms

### Output
- Final incident report
- Updated playbooks and procedures
- Action items for improvement