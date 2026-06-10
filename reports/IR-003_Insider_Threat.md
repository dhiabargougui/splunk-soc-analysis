# IR-003 — APT / Insider Threat & Data Exfiltration
**Analyst:** Mohamed Dhia Bargougui
**Dataset:** Splunk BOTS v3 — Frothly Corporation
**Date Started:** <!-- fill in -->
**Last Updated:** <!-- fill in -->
**Severity:** 🔴 Critical
**Status:** 🔄 In Progress

---

## Executive Summary

> *Write this last. 3–5 sentences. Who the threat actor was (Taedonggang APT), what credentials were compromised, what data was exfiltrated, what cloud services were abused.*

---

## Incident Metadata

| Field | Value |
|---|---|
| Incident ID | IR-003 |
| Threat Actor | Taedonggang (suspected) |
| Detection Source | <!-- e.g. CloudTrail anomaly / DLP alert --> |
| Affected Account(s) | <!-- fill in during investigation --> |
| Affected Systems | <!-- AWS / Azure / on-prem --> |
| Attack Type | APT / Credential Compromise / Data Exfiltration |
| Data Sources Used | o365 · aws:cloudtrail · stream · wineventlog · osquery |

---

## Timeline of Events

| Timestamp (UTC) | Event | Source | Notes |
|---|---|---|---|
| <!-- time --> | <!-- Credential exposure observed --> | <!-- sourcetype --> | |
| <!-- time --> | <!-- Unauthorized login --> | | |
| <!-- time --> | <!-- Cloud resource access --> | | |
| <!-- time --> | <!-- Data staging --> | | |
| <!-- time --> | <!-- Exfiltration --> | | |
| | | | |

---

## Attack Narrative

### Phase 1 — Initial Access / Credential Compromise
<!-- How were credentials obtained? Leaked on GitHub? Phishing? Credential stuffing?
     BOTS v3 hint: AWS credentials were leaked to a public GitHub repository -->

### Phase 2 — Cloud Infrastructure Abuse
<!-- What AWS/Azure resources were accessed or modified?
     S3 buckets? EC2 instances? IAM roles? -->

### Phase 3 — Reconnaissance (Internal)
<!-- What did the attacker enumerate after gaining access? -->

### Phase 4 — Data Staging
<!-- Where was data consolidated before exfiltration? -->

### Phase 5 — Exfiltration
<!-- How was data exfiltrated? DNS tunneling? HTTPS? S3 sync? -->

### Phase 6 — Persistence
<!-- Did the attacker establish persistence? New IAM user? Backdoor? -->

---

## Key SPL Queries

**Identify credential exposure / unusual login:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify anomalous CloudTrail activity:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify data staging:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify exfiltration:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify persistence mechanisms:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

---

## Indicators of Compromise (IOCs)

| Type | Value | Confidence | Context |
|---|---|---|---|
| IP Address | <!-- --> | High | <!-- attacker source IP --> |
| AWS Access Key ID | <!-- AKIA... --> | High | <!-- compromised key --> |
| S3 Bucket | <!-- --> | High | <!-- accessed/exfil target --> |
| Username | <!-- --> | High | <!-- compromised account --> |
| Domain | <!-- --> | Med | <!-- C2 or exfil domain --> |
| User-Agent | <!-- --> | Med | <!-- attacker tooling signature --> |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Observed Evidence |
|---|---|---|---|
| Initial Access | Valid Accounts — Cloud Accounts | T1078.004 | <!-- --> |
| Credential Access | Unsecured Credentials | T1552 | <!-- --> |
| Discovery | Cloud Infrastructure Discovery | T1580 | <!-- --> |
| Collection | Data from Cloud Storage | T1530 | <!-- --> |
| Exfiltration | Transfer Data to Cloud Account | T1537 | <!-- --> |
| Persistence | Create Cloud Instance / IAM | T1136.003 | <!-- --> |

---

## Data Exposure Assessment

| Data Type | Location | Volume | Sensitivity |
|---|---|---|---|
| <!-- e.g. financial records --> | <!-- S3 bucket name --> | <!-- size/count --> | <!-- High/Med/Low --> |
| | | | |

---

## Recommendations

1. <!-- e.g. Immediately revoke compromised AWS access key AKIA... -->
2. <!-- e.g. Enable AWS CloudTrail across all regions if not already active -->
3. <!-- e.g. Implement git-secrets or truffleHog scanning on all repositories -->
4. <!-- e.g. Apply least-privilege IAM policies — no wildcard permissions -->
5. <!-- e.g. Enable MFA on all cloud console logins -->
6. <!-- e.g. Set S3 bucket policies to block public access by default -->
7. <!-- e.g. Configure GuardDuty for ongoing AWS threat detection -->

---

## Lessons Learned

- <!-- e.g. AWS credentials were committed to a public GitHub repo — no secret scanning in CI/CD -->
- <!-- e.g. No alerting on S3 GetObject from unknown IP ranges -->
- <!-- e.g. CloudTrail logs were not being monitored in real time -->

---

## References

- [MITRE ATT&CK — Valid Accounts T1078](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK — Transfer Data to Cloud Account T1537](https://attack.mitre.org/techniques/T1537/)
- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [Splunk BOTS v3 Dataset](https://github.com/splunk/botsv3)
