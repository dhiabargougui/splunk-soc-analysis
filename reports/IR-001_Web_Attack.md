# IR-001 — Web Application Attack & Initial Compromise
**Analyst:** Mohamed Dhia Bargougui
**Dataset:** Splunk BOTS v3 — Frothly Corporation
**Date Started:** <!-- fill in -->
**Last Updated:** <!-- fill in -->
**Severity:** 🔴 Critical
**Status:** 🔄 In Progress

---

## Executive Summary

> *Write this last. 3–5 sentences. What happened, how it was detected, what was impacted, what was done. Written for a non-technical reader.*

---

## Incident Metadata

| Field | Value |
|---|---|
| Incident ID | IR-001 |
| Detection Source | <!-- e.g. Suricata IDS / web logs --> |
| Affected Host(s) | <!-- fill in during investigation --> |
| Affected User(s) | <!-- fill in during investigation --> |
| Attack Vector | Web Application |
| Data Sources Used | stream:http · suricata · apache · wineventlog · sysmon |

---

## Timeline of Events

> *Fill this in chronologically as you investigate. Every significant event gets a row.*

| Timestamp (UTC) | Event | Source | Notes |
|---|---|---|---|
| <!-- time --> | <!-- what happened --> | <!-- sourcetype --> | <!-- context --> |
| | | | |
| | | | |

---

## Attack Narrative

> *Write this as a story after the investigation is complete. Walk the reader through the attack step by step — what the attacker did, in what order, and how you found it. Use past tense. Be specific.*

### Phase 1 — Reconnaissance
<!-- What scanning or recon activity did you observe? Source IPs, tools, patterns -->

### Phase 2 — Initial Access
<!-- How did the attacker get in? SQLi? Brute force? Exploit? -->

### Phase 3 — Execution / Webshell
<!-- Was a webshell uploaded? What commands were run? -->

### Phase 4 — C2 Communication
<!-- Did the attacker establish C2? What IPs/domains? What protocols? -->

### Phase 5 — Impact
<!-- What was the outcome? Data accessed? Persistence established? -->

---

## Key SPL Queries

> *Document every query that produced a meaningful finding. Annotate what each one does.*

**Identify scanning activity:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->>*

**Identify web attack attempts:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify webshell upload:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify C2 communication:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

---

## Indicators of Compromise (IOCs)

| Type | Value | Confidence | Context |
|---|---|---|---|
| IP Address | <!-- x.x.x.x --> | High / Med / Low | <!-- e.g. attacker source IP --> |
| Domain | <!-- domain --> | | |
| File Hash (MD5/SHA256) | <!-- hash --> | | |
| URL | <!-- path --> | | |
| User-Agent | <!-- string --> | | |
| Filename | <!-- name --> | | |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Observed Evidence |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | <!-- e.g. Suricata alerts for port scan --> |
| Initial Access | Exploit Public-Facing Application | T1190 | <!-- --> |
| Execution | Command and Scripting Interpreter | T1059 | <!-- --> |
| Persistence | Web Shell | T1505.003 | <!-- --> |
| Command & Control | Application Layer Protocol | T1071 | <!-- --> |

---

## Recommendations

> *Specific, actionable, numbered. Written for a security team to act on.*

1. <!-- e.g. Block source IP x.x.x.x at perimeter firewall -->
2. <!-- e.g. Remove webshell located at /path/to/file -->
3. <!-- e.g. Patch CVE-XXXX-XXXX on affected web server -->
4. <!-- e.g. Rotate credentials for compromised accounts -->
5. <!-- e.g. Implement WAF rule to block SQLi patterns -->

---

## Lessons Learned

> *What detection gaps did this investigation reveal? What would have caught this earlier?*

- <!-- e.g. No alerting on web shell file creation events -->
- <!-- e.g. Suricata signatures were not tuned for this attack pattern -->

---

## References

- [MITRE ATT&CK — Web Shell T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — Exploit Public-Facing Application T1190](https://attack.mitre.org/techniques/T1190/)
- [Splunk BOTS v3 Dataset](https://github.com/splunk/botsv3)
