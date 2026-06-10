# IR-002 — Ransomware Investigation
**Analyst:** Mohamed Dhia Bargougui
**Dataset:** Splunk BOTS v3 — Frothly Corporation
**Date Started:** <!-- fill in -->
**Last Updated:** <!-- fill in -->
**Severity:** 🔴 Critical
**Status:** 🔄 In Progress

---

## Executive Summary

> *Write this last. 3–5 sentences. What ransomware family, how it entered, what systems were encrypted, what the ransom demand was, what was done.*

---

## Incident Metadata

| Field | Value |
|---|---|
| Incident ID | IR-002 |
| Ransomware Family | <!-- fill in during investigation --> |
| Detection Source | <!-- e.g. endpoint alert / user report --> |
| Patient Zero (Host) | <!-- first infected system --> |
| Affected Host(s) | <!-- all impacted systems --> |
| Infection Vector | <!-- email / RDP / USB / web --> |
| Data Sources Used | wineventlog · sysmon · stream · suricata · fortigate |

---

## Timeline of Events

| Timestamp (UTC) | Event | Source | Notes |
|---|---|---|---|
| <!-- time --> | <!-- Initial infection vector observed --> | <!-- sourcetype --> | |
| <!-- time --> | <!-- Malware execution --> | | |
| <!-- time --> | <!-- File encryption begins --> | | |
| <!-- time --> | <!-- Lateral movement attempt --> | | |
| <!-- time --> | <!-- Ransom note dropped --> | | |
| | | | |

---

## Attack Narrative

### Phase 1 — Delivery
<!-- How did the ransomware arrive? Phishing email? Drive-by download? RDP brute force? -->

### Phase 2 — Execution
<!-- What process executed the ransomware? What parent process spawned it? -->

### Phase 3 — Privilege Escalation / Defense Evasion
<!-- Did the attacker attempt to escalate? Disable AV? Clear logs? -->

### Phase 4 — Lateral Movement
<!-- Did ransomware spread to other hosts? How — SMB? WMI? PsExec? -->

### Phase 5 — Impact — Encryption
<!-- Which files/directories were encrypted? What extension was appended? -->

### Phase 6 — Ransom Demand
<!-- What was the ransom note filename? Contents? Payment address? -->

---

## Key SPL Queries

**Identify initial execution:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify file encryption activity:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify lateral movement:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify C2 or exfiltration:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

**Identify ransom note drop:**
```spl
<!-- paste query here -->
```
*Finding: <!-- what did this return -->*

---

## Indicators of Compromise (IOCs)

| Type | Value | Confidence | Context |
|---|---|---|---|
| File Hash (MD5) | <!-- --> | High | <!-- ransomware binary --> |
| File Hash (SHA256) | <!-- --> | High | <!-- --> |
| Filename | <!-- --> | High | <!-- e.g. ransom note name --> |
| File Extension | <!-- --> | High | <!-- e.g. .locky .cerber --> |
| IP Address | <!-- --> | Med | <!-- C2 server --> |
| Registry Key | <!-- --> | Med | <!-- persistence mechanism --> |
| Mutex | <!-- --> | Med | <!-- malware mutex --> |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Observed Evidence |
|---|---|---|---|
| Initial Access | Phishing / Valid Accounts / RDP | T1566 / T1078 / T1133 | <!-- --> |
| Execution | User Execution / PowerShell | T1204 / T1059.001 | <!-- --> |
| Defense Evasion | Impair Defenses | T1562 | <!-- --> |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | <!-- --> |
| Impact | Data Encrypted for Impact | T1486 | <!-- --> |
| Impact | Inhibit System Recovery | T1490 | <!-- --> |

---

## Scope of Impact

| System | Encrypted | User Logged In | Recovery Status |
|---|---|---|---|
| <!-- hostname --> | Yes / No | <!-- username --> | <!-- recovered / not --> |
| | | | |

---

## Recommendations

1. <!-- e.g. Isolate affected systems immediately from the network -->
2. <!-- e.g. Restore from last known clean backup dated XX/XX/XXXX -->
3. <!-- e.g. Block ransomware C2 IPs at firewall -->
4. <!-- e.g. Disable SMBv1 across all endpoints -->
5. <!-- e.g. Enforce MFA on all RDP access -->
6. <!-- e.g. Deploy file integrity monitoring on critical directories -->

---

## Lessons Learned

- <!-- e.g. Shadow copies were deleted — backup strategy must be reviewed -->
- <!-- e.g. No EDR alert on mass file rename activity -->
- <!-- e.g. Lateral movement via SMB was not detected until post-infection -->

---

## References

- [MITRE ATT&CK — Data Encrypted for Impact T1486](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — Inhibit System Recovery T1490](https://attack.mitre.org/techniques/T1490/)
- [Splunk Ransomware Investigation Guide](https://lantern.splunk.com/Security_Use_Cases/Advanced_Threat_Detection/Investigating_a_ransomware_attack)
- [Splunk BOTS v3 Dataset](https://github.com/splunk/botsv3)
