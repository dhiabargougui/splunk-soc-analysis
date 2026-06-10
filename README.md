# Splunk SOC Analysis — BOTS v3 Threat Hunting Lab

**Analyst:** Dhia Bargougui
**LinkedIn:** [linkedin.com/in/dhiabargougui](linkedin.com/in/mohamed-dhia-bargougui)
**Dataset:** Boss of the SOC (BOTS) v3 — Splunk's industry-standard blue team CTF dataset
**Status:** 🔄 Ongoing — continuously updated as new investigations are completed

---

## Overview

This repository documents my hands-on SOC analyst work using the **BOTS v3** dataset loaded into a local Splunk Enterprise instance. Each investigation simulates a real-world incident response scenario — from initial triage through root cause analysis, IOC extraction, and formal reporting.

The goal is to practice and demonstrate the full analyst workflow:
- Receiving an alert or anomaly
- Forming a hypothesis
- Writing and refining SPL queries
- Pivoting across data sources
- Documenting findings in a structured IR report
- Mapping attacker behavior to MITRE ATT&CK

This is not a CTF writeup. It is a simulation of what a junior SOC analyst does on the job — minus the client data.

---

## Environment

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise (local instance) |
| Dataset | BOTS v3 (Boss of the SOC v3) |
| Data Sources | Sysmon, WinEventLog, Suricata IDS, Stream, Fortigate, Apache, Osquery |
| ATT&CK Version | MITRE ATT&CK v14 |
| OS | Windows 10 |

---

## Investigations

| # | Scenario | Threat Type | Status | Report |
|---|---|---|---|---|
| 01 | Web Application Attack | SQLi, Webshell, C2 | 🔄 In Progress | [IR-001](reports/IR-001_Web_Attack.md) |
| 02 | Ransomware Outbreak | Lateral Movement, Encryption | 🔄 In Progress | [IR-002](reports/IR-002_Ransomware.md) |
| 03 | Insider Threat / Exfiltration | Data Staging, DNS Exfil | 🔄 In Progress | [IR-003](reports/IR-003_Insider_Threat.md) |

---

## Repository Structure

```
splunk-soc-analysis/
├── investigations/        # Analyst notebooks — raw findings, queries, pivots
├── reports/               # Formal IR reports — polished, job-ready output
├── queries/               # SPL query library organized by scenario
├── dashboards/            # Screenshots of Splunk dashboards built during analysis
└── assets/                # Attack timelines, diagrams, supporting visuals
```

**investigations/** — informal working notes. What I searched, what I found, dead ends, pivots. Written in real time during analysis.

**reports/** — formal incident response reports following a SANS-style structure. Executive summary, attack timeline, IOCs, MITRE mapping, and recommendations. These are the deliverables.

**queries/** — every SPL query used, annotated with what it does and what it found. Reusable and organized by scenario.

---

## Skills Demonstrated

- **Threat hunting** — hypothesis-driven investigation across multiple log sources
- **SPL** — Splunk Search Processing Language for log correlation, statistical analysis, and IOC extraction
- **Incident response** — structured IR methodology from detection through containment and remediation
- **Log analysis** — Windows Event Logs, Sysmon, IDS alerts, web server logs, network flow data
- **MITRE ATT&CK** — mapping observed TTPs to the ATT&CK framework
- **Technical writing** — formal IR reports written for both technical and executive audiences

---

## Reports

Each report follows this structure:
- Executive Summary
- Timeline of Events
- Attack Narrative
- IOCs Identified
- SPL Queries Used
- MITRE ATT&CK Mapping
- Recommendations

→ [View all reports](reports/)

---

## Notes

All data used in this project comes from the publicly available BOTS v3 dataset provided by Splunk for educational and training purposes. No real organizational data is involved. This project is part of my continuous learning and professional development as a SOC analyst.
