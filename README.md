<div align="center">

# 🔍 Splunk SOC Analysis Lab
### Threat Hunting & Incident Response — BOTS v3 Dataset

[![Status](https://img.shields.io/badge/Status-Ongoing-blue?style=flat-square)](/)
[![Dataset](https://img.shields.io/badge/Dataset-BOTS%20v3-orange?style=flat-square)](/)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-green?style=flat-square)](/)
[![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red?style=flat-square)](/)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mohamed%20Dhia%20Bargougui-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/mohamed-dhia-bargougui/)

</div>

---

## Who is this for

Hiring managers and SOC leads who want to see how I work — not just what I know. Every file in this repo reflects a real analyst workflow: forming a hypothesis, hunting through logs, pivoting across data sources, and writing a report that someone else can act on.

No CTF point-chasing. No copy-pasted writeups. This is a simulation of day-one SOC work.

---

## Environment

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise (local instance) |
| Dataset | Boss of the SOC (BOTS) v3 — Splunk's blue team training dataset |
| Log Sources | Sysmon · WinEventLog · Suricata IDS · Stream · Fortigate · Apache · Osquery |
| Framework | MITRE ATT&CK v14 |
| OS | Windows 11 |

---

## Investigations

| # | Scenario | Threat Type | Status | Notebook | Report |
|---|---|---|---|---|---|
| 01 | Web Application Attack | SQLi · Webshell · C2 | 🔄 In Progress | [Notes](investigations/01-web-attack.md) | [IR-001](reports/IR-001_Web_Attack.md) |
| 02 | Ransomware Outbreak | Lateral Movement · Encryption | 🔄 In Progress | [Notes](investigations/02-ransomware.md) | [IR-002](reports/IR-002_Ransomware.md) |
| 03 | Insider Threat | Data Staging · DNS Exfil | 🔄 In Progress | [Notes](investigations/03-insider-threat.md) | [IR-003](reports/IR-003_Insider_Threat.md) |

---

## How this repo is organized

```
splunk-soc-analysis/
│
├── investigations/       # Analyst notebooks — raw findings written in real time
│   ├── 01-web-attack.md
│   ├── 02-ransomware.md
│   └── 03-insider-threat.md
│
├── reports/              # Formal IR reports — structured, polished, job-ready
│   ├── IR-001_Web_Attack.md
│   ├── IR-002_Ransomware.md
│   ├── IR-003_Insider_Threat.md
│   └── executive-summary.md
│
├── queries/              # SPL query library — annotated and reusable
│   ├── web_attack.spl
│   ├── ransomware.spl
│   └── insider_threat.spl
│
├── dashboards/           # Splunk dashboard screenshots
│   └── screenshots/
│
└── assets/               # Attack timelines and supporting visuals
```

**investigations/** — informal working notes. Queries, dead ends, pivots, timestamps. Written during the hunt, not after.

**reports/** — formal incident response reports. Executive summary, attack timeline, IOC table, MITRE mapping, recommendations. These are the deliverables.

**queries/** — every SPL query used in each investigation, annotated with what it searches for and what it returned.

---

## Skills demonstrated

- **SPL** — log correlation, statistical analysis, IOC extraction, subsearches
- **Threat hunting** — hypothesis-driven investigation across multiple log sources
- **Incident response** — full IR cycle: detection → triage → analysis → containment → reporting
- **Log analysis** — Windows Event Logs, Sysmon, network IDS, web server logs, firewall logs
- **MITRE ATT&CK** — mapping observed TTPs to tactics and techniques
- **Technical writing** — IR reports written for both technical analysts and non-technical stakeholders

---

## Report structure

Every formal report in `/reports` follows this format:

```
Executive Summary
Timeline of Events
Attack Narrative
IOCs Identified
SPL Queries Used
MITRE ATT&CK Mapping
Recommendations
```

→ [Browse all reports](reports/)

---

<div align="center">

**Mohamed Dhia Bargougui**
SOC Analyst · Incident Response · Blue Team

[![LinkedIn](https://img.shields.io/badge/Connect-LinkedIn-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/mohamed-dhia-bargougui/)

*All data is from the publicly available BOTS v3 dataset provided by Splunk for training purposes. No real organizational data is involved.*

</div>
