# Investigation Notebook — 01: Web Application Attack Triage
**Analyst:** Mohamed Dhia Bargougui
**Dataset:** Splunk BOTS v3 — Frothly Corporation
**Date:** 2026-06-11
**Status:** ✅ Phase 1 Complete — Primary Suspect Ruled Out, Hunt Continues

---

## What is this file?

This is my live analyst notebook for the web attack investigation. It is written in real time as I work through the data — not cleaned up afterward. It includes every query I ran, what I found, what I ruled out, and why. It also explains concepts along the way for anyone learning SOC analysis.

---

## Background: What are we investigating?

The BOTS v3 dataset simulates a real corporate environment — Frothly Brewery — that came under attack. Our job as the analyst is to find out:

- Was there a web application attack?
- Who did it?
- How did they get in?
- What did they do?

We start with no assumptions. We let the data tell the story.

---

## 📚 Concept: How to Think Like an Analyst

Before touching Splunk, a real analyst asks three questions:

1. **What data do I have?** — You can't find what you can't see. Know your log sources.
2. **What am I looking for?** — Form a hypothesis before you search. Aimless searching wastes time.
3. **How do I prove or disprove it?** — Every finding needs evidence. Every ruled-out lead needs proof too.

This investigation follows that exact process.

---

## Phase 1 — Mapping the Data Terrain

### 📚 Concept: What is a Sourcetype?

In Splunk, a **sourcetype** tells you what kind of log an event came from. Think of it like a file format label. `stream:http` means web traffic. `wineventlog:security` means Windows login events. `suricata` means IDS alerts from a network sensor.

Knowing your sourcetypes is like knowing which filing cabinet to open before you start searching.

### Query 1 — Inventory all available data sources

```spl
index=botsv3 | stats count by sourcetype | sort -count
```

**What each part does:**
- `index=botsv3` — Search only the BOTS v3 dataset
- `| stats count by sourcetype` — Group all events by their data source and count them
- `| sort -count` — Sort highest to lowest (the `-` means descending)

**Finding:** 1,944,092 events across 107 sourcetypes confirmed. Key sourcetypes present:
- `stream:http` — web traffic ✅
- `suricata` — IDS alerts ✅
- `wineventlog:security` — Windows authentication ✅
- `aws:cloudwatchlogs` — AWS infrastructure ✅
- `stream:dns` — DNS queries ✅

**Why this matters:** Before hunting, confirm your visibility. If `stream:http` wasn't here, we couldn't investigate web attacks at all.

---

## Phase 2 — High-Volume Source IP Analysis

### 📚 Concept: Private vs Public IP Addresses

Not all IP addresses are equal. There are two types:

**Private IPs** — used inside corporate networks, never directly reachable from the internet:
- `10.x.x.x`
- `172.16.x.x` to `172.31.x.x`
- `192.168.x.x`

**Public IPs** — belong to someone on the internet. Could be a legitimate user, a bot, or an attacker.

**Rule of thumb:** In a threat hunt, internal IPs are expected. External IPs need to be explained.

### Query 2 — Find the top HTTP talkers

```spl
index=botsv3 sourcetype=stream:http | stats count by src_ip | sort -count | head 20
```

**What each part does:**
- `sourcetype=stream:http` — Only look at web traffic
- `stats count by src_ip` — Count requests per source IP
- `sort -count` — Highest volume first
- `head 20` — Show only top 20 results

**Finding:**

| IP | Count | Type | Assessment |
|---|---|---|---|
| `192.168.3.130` | 2207 | Private — internal | Expected |
| `172.16.1.239` | 1193 | Private — internal | Expected |
| `172.16.0.149` | 1192 | Private — internal | Expected |
| `91.207.175.249` | 839 | **Public — external** | 🔴 Investigate |
| `45.62.48.155` | 182 | Public — external | 🟡 Note |
| `35.182.246.222` | 197 | Public — AWS range | 🟡 Note |

**Primary suspect identified: `91.207.175.249`** — highest volume external IP making 839 HTTP requests.

---

## Phase 3 — Deep Dive on Suspect IP

### Query 3 — Build a transaction timeline

```spl
index=botsv3 sourcetype=stream:http src_ip="91.207.175.249"
| table _time, src_ip, dest_ip, http_method, uri_path, status, http_user_agent
| sort _time
```

**What each part does:**
- `src_ip="91.207.175.249"` — Filter to only this IP's traffic
- `table _time, src_ip, ...` — Show only these fields as a clean table
- `_time` — Timestamp
- `http_method` — GET (requesting a page) or POST (submitting data)
- `uri_path` — The URL being accessed — where attacks show up
- `status` — HTTP response code (200=OK, 404=Not Found, 500=Server Error)
- `http_user_agent` — What tool or browser the client is using
- `sort _time` — Chronological order

**Finding:** Early requests were GET requests for standard layout assets — images, CSS files, jQuery scripts — all returning 200 OK. Looked like normal page rendering, not active exploitation.

### 📚 Concept: HTTP Status Codes

| Code | Meaning | Analyst Relevance |
|---|---|---|
| `200` | OK — request succeeded | Normal |
| `304` | Not Modified — browser used cached version | Normal browser behavior |
| `404` | Not Found — resource doesn't exist | Could indicate scanning |
| `403` | Forbidden — access denied | Could indicate unauthorized access attempt |
| `500` | Server Error — application crashed | Could indicate successful exploitation |

A flood of `404` errors from one IP = scanning. A `500` after a suspicious request = possible exploit success. Always check status codes alongside the URI path.

---

### Query 4 — User-Agent audit

```spl
index=botsv3 sourcetype=stream:http src_ip="91.207.175.249"
| stats count by http_user_agent
```

**What each part does:**
- `stats count by http_user_agent` — Aggregate and count unique browser/tool signatures

**Finding:** Only two User-Agents observed — standard Google Chrome and Microsoft Edge on Windows 10. No attack tools detected.

### 📚 Concept: User-Agent Strings and What They Reveal

The `http_user_agent` field is how a browser or tool identifies itself to a web server. Attackers often use automated tools that have distinctive signatures:

| User-Agent signature | What it means |
|---|---|
| `sqlmap` | Automated SQL injection tool |
| `Nikto` | Web vulnerability scanner |
| `Nmap Scripting Engine` | Port scanner with web probes |
| `python-requests` | Python script — could be custom attack tool |
| `Mozilla/5.0 (Windows NT 10.0...)` | Standard browser — could be manual or spoofed |

**Caveat:** A skilled attacker will spoof their User-Agent to look like a normal browser. Absence of a malicious User-Agent does NOT rule out an attack — it just means they were careful.

---

### Query 5 — URL path analysis

```spl
index=botsv3 sourcetype=stream:http src_ip="91.207.175.249"
| stats count by uri_path | sort -count | head 20
```

**What each part does:**
- `stats count by uri_path` — Count how many times each URL path was hit
- `sort -count | head 20` — Show the most-visited paths first

**Finding:** Heavy interaction with standard site assets and a web forum application — paths like `/forumdisplay.php`. No unusual or admin paths accessed.

---

### Query 6 — POST method hunt

```spl
index=botsv3 sourcetype=stream:http src_ip="91.207.175.249" http_method=POST
| table _time, uri_path, status | sort _time
```

**What each part does:**
- `http_method=POST` — Filter to only POST requests (data submission)

**Finding:** Zero results. No POST requests made. This rules out standard form-based attacks like login brute force, SQL injection via forms, or file uploads.

### 📚 Concept: GET vs POST — Why It Matters

| Method | What it does | Attack relevance |
|---|---|---|
| `GET` | Requests a page or resource | Can carry payloads in the URL query string |
| `POST` | Submits data to the server | Most common method for SQLi, login attacks, file upload |

No POST requests from a suspected attacker is a significant finding — it means they didn't try to inject anything via standard form submission.

---

### Query 7 — GET parameter inspection

```spl
index=botsv3 sourcetype=stream:http src_ip="91.207.175.249" uri_query=*
| table _time, uri_path, uri_query, status | sort _time
```

**What each part does:**
- `uri_query=*` — Only show events where URL query parameters exist (the `?param=value` part of a URL)

**Finding:** Parameters observed: `ver=1800`, `fid=5` (Forum ID), `tid=14` (Thread ID). Status codes alternated between `200 OK` and `304 Not Modified`. The `304` responses confirm a real browser with caching — not a script.

---

## Phase 4 — IDS Cross-Reference

### Query 8 — Suricata IDS alert check

```spl
index=botsv3 src_ip="91.207.175.249" sourcetype=suricata
| stats count by alert.signature
```

**What each part does:**
- `sourcetype=suricata` — Pivot to IDS alerts instead of raw traffic
- `stats count by alert.signature` — Show which attack signatures fired

**Finding:** Zero results. No IDS signatures triggered for this IP. No scanning, fuzzing, or exploit patterns detected at the network layer.

### 📚 Concept: Why Cross-Reference with IDS?

Raw traffic logs (stream:http) show you what was requested. IDS logs (Suricata) tell you if the network sensor recognized any of those requests as known attack patterns. Using both together gives you two independent data sources confirming or contradicting each other. This is called **data source correlation** — a core SOC skill.

---

### Query 9 — Outbound C2 beacon check

```spl
index=botsv3 dest_ip="91.207.175.249"
| stats count by src_ip, sourcetype | sort -count
```

**What each part does:**
- `dest_ip="91.207.175.249"` — Flip the IP to the destination — are any internal hosts calling out to it?
- `stats count by src_ip, sourcetype` — Which internal machines are talking to it and from which log source

**Finding:** Zero results. No internal host ever initiated communication to this IP.

### 📚 Concept: Inbound vs Outbound — The C2 Pivot

This is one of the most important pivots in threat hunting. There are two threat scenarios:

1. **External attacker hitting your server inbound** — you see them in `src_ip`
2. **Internal machine infected and beaconing out** — you see your machine in `src_ip`, attacker IP in `dest_ip`

When OSINT flags an IP as suspicious, always check both directions. An IP can be a known C2 node that infected machines call home to — in that case it appears as a `dest_ip`, not a `src_ip`. Flipping the perspective is standard analyst technique.

---

## Conclusion: IP Ruled Out

**Verdict: `91.207.175.249` — Benign / False Positive**

| Evidence | Finding |
|---|---|
| HTTP methods used | GET only — no POST injection attempts |
| User-Agent strings | Standard Chrome and Edge — no attack tools |
| URI paths accessed | Standard site assets and forum pages |
| URL parameters | Forum navigation IDs — no payloads |
| Status codes | 200 and 304 — normal browser caching behavior |
| Suricata IDS alerts | Zero — no attack signatures triggered |
| Outbound C2 check | Zero — no internal hosts beaconing to this IP |

This IP was a public web user or crawler browsing Frothly's website normally. The investigation was thorough — every angle was checked before ruling it out.

**This is not a failure. This is exactly what analysts do.** Ruling out a false positive cleanly and with documented evidence is a professional outcome. The hunt continues for the real attacker.

---

## Next Step

Pivot to the next external IP suspects and investigate web attack activity from a different angle — look for known attack tool signatures in the User-Agent field across ALL external IPs, not just one.
