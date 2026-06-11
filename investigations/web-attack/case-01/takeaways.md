# Takeaways — Web Attack | Case 01
**Analyst:** Mohamed Dhia Bargougui
**Case:** Triage of External IP 91.207.175.249
**Date:** 2026-06-11

---

## What this file is

These are the concepts, skills, and fundamentals I learned or reinforced during this investigation. Written so that anyone starting out in SOC analysis can learn from this case too.

---

## 1. Always Map Your Data First

Before hunting, run this:

```spl
index=botsv3 | stats count by sourcetype | sort -count
```

**Why:** You cannot hunt for something you have no logs for. This query shows you every data source available and how many events each has. It takes 30 seconds and saves you hours of searching in the wrong place.

**Real world:** In a real SOC, this is the first thing you do when you get access to a new environment. Know your visibility before you start.

---

## 2. Private vs Public IP Addresses

This is one of the most fundamental concepts in network security.

### Private IP ranges — internal only, never on the internet

| Range | What you'll see |
|---|---|
| `10.0.0.0 – 10.255.255.255` | `10.x.x.x` |
| `172.16.0.0 – 172.31.255.255` | `172.16.x.x` to `172.31.x.x` |
| `192.168.0.0 – 192.168.255.255` | `192.168.x.x` |

These are reserved for internal networks — company LANs, home routers, lab machines. They cannot be routed on the public internet.

### Public IPs — anything outside those ranges

If an IP doesn't fall in the three ranges above, it belongs to someone on the internet. It could be a legitimate user, a bot, a researcher, or an attacker.

### The analyst rule:
> Internal IPs are expected. External IPs need to be explained.

**Applied to this case:** Out of the top 20 HTTP source IPs, most were internal (`192.168.x.x`, `172.16.x.x`). The ones that stood out were the public IPs — especially `91.207.175.249` with 839 requests. That's what triggered the investigation.

---

## 3. What is a Sourcetype?

In Splunk, every log event has a `sourcetype` — a label that tells you what kind of log it is and where it came from.

| Sourcetype | What it contains |
|---|---|
| `stream:http` | Raw HTTP web traffic captured off the network wire |
| `stream:dns` | DNS queries and responses |
| `stream:tcp` / `stream:ip` | Raw network layer traffic |
| `wineventlog:security` | Windows Security Event Log — logins, privilege use |
| `xmlwineventlog:...sysmon` | Sysmon — deep process, file, and network telemetry |
| `suricata` | Network IDS alerts — known attack signature matches |
| `aws:cloudwatchlogs` | AWS infrastructure and service logs |
| `osquery:results` | Endpoint telemetry from the Osquery agent |
| `cisco:asa` | Cisco firewall traffic logs |

**Why it matters:** Every investigation starts by knowing which sourcetype holds the data you need. Web attack? Go to `stream:http`. Suspicious process? Go to `sysmon`. Login anomaly? Go to `wineventlog:security`.

---

## 4. Core SPL Concepts

SPL (Search Processing Language) is Splunk's query language. Here are the building blocks used in this case.

### The pipe `|`
Works exactly like a Unix pipe. Takes the output of the left side and feeds it into the right side.

```spl
index=botsv3 | stats count by sourcetype
```
First get all events → then count them by sourcetype.

### `stats count by [field]`
Groups events by a field and counts how many events fall in each group.

```spl
| stats count by src_ip
```
Tells you how many events came from each source IP.

### `sort -count`
Sorts results. The `-` means descending (highest first). Without `-` it sorts ascending (lowest first).

### `head N`
Limits output to the first N rows. Always use this when you just want the top results.

```spl
| sort -count | head 20
```
Top 20 results by count.

### `table [field1, field2, ...]`
Displays only the fields you specify as a clean table. Essential for readable output.

```spl
| table _time, src_ip, uri_path, status, http_user_agent
```

### `field=value` filtering
Filter events where a specific field matches a value.

```spl
src_ip="91.207.175.249"
http_method=POST
uri_query=*
```
The `*` means "this field exists and has any value."

---

## 5. Key HTTP Fields and What They Tell You

When investigating web attacks, these are the fields that matter most in `stream:http`:

| Field | What it is | What to look for |
|---|---|---|
| `src_ip` | Who made the request | External IPs, high volume |
| `dest_ip` | Who received the request | Your web server |
| `http_method` | GET or POST | POST = data submission = higher risk |
| `uri_path` | The URL path requested | Admin paths, `.php` files, unusual patterns |
| `uri_query` | Parameters in the URL | SQLi payloads, encoded characters |
| `status` | HTTP response code | 500 after attack = possible success |
| `http_user_agent` | Tool or browser identity | sqlmap, Nikto, python-requests = attack tools |

---

## 6. HTTP Status Codes Every Analyst Should Know

| Code | Meaning | Why it matters |
|---|---|---|
| `200` | OK | Normal successful request |
| `304` | Not Modified | Browser used cached version — proves real browser behavior |
| `301/302` | Redirect | Could indicate URL manipulation |
| `400` | Bad Request | Malformed request — could be fuzzing |
| `401` | Unauthorized | Access denied — could be brute force |
| `403` | Forbidden | Blocked — attacker hitting restricted areas |
| `404` | Not Found | Many 404s from one IP = scanning |
| `500` | Server Error | Application crashed — possible successful exploit |

**Key pattern:** A suspicious request followed by a `500` is a red flag. It means something broke on the server — possibly because an exploit worked.

---

## 7. GET vs POST — Why the Difference Matters

| Method | What it does | Attack relevance |
|---|---|---|
| `GET` | Requests a resource | Payloads can be hidden in URL query parameters |
| `POST` | Submits data to the server | Most common for SQLi, login attacks, file uploads |

In this case, `91.207.175.249` made **zero POST requests** — this was a significant finding that helped rule out active exploitation attempts.

---

## 8. User-Agent Strings — Reading Attacker Tooling

The `http_user_agent` field tells you what software made the request. Attackers using automated tools often leave a signature:

| User-Agent | What it means |
|---|---|
| `sqlmap/1.x` | SQL injection automation tool |
| `Nikto/2.x` | Web vulnerability scanner |
| `Nmap Scripting Engine` | Nmap with web probing scripts |
| `python-requests/2.x` | Python script — custom tooling |
| `Hydra` | Password brute force tool |
| `Mozilla/5.0 (Windows NT...)` | Standard browser — could be normal or spoofed |

**Important caveat:** Skilled attackers spoof their User-Agent to look like a normal browser. The absence of a malicious User-Agent does not rule out an attack — it just means they were careful.

---

## 9. Always Check Both Directions — The C2 Pivot

This is one of the most important habits in threat hunting.

When you suspect an external IP, check it **two ways:**

**Direction 1 — Is it attacking inbound?**
```spl
index=botsv3 src_ip="91.207.175.249" sourcetype=stream:http
```
Is this IP sending requests TO our server?

**Direction 2 — Are we calling it outbound?**
```spl
index=botsv3 dest_ip="91.207.175.249"
```
Are any of our internal machines sending traffic TO this IP?

**Why this matters:** Command and Control (C2) works by having infected internal machines beacon outward to the attacker's server. If you only check inbound traffic, you miss this entirely. An IP flagged by threat intelligence as a C2 node will appear as a `dest_ip`, not a `src_ip`.

---

## 10. Cross-Referencing Data Sources — Correlation

Never rely on a single log source. Always validate findings across multiple sourcetypes.

In this case:
- `stream:http` showed the traffic behavior
- `suricata` confirmed whether any attack signatures fired
- All sourcetypes confirmed no outbound beaconing

When multiple independent data sources agree, your confidence in the finding goes up significantly. This is called **data source correlation** and it is a core SOC skill.

---

## 11. A Ruled-Out Lead is Still Professional Work

This case ended with the IP being ruled out as benign. That is not a failure.

**What makes it professional:**
- Every angle was investigated before ruling it out
- Each negative finding was documented with evidence
- The methodology was structured and repeatable
- The conclusion was supported by multiple data sources

In a real SOC, undocumented negative findings are a liability. If you ruled something out but didn't write it down, the next analyst will investigate the same IP again wasting time. Documented negative findings are as valuable as confirmed IOCs.

---

## Summary: The Triage Checklist

When you encounter a suspicious IP in web traffic, work through this checklist:

- [ ] Check traffic volume — is it anomalous?
- [ ] Classify the IP — private or public?
- [ ] Build a transaction timeline — what did they request?
- [ ] Check HTTP methods — any POST requests?
- [ ] Audit User-Agent strings — any attack tool signatures?
- [ ] Inspect URI paths and parameters — any payloads?
- [ ] Cross-reference with IDS — did Suricata fire?
- [ ] Flip to dest_ip — are internal hosts beaconing to it?
- [ ] Document your conclusion with evidence either way
