# Enterprise-SIEM

A simplified Security Information and Event Management (SIEM) system,
built in Java from scratch — no frameworks, no external libraries, no Maven.
Just standard Java, compiled and run with two commands.

A SIEM is the tool a security team uses to pull logs from many systems into
one place, store them, and automatically flag suspicious patterns that a human
watching logs line-by-line would miss. This project implements the same core
pipeline — **generate → parse → detect → alert → report** — at a beginner-friendly
scale, inspired by real tools like Splunk, QRadar, and Wazuh.

---

## How to run it

```bash
javac *.java
java Main
```

Then open `dashboard.html` in your browser.

That's it. No `pom.xml`, no `pip install`, no setup steps.

---

## Project structure

| File | Responsibility |
|---|---|
| `LogEvent.java` | Data class — holds one parsed log line |
| `Alert.java` | Data class — holds one triggered alert |
| `SampleLogGenerator.java` | Writes a synthetic `sample_auth.log` with normal logins, a brute-force attack, and a port scan |
| `LogParser.java` | Reads `sample_auth.log`, parses each line into a `LogEvent` object |
| `DetectionEngine.java` | Runs brute-force and port-scan detection rules across all events |
| `DashboardBuilder.java` | Builds a dark-themed HTML report from all events and alerts |
| `Main.java` | Entry point — wires all five steps together |

---

## What it detects

### Rule 1 — Brute-force attack (HIGH severity)
**Condition:** The same IP address has 5 or more failed logins within a 5-minute window.

This is a classic password-guessing attack. One failed login is normal (everyone
mistype sometimes). Eight failed logins in under two minutes from the same IP is
a different story.

### Rule 2 — Port scan (MEDIUM severity)
**Condition:** The same IP address probes 10 or more *different* ports within a 1-minute window.

Port scanning is how attackers map out a target network before choosing where to
attack. We count *distinct* ports (not total probes), because probing port 22
five times is less suspicious than probing five different ports once each.

---

## What the demo log contains

| Events | Count | Alert expected? |
|---|---|---|
| Normal logins (3 users) | 5 | No |
| Legitimate single failed login | 1 | No — one failure is normal |
| Brute-force from `198.51.100.23` | 8 | **Yes — HIGH** |
| Port scan from `203.0.113.45` | 15 | **Yes — MEDIUM** |

The legitimate user's single failed login (`10.0.0.8`) correctly does **not**
trigger an alert. Avoiding false positives is half the challenge of real SIEM
detection logic — worth mentioning if you discuss this project in an interview.

All IP addresses are from RFC 5737 documentation-only ranges and do not belong
to any real person or organisation.

---

## Log format

```
2026-06-28 03:31:20 | AUTH_FAILED | ip=198.51.100.23 | user=admin
```

Real-world logs (Linux `auth.log`, Windows Event Log, firewall syslog) are
messier and need regular expressions to parse. This simplified, consistent format
keeps the focus on the SIEM concepts — parsing, grouping, correlation — without
regex complexity getting in the way.

---

## Ideas for extending this project

- Parse a real Linux `auth.log` file using regex instead of the synthetic format
- Add more detection rules — off-hours login alerts, impossible travel detection
- Replace the static HTML report with a live dashboard using a simple web server
- Add email or Slack notifications when a HIGH alert is raised
- Read logs in real-time by tailing a file instead of processing a snapshot
