# Project 1 — Linux Host Security Monitoring Using Splunk

## Overview

This project demonstrates the design and implementation of a lightweight Security Operations Center (SOC) monitoring solution for a Linux host using Splunk Enterprise.

The objective was to simulate real-world attack scenarios, build custom SPL detections, create a monitoring dashboard, and configure scheduled alerts while minimizing alert fatigue.

This project focuses on:

- SSH brute-force detection
- Privilege escalation monitoring
- Root activity visibility
- Alert threshold tuning
- SOC-style dashboard design

---

## 🏗 Lab Environment

- **SIEM Platform:** Splunk Enterprise (Trial License)
- **Operating System:** Ubuntu Linux (VirtualBox VM)
- **Log Source:** `/var/log/auth.log`
- **Index:** `main`
- **Log Type Monitored:** Authentication & sudo activity

---

## 🔍 Detection 1 — Failed SSH Login Attempts

### SPL Query

```spl
index=main source="/var/log/auth.log" "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src>\d+\.\d+\.\d+\.\d+)"
| stats count by src user
| where count >= 5

Purpose

Detect excessive SSH login failures from the same source IP and username combination, indicating possible brute-force activity.

Screenshot

![Failed SSH Detection Query](SPL Detection Query.png)

![SSH Attack Simulation](attack_simulation_ssh_failures.png)

🧪 Attack Simulation (Manual SSH Failures)

To validate the detection, multiple failed SSH login attempts were generated from:

fakeuser@localhost

attacker1@localhost

📌 Placeholder — Ubuntu terminal screenshot will be inserted here later.

![SSH Attack Simulation](attack_simulation_ssh_failures.png)

🔐 Detection 2 — Privilege Escalation via sudo
SPL Query
index=main source="/var/log/auth.log" "sudo:"
| rex field=_raw "sudo:\s+(?<user>[^:]+)\s*:"
| rex field=_raw "COMMAND=(?<command>.+)$"
| stats count by user command
| sort - count

Purpose

Monitor execution of privileged commands via sudo to detect suspicious privilege escalation attempts.

Screenshot



