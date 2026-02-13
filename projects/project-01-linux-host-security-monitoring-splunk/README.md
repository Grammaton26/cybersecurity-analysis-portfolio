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




