# Cybersecurity SOC Analyst Portfolio

Hands-on cybersecurity projects focused on Security Operations Center (SOC) monitoring, threat detection, and SIEM analysis using Splunk and Linux log data.

This portfolio demonstrates practical experience with:

* Security log analysis
* SIEM detection engineering
* Linux authentication monitoring
* SSH brute-force detection
* Threat hunting workflows
* SOC dashboard creation

All projects were built in a lab environment using Splunk Enterprise and Ubuntu Linux.

---

## Security Tools Used
* Splunk Enterprise
* Linux (Ubuntu Server)
* VirtualBox
* SPL (Search Processing Language)
* Regex log parsing
* SSH authentication logs

---

## SOC Skills Demonstrated
* SIEM log ingestion
* Security event monitoring
* Detection engineering
* Threat hunting
* Authentication attack analysis
* Dashboard development
* Security alert creation
* Incident investigation

---

## Cybersecurity Projects
### Project 1
**Linux Host Security Monitoring with Splunk**

SOC monitoring dashboard analyzing Linux authentication logs.

Features:

* Failed SSH login monitoring
* Privilege escalation detection
* Root activity visibility
* Scheduled security alerts
* SOC dashboard creation

[Project 1 Link](projects/project-01-linux-host-security-monitoring-splunk)

---

### Project 2
**Brute Force Detection & Threat Hunting** 

Investigation of SSH brute-force login attempts using Splunk log analysis and detection engineering.

Features:

* Time-based brute force detection
* Targeted account analysis
* Source IP attribution
* Detection threshold development
* SOC brute force detection report

[Project 2 Link](projects/project-02-brute-force-detection-splunk)

--- 

### Project 3
**Suspicious Login Investigation & Account Compromise Detection**

Simulated SOC investigation of suspicious authentication activity and potential compromised accounts.

Planned features:

* Successful login detection
* Suspicious login pattern analysis
* attacker behavior investigation
* SOC alert development

[Project 3 Link](projects/project-03-suspicious-login-investigation-splunk)

---

## Lab Architecture

```
Attacker Simulation
        ↓
Ubuntu Linux Authentication Logs
        ↓
/var/log/auth.log
        ↓
Splunk Log Ingestion
        ↓
SPL Threat Detection Queries
        ↓
SOC Monitoring Dashboard
```
