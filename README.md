# Identity Security Project

## Objective
The objective of this lab is to demonstrate **identity-based threat detection, investigation, and response** using **Splunk Enterprise** as the SIEM platform.

This project focuses on detecting suspicious authentication activity and identity abuse within an **Active Directory domain**, and documenting how a SOC would **detect, triage, and respond** to those threats.

It expands upon the  [Active Directory Project](https://github.com/CRT-3005/AD-Project) by ingesting, analysing, and operationalising Windows authentication telemetry for identity security use cases.

---

## Table of Contents
1. [Lab Environment](#lab-environment)  
2. [Skills Learned](#skills-learned)  
3. [Tools Used](#tools-used)  
4. [Workflow Overview](#workflow-overview)  
5. [Detection Coverage](#detection-coverage)  
6. [SOC Playbooks](#soc-playbooks)  
7. [Hardening & Prevention](#hardening--prevention)

---

## Lab Environment

The lab environment replicates a small enterprise network designed to simulate identity attacks and corresponding SOC detections.

<img width="668" height="655" alt="Identity-Security-Project drawio" src="https://github.com/user-attachments/assets/86a1ef93-742f-4e0c-942f-63d2f7bbbc55" />

**Domain:** ADProject.local  
**Network:** 192.168.10.0/24  

**Splunk Server:** 192.168.10.10  
**Domain Controller:** 192.168.10.7  
**Windows 11 Client:** 192.168.10.100  
**Attacker (Kali Linux):** 192.168.10.250  

### Host Overview

| Hostname | Role | Operating System | Purpose |
|----------|------|------------------|---------|
| **ADDC01** | Domain Controller | Windows Server 2022 | AD DS, DNS, authentication logging |
| **TARGET-PC** | Workstation | Windows 11 Pro | Domain-joined identity testing |
| **Splunk Server** | SIEM | Ubuntu Server 22.04 | Centralized log ingestion, correlation, and identity threat detection |
| **Kali** | Attacker | Kali Linux | Kerberos, NTLM, SMB attack simulation |

### Network Configuration
All systems operate on the same internal network (192.168.10.0/24).  
**Splunk Universal Forwarders** on ADDC01 and TARGET-PC forward logs to Splunk over TCP **9997**.

---

## Skills Learned
- Windows authentication telemetry analysis (Kerberos & NTLM)
- Splunk SPL development and field extraction
- Detection engineering using correlation logic
- SOC alert scheduling and detection latency awareness
- Identity attack investigation workflows
- MITRE ATT&CK mapping for identity threats
- Windows identity hardening (LAPS)

---

## Tools Used
- **Splunk Developer Edition**
- **Splunk Universal Forwarder**
- **Splunk Add-on for Windows**
- **Active Directory (Windows Server 2022)**
- **Windows 11 Pro**
- **Kali Linux** (Kerbrute, CrackMapExec)
- **VirtualBox**

---

## Workflow Overview
1. **Log Generation** – Windows authentication events (4624, 4625, 4768, 4771)
2. **Log Forwarding** – Splunk UF forwards Security logs to SIEM
3. **Indexing & Parsing** – XML Security logs ingested with full fidelity
4. **Detection Engineering** – SPL written to detect identity abuse
5. **Correlation & Alerting** – Scheduled alerts reflect SOC workflows
6. **Investigation & Response** – Playbooks document analyst actions
7. **Hardening** – Controls implemented to reduce attack impact

---

## Detection Coverage

### 🔐 Kerberos Password Spray
- Tool: **Kerbrute**
- Event IDs: **4768 / 4771**
- Detection via regex-assisted extraction from Security XML

📄 Documentation:  
👉 `detections/kerberos-password-spray.md`

---

### 🔐 NTLM Password Spray
- Tool: **CrackMapExec**
- Event ID: **4625**
- Correlation based on distinct usernames per source IP

📄 Documentation:  
👉 `detections/ntlm-password-spray.md`

---

### 🔐 SMB Authentication Abuse (Valid Accounts)
- Tool: **CrackMapExec**
- Event ID: **4624 (Logon Type 3)**
- Detection using baseline comparison and source IP analysis

📄 Documentation:  
👉 `detections/smb-authentication-abuse.md`

---

## SOC Playbooks

SOC playbooks document **what an analyst does after an alert fires**, including investigation, validation, and response steps.

📘 Playbooks:
- **NTLM Password Spray Response**  
  👉 `playbooks/NTLM_Password_Spray_Playbook.md`

- **Kerberos Authentication Guessing**  
  👉 `playbooks/Kerberos_Authentication_Guessing_Playbook.md`

Each playbook includes:
- Alert context
- Investigation SPL
- Analyst decision points
- Containment and remediation guidance
- MITRE ATT&CK mapping

---

## Hardening & Prevention

### 🛡 Windows LAPS Deployment
To reduce lateral movement and credential reuse risk, **Windows LAPS** was deployed across the domain.

- Unique local administrator passwords per host
- Automatic rotation and AD-backed storage
- Verified via PowerShell, ADUC, and Event Viewer

📄 Documentation:  
👉 `hardening/LAPS_Hardening.md`

---

## Key Takeaways
- Identity attacks generate high-fidelity telemetry when auditing is configured correctly
- Kerberos and NTLM require different detection strategies
- Correlation over time is essential for password spray detection
- SOC alerts operate on defined schedules, not instant execution
- Hardening controls significantly reduce post-compromise impact

---

## Project Status
This project is actively expanding to include:
- Privilege escalation detection
- Group membership abuse
- Detection tuning and false positive reduction
