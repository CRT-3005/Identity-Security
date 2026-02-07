# Identity Security Project

## Objective

This project demonstrates end-to-end identity security monitoring within an Active Directory environment, focusing on how a Security Operations Center (SOC) detects, validates, and mitigates authentication-based threats.

Using Splunk as the SIEM platform, the lab simulates real-world identity attack techniques, engineers high-signal detections, applies preventative hardening controls, and validates security posture through dashboards and telemetry. Emphasis is placed on Kerberos and NTLM authentication abuse, service account risk, and continuous monitoring to detect configuration regressions.

The goal of this project is to reflect realistic SOC workflows by combining detection engineering, identity hardening, and operational visibility rather than isolated attack simulations.

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
| **Kali** | Attacker | Kali Linux | Kerberos, NTLM, SMB, and authentication abuse simulation |

### Network Configuration

All systems operate on the same internal network (192.168.10.0/24).  
**Splunk Universal Forwarders** on ADDC01 and TARGET-PC forward logs to Splunk over TCP **9997**.

---

## Skills Learned

- Windows authentication telemetry analysis (Kerberos & NTLM)
- Splunk SPL development and XML field extraction
- Detection engineering using correlation logic
- Detection tuning and false positive reduction
- SOC alert scheduling and investigation workflows
- Identity attack investigation techniques
- MITRE ATT&CK mapping for identity threats
- Windows identity hardening (LAPS)

---

## Tools Used

- **Splunk Developer Edition**
- **Splunk Universal Forwarder**
- **Splunk Add-on for Windows**
- **Active Directory (Windows Server 2022)**
- **Windows 11 Pro**
- **Kali Linux** (Kerbrute, CrackMapExec, Kerberos tooling)
- **VirtualBox**

---

## Workflow Overview

1. **Telemetry Generation**  
   Windows authentication activity is generated across the domain, including successful and failed logons, Kerberos ticket requests, and authentication failures (Event IDs 4624, 4625, 4768, 4769, 4771).

2. **Log Collection & Forwarding**  
   Splunk Universal Forwarders securely transmit Windows Security Event logs from domain hosts to the SIEM for centralized analysis.

3. **Indexing & Parsing**  
   XML-based Windows Security logs are ingested with full fidelity, enabling reliable field extraction and accurate correlation.

4. **Detection Engineering**  
   SPL detections are engineered to identify identity abuse patterns, authentication anomalies, and Kerberos-related attack techniques.

5. **Correlation & Alerting**  
   Detections are scheduled and correlated over time to reflect realistic SOC alerting workflows and reduce false positives.

6. **Investigation & Response**  
   SOC playbooks guide analyst investigation, validation, and response actions following alert generation.

7. **Hardening & Validation**  
   Preventative identity security controls are implemented and validated using live authentication telemetry to reduce attack surface and detect configuration regressions.

---

## Detection Coverage

This section documents the identity-based threats and authentication abuse scenarios detected within the lab environment.

Each detection is designed to reflect realistic SOC use cases, focusing on high-signal identity telemetry, correlation over time, and clear analyst decision points. Where applicable, detections are paired with tuning, dashboards, and hardening controls to demonstrate full detection lifecycle ownership rather than isolated alert creation.

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

### 🔐 Failed → Successful Authentication Correlation
- Event IDs: **4625 → 4624**
- Correlates authentication failures followed by success within short time windows
- Identifies potential credential compromise and reuse

📄 Documentation:  
👉 `detections/failed-to-successful-authentication-correlation.md`

---

### 🔐 Privileged Account Authentication Monitoring
- Event IDs: **4624 / 4625**
- Focuses on high-risk authentication involving privileged accounts
- Tuned to remove expected local administrative noise

📄 Documentation:  
👉 `detections/privileged-account-authentication-monitoring.md`

---

### 🌍 Impossible Travel Authentication (Kerberos)
- Event IDs: **4768 / 4769**
- Detects successful Kerberos authentication from multiple source IPs within a short time window
- Uses normalization and correlation to identify credential misuse without failures

📄 Documentation:  
👉 `detections/impossible-travel-kerberos-authentication.md`

---
### 🔐 Kerberoasting – Weak Kerberos Encryption
- Event ID: **4769**
- Detection of Kerberos service tickets issued using non-AES encryption
- Acts as a regression control in an AES-hardened domain

📄 Documentation:  
👉 `detections/kerberoasting-weak-encryption-detection.md`

---

## SOC Playbooks

SOC playbooks document the investigative and response actions taken after an alert fires, translating detections into repeatable analyst workflows.

Each playbook outlines how alerts are validated, contextualized, and escalated using authentication telemetry, enrichment queries, and identity context. The focus is on practical decision-making, false positive handling, and response guidance rather than theoretical incident response.

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

### 🔐 Kerberos Hardening
Kerberos authentication was hardened to reduce credential theft and offline cracking risks.

Key controls implemented and validated:
- AES-only Kerberos encryption enforced
- Service account Kerberoasting risk assessed
- Kerberos preauthentication verified across user accounts
- Hardening validated using live Kerberos telemetry (Event IDs 4768 / 4769)

📄 Documentation:  
👉 `hardening/kerberos-hardening.md`

---

## Dashboards

Custom Splunk dashboards were created to provide SOC-level visibility into authentication security and identity posture.

### 📊 Kerberos Security Posture Dashboard
- Continuous visibility into Kerberos service ticket activity
- Encryption posture validation (AES-only enforcement)
- Kerberoasting exposure monitoring
- Early detection of configuration regressions

📄 Documentation:  
👉 `dashboards/kerberos-security-posture.md`

---

## Key Takeaways

- Identity-based attacks generate high-fidelity telemetry when Windows authentication auditing is correctly configured and centrally ingested into a SIEM.
- Kerberos security requires a combination of **detection, hardening, and continuous validation**, not just alerting on attack tools or signatures.
- Enforcing AES-only Kerberos encryption and verifying preauthentication settings significantly reduces Kerberoasting and AS-REP roasting risk.
- Service accounts represent a critical identity attack surface and must be monitored, hardened, and validated using live authentication telemetry.
- Effective Kerberos detections can act as **regression controls**, alerting when security posture drifts or legacy configurations reappear.
- SOC dashboards provide continuous visibility into authentication posture, enabling analysts to validate controls, identify risk early, and respond quickly to anomalies.
- Correlating detections, hardening controls, and dashboards creates a complete identity security lifecycle that mirrors real-world SOC operations.

---

## Project Status

This project is actively expanding to deepen identity security coverage and SOC operational maturity, with planned enhancements including:

- Group membership abuse detection and monitoring for privileged roles
- Advanced Kerberos abuse detections and regression controls
- Expanded SOC dashboards for identity posture and authentication visibility
- Additional detection tuning, false positive reduction, and SOC playbooks

