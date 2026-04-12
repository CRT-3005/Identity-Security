# Identity Security Project

## Objective

This project demonstrates identity security monitoring in an Active Directory lab from a SOC perspective. Using Splunk, it covers authentication telemetry collection, detection engineering, alert correlation, analyst investigation, and identity hardening validation.

The lab focuses on Kerberos and NTLM abuse, privileged account activity, service account risk, and dashboard-driven monitoring to show how identity threats can be detected, investigated, and reduced through defensive controls.

---

## At a Glance

- Active Directory identity security lab built in VirtualBox
- Splunk-based detection engineering for Kerberos, NTLM, and SMB authentication abuse
- SOC playbooks for alert investigation and response
- Hardening validation for Windows LAPS and Kerberos controls
- Dashboards for authentication pressure and Kerberos security posture

---

## Table of Contents
1. [Lab Environment](#lab-environment)  
2. [Skills Learned](#skills-learned)  
3. [Tools Used](#tools-used)  
4. [Workflow Overview](#workflow-overview)  
5. [Detection Coverage](#detection-coverage)  
6. [SOC Playbooks](#soc-playbooks)  
7. [Hardening & Prevention](#hardening)  
8. [Dashboards](#dashboards)  
9. [Key Takeaways](#key-takeaways)  
10. [Next Improvements](#next-improvements)

---

## Lab Environment

The lab simulates a small enterprise Active Directory environment used to generate, detect, and investigate identity-based attacks.

**Domain:** `ADProject.local`  
**Network:** `192.168.10.0/24`

### Host Overview

| Hostname | Role | Operating System | Purpose |
|---|---|---|---|
| ADDC01 | Domain Controller | Windows Server 2022 | AD DS, DNS, authentication logging |
| TARGET-PC | Workstation | Windows 11 Pro | Domain-joined identity testing |
| SPLUNK01 | SIEM | Ubuntu Server 22.04 | Log ingestion, correlation, and detection |
| KALI | Attacker | Kali Linux | Kerberos, NTLM, and SMB attack simulation |

### IP Addressing

| System | IP Address |
|---|---|
| Domain Controller | 192.168.10.7 |
| Splunk Server | 192.168.10.10 |
| Windows 11 Client | 192.168.10.100 |
| Kali Linux | 192.168.10.250 |

### Network Configuration

All systems operate on the same internal network. Splunk Universal Forwarders on ADDC01 and TARGET-PC forward Windows logs to Splunk over TCP 9997.

---

## Skills Learned

- Windows authentication telemetry analysis (Kerberos & NTLM)
- Splunk SPL development and XML field extraction
- Detection engineering using correlation logic
- Detection tuning and false positive reduction
- SOC alert scheduling and investigation workflows
- Identity attack investigation techniques
- MITRE ATT&CK mapping for identity threats
- Windows identity hardening (LAPS and Kerberos controls)

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

The project follows a SOC workflow from telemetry generation to detection, investigation, and hardening validation.

1. **Telemetry Generation**  
   Windows authentication events are generated across the domain, including Event IDs 4624, 4625, 4768, 4769, and 4771.

2. **Log Collection and Forwarding**  
   Splunk Universal Forwarders send Windows Security logs to Splunk for central analysis.

3. **Indexing and Parsing**  
   XML event data is ingested with full fidelity for field extraction and correlation.

4. **Detection Engineering**  
   SPL detections identify authentication abuse, Kerberos anomalies, and identity misuse.

5. **Correlation and Alerting**  
   Detections are scheduled and correlated over time to reduce noise and improve signal quality.

6. **Investigation and Response**  
   SOC playbooks guide triage, validation, and response.

7. **Hardening and Validation**  
   Identity controls are implemented and validated using live telemetry.

---

## Detection Coverage

This section documents the identity-based threats and authentication abuse scenarios detected within the lab environment.

The detections are designed around realistic SOC use cases, with a focus on high-signal identity telemetry, correlation over time, and clear analyst decision points. Where relevant, detections are supported by tuning, dashboards, and hardening controls to show full detection lifecycle ownership rather than isolated alert creation.

### 🔐 Kerberos Password Spray
Detects Kerberos password spray activity generated with **Kerbrute**.

- **Event IDs:** 4768, 4771
- **Detection Method:** Regex-assisted extraction from Security XML
- **Why it matters:** Identifies broad password guessing attempts against domain accounts over Kerberos

**Documentation:** `detections/kerberos-password-spray.md`

---

### 🔐 NTLM Password Spray
Detects NTLM password spray activity generated with **CrackMapExec**.

- **Event ID:** 4625
- **Detection Method:** Correlation based on distinct usernames per source IP
- **Why it matters:** Highlights repeated password guessing attempts against multiple accounts from a single source

**Documentation:** `detections/ntlm-password-spray.md`

---

### 🔐 SMB Authentication Abuse (Valid Accounts)
Detects successful SMB authentication from valid credentials used in suspicious patterns.

- **Event ID:** 4624 (Logon Type 3)
- **Detection Method:** Baseline comparison and source IP analysis
- **Why it matters:** Helps identify unauthorised lateral movement or suspicious network logon activity using legitimate accounts

**Documentation:** `detections/smb-authentication-abuse.md`

---

### 🔐 Failed → Successful Authentication Correlation
Correlates repeated authentication failures followed by a successful logon within a short time window.

- **Event IDs:** 4625, 4624
- **Detection Method:** Short-window correlation of failed and successful authentication activity
- **Why it matters:** Helps identify possible credential compromise, brute force success, or password reuse

**Documentation:** `detections/failed-to-successful-authentication-correlation.md`

---

### 🔐 Privileged Account Authentication Monitoring
Monitors authentication activity involving privileged or high-value accounts.

- **Event IDs:** 4624, 4625
- **Detection Method:** Focused monitoring of privileged account logons with tuning to remove expected administrative noise
- **Why it matters:** Improves visibility of risky authentication activity involving elevated accounts

**Documentation:** `detections/privileged-account-authentication-monitoring.md`

---

### 🌍 Impossible Travel Authentication (Kerberos)
Detects successful Kerberos authentication for the same account from multiple source IPs within a short time window.

- **Event IDs:** 4768, 4769
- **Detection Method:** Normalisation and correlation of successful Kerberos authentication activity
- **Why it matters:** Helps identify suspicious account use that may indicate credential misuse without relying on failed logons

**Documentation:** `detections/impossible-travel-kerberos-authentication.md`

---

### 🔐 Kerberoasting – Weak Kerberos Encryption
Detects Kerberos service tickets issued using non-AES encryption.

- **Event ID:** 4769
- **Detection Method:** Detection of service tickets issued with weak Kerberos encryption types
- **Why it matters:** Acts as a regression control in an AES-hardened domain and helps identify weaker kerberoasting exposure

**Documentation:** `detections/kerberoasting-weak-encryption-detection.md`

---

## SOC Playbooks

SOC playbooks document the investigative and response actions taken after an alert fires, turning detections into repeatable analyst workflows.

Each playbook shows how alerts are validated, contextualised, and escalated using authentication telemetry, enrichment queries, and identity context. The focus is on practical analyst decision-making, false positive handling, and response guidance rather than theoretical incident response.

### NTLM Password Spray Response
Supports investigation and response for suspected NTLM password spray activity.

**Documentation:** `playbooks/ntlm-password-spray-playbook.md`

---

### Kerberos Password Spray Response
Supports investigation and response for suspected Kerberos password spray activity.

**Documentation:** `playbooks/kerberos-password-spray-playbook.md`

---

Each playbook includes:

- Alert context
- Investigation SPL
- Analyst decision points
- Containment and remediation guidance
- MITRE ATT&CK mapping

---

## Hardening

This section covers the defensive controls implemented in the lab to reduce identity attack exposure and improve resilience against common authentication-based threats.

### 🛡 Windows LAPS Deployment
Windows LAPS was deployed across the domain to reduce local administrator password reuse and limit lateral movement opportunities.

- **Control Objective:** Unique local administrator passwords per host with automatic rotation
- **Validation:** Confirmed through PowerShell, Active Directory Users and Computers, and Event Viewer
- **Why it matters:** Reduces shared local admin risk and limits credential reuse across systems

**Documentation:** `hardening/laps-hardening.md`

---

### 🔐 Kerberos Hardening
Kerberos authentication was hardened to reduce credential theft and offline cracking risk.

- **Controls Implemented:** AES-only Kerberos encryption, Kerberoasting exposure review, and preauthentication validation across user accounts
- **Validation:** Confirmed using live Kerberos telemetry from Event IDs 4768 and 4769
- **Why it matters:** Strengthens Kerberos authentication security and helps reduce weak ticket exposure in the domain

**Documentation:** `hardening/kerberos-hardening.md`

---

## Dashboards

Custom Splunk dashboards provide SOC-level visibility into authentication activity, Kerberos security posture, and signs of identity abuse across the environment.

### 📊 Kerberos Security Posture Dashboard
Provides continuous visibility into Kerberos service ticket activity and domain Kerberos security controls.

- **Coverage:** Kerberos service ticket activity and encryption type usage
- **Use Case:** AES-only enforcement validation and kerberoasting exposure monitoring
- **Why it matters:** Helps identify weak encryption use, service account exposure, and configuration regressions

**Documentation:** `dashboards/kerberos-security-posture.md`

---

### 📊 Authentication Pressure Dashboard
Provides analyst visibility into failed authentication activity and common account targeting patterns.

- **Coverage:** Failed authentication volume, source IP targeting, and account targeting trends
- **Use Case:** Password spray identification and failed-to-successful authentication correlation
- **Why it matters:** Helps analysts spot authentication abuse quickly and review potential compromise patterns

**Documentation:** `dashboards/authentication-pressure-dashboard.md`

---

## Key Takeaways

- Identity-based attacks generate high-value telemetry when Windows authentication auditing is configured correctly and centrally ingested into a SIEM.
- Kerberos security depends on **detection, hardening, and continuous validation**, not just alerting on known attack tools or signatures.
- Enforcing AES-only Kerberos encryption and verifying preauthentication settings reduces exposure to Kerberoasting and AS-REP roasting.
- Service accounts remain a key identity attack surface and should be monitored, hardened, and validated through live authentication telemetry.
- Kerberos detections can also act as **regression controls**, helping identify security drift and the return of weaker legacy configurations.
- SOC dashboards improve visibility into authentication posture and help analysts spot risk early and respond to suspicious activity faster.
- Linking detections, hardening controls, and dashboards creates a full identity security lifecycle that reflects real SOC operations.

---

## Next Improvements

Planned next steps for the project include:

- Group membership abuse detection and monitoring for privileged roles
- Additional Kerberos abuse detections and regression controls
- Expanded SOC dashboards for identity posture and authentication visibility
- Further detection tuning, false positive reduction, and SOC playbook development

---

