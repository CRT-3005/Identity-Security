# Identity Security Project

## Objective

This project demonstrates identity security monitoring in an Active Directory lab from a SOC perspective. Using Splunk, it covers authentication telemetry collection, detection engineering, alert correlation, analyst investigation, and identity hardening validation.

The lab focuses on Kerberos and NTLM abuse, privileged account activity, service account risk, and dashboard-driven monitoring to show how identity threats can be detected, investigated, and reduced through defensive controls.

---

## At a Glance

- Active Directory identity security lab built in VirtualBox
- Originally deployed on a flat `192.168.10.0/24` network for detection and hardening work
- Later migrated behind pfSense onto a routed `192.168.50.0/24` subnet for network segmentation
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
7. [Hardening & Network Segmentation](#hardening--network-segmentation)  
8. [Dashboards](#dashboards)  
9. [Key Takeaways](#key-takeaways)  
10. [Next Improvements](#next-improvements)  
11. [Project Status](#project-status)

---

## Lab Environment

The lab simulates a small enterprise Active Directory environment used to generate, detect, and investigate identity-based attacks.

The environment was originally built on a flat VirtualBox network using the `192.168.10.0/24` subnet. This supported the initial detection engineering, hardening validation, dashboard creation, and SOC playbook development.

After the core identity security work was completed, the lab was migrated behind a lightweight pfSense firewall onto a new routed internal subnet, `192.168.50.0/24`. This change was made to improve the lab architecture, introduce a security boundary, and create a foundation for future segmentation and firewall rule testing.

**Domain:** `ADProject.local`  
**Original Network:** `192.168.10.0/24`  
**Current Network:** `192.168.50.0/24` behind pfSense  
**Current Gateway:** `192.168.50.1`

### Host Overview

| Hostname | Role | Operating System | Purpose |
|---|---|---|---|
| ADDC01 | Domain Controller | Windows Server 2022 | AD DS, DNS, authentication logging |
| TARGET-PC | Workstation | Windows 11 Pro | Domain-joined identity testing |
| SPLUNK01 | SIEM | Ubuntu Server 22.04 | Log ingestion, correlation, and detection |
| KALI | Attacker | Kali Linux | Kerberos, NTLM, and SMB attack simulation |
| pfSense | Firewall / Gateway | pfSense CE | Lab gateway, routed subnet, and future firewall rule testing |

### IP Addressing

| System | Role | Original IP | Current IP |
|---|---|---:|---:|
| pfSense | Firewall / Gateway | N/A | `192.168.50.1` |
| Domain Controller | AD DS / DNS | `192.168.10.7` | `192.168.50.20` |
| Splunk Server | SIEM | `192.168.10.10` | `192.168.50.10` |
| Windows 11 Client | Domain-joined workstation | `192.168.10.100` | `192.168.50.110` |
| Kali Linux | Attack simulation host | `192.168.10.250` | `192.168.50.100` |

### Network Configuration

The lab initially operated as a flat internal network to support rapid build-out and testing of identity detections, hardening controls, dashboards, and SOC playbooks.

The current architecture places the core lab systems behind pfSense on the `192.168.50.0/24` subnet. pfSense acts as the default gateway and provides a foundation for future firewall rules, controlled attack paths, and segmentation testing.

Splunk Universal Forwarders on ADDC01 and TARGET-PC forward Windows logs to Splunk over TCP 9997. After the subnet migration, the forwarder outputs were updated to point to the new Splunk server address at `192.168.50.10:9997`.

Connectivity to the Splunk receiving port was confirmed from both Windows hosts using `Test-NetConnection`. Full event ingestion validation will be completed after the renewed Splunk Developer license is applied.

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
- Network segmentation and firewall-backed lab migration using pfSense

---

## Tools Used

- **Splunk Developer Edition**
- **Splunk Universal Forwarder**
- **Splunk Add-on for Windows**
- **Active Directory (Windows Server 2022)**
- **Windows 11 Pro**
- **Kali Linux** (Kerbrute, CrackMapExec, Kerberos tooling)
- **pfSense CE**
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

8. **Network Segmentation**  
   pfSense is used to place core lab systems behind a routed internal subnet and provide a foundation for future firewall rule testing.

---

## Detection Coverage

This section documents the identity-based threats and authentication abuse scenarios detected within the lab environment.

The detections are designed around realistic SOC use cases, with a focus on high-signal identity telemetry, correlation over time, and clear analyst decision points. Where relevant, detections are supported by tuning, dashboards, and hardening controls to show full detection lifecycle ownership rather than isolated alert creation.

### 🔐 Kerberos Password Spray

Detects Kerberos password spray activity generated with **Kerbrute**.

- **Event IDs:** 4768, 4771
- **Detection Method:** Regex-assisted extraction from Security XML
- **Why it matters:** Identifies broad password guessing attempts against domain accounts over Kerberos

**Documentation:** [`detections/kerberos-password-spray.md`](./detections/kerberos-password-spray.md)

---

### 🔐 NTLM Password Spray

Detects NTLM password spray activity generated with **CrackMapExec**.

- **Event ID:** 4625
- **Detection Method:** Correlation based on distinct usernames per source IP
- **Why it matters:** Highlights repeated password guessing attempts against multiple accounts from a single source

**Documentation:** [`detections/ntlm-password-spray.md`](./detections/ntlm-password-spray.md)

---

### 🔐 SMB Authentication Abuse (Valid Accounts)

Detects successful SMB authentication from valid credentials used in suspicious patterns.

- **Event ID:** 4624 (Logon Type 3)
- **Detection Method:** Baseline comparison and source IP analysis
- **Why it matters:** Helps identify unauthorised lateral movement or suspicious network logon activity using legitimate accounts

**Documentation:** [`detections/smb-authentication-abuse.md`](./detections/smb-authentication-abuse.md)

---

### 🔐 Failed → Successful Authentication Correlation

Correlates repeated authentication failures followed by a successful logon within a short time window.

- **Event IDs:** 4625, 4624
- **Detection Method:** Short-window correlation of failed and successful authentication activity
- **Why it matters:** Helps identify possible credential compromise, brute force success, or password reuse

**Documentation:** [`detections/failed-to-successful-authentication-correlation.md`](./detections/failed-to-successful-authentication-correlation.md)

---

### 🔐 Privileged Account Authentication Monitoring

Monitors authentication activity involving privileged or high-value accounts.

- **Event IDs:** 4624, 4625
- **Detection Method:** Focused monitoring of privileged account logons with tuning to remove expected administrative noise
- **Why it matters:** Improves visibility of risky authentication activity involving elevated accounts

**Documentation:** [`detections/privileged-account-authentication-monitoring.md`](./detections/privileged-account-authentication-monitoring.md)

---

### 🌍 Impossible Travel Authentication (Kerberos)

Detects successful Kerberos authentication for the same account from multiple source IPs within a short time window.

- **Event IDs:** 4768, 4769
- **Detection Method:** Normalisation and correlation of successful Kerberos authentication activity
- **Why it matters:** Helps identify suspicious account use that may indicate credential misuse without relying on failed logons

**Documentation:** [`detections/impossible-travel-kerberos-authentication.md`](./detections/impossible-travel-kerberos-authentication.md)

---

### 🔐 Kerberoasting – Weak Kerberos Encryption

Detects Kerberos service tickets issued using non-AES encryption.

- **Event ID:** 4769
- **Detection Method:** Detection of service tickets issued with weak Kerberos encryption types
- **Why it matters:** Acts as a regression control in an AES-hardened domain and helps identify weaker kerberoasting exposure

**Documentation:** [`detections/kerberoasting-weak-encryption-detection.md`](./detections/kerberoasting-weak-encryption-detection.md)

---

## SOC Playbooks

SOC playbooks document the investigative and response actions taken after an alert fires, turning detections into repeatable analyst workflows.

Each playbook shows how alerts are validated, contextualised, and escalated using authentication telemetry, enrichment queries, and identity context. The focus is on practical analyst decision-making, false positive handling, and response guidance rather than theoretical incident response.

### NTLM Password Spray Response

Supports investigation and response for suspected NTLM password spray activity.

**Documentation:** [`playbooks/ntlm-password-spray-playbook.md`](./playbooks/ntlm-password-spray-playbook.md)

---

### Kerberos Password Spray Response

Supports investigation and response for suspected Kerberos password spray activity.

**Documentation:** [`playbooks/kerberos-password-spray-playbook.md`](./playbooks/kerberos-password-spray-playbook.md)

---

Each playbook includes:

- Alert context
- Investigation SPL
- Analyst decision points
- Containment and remediation guidance
- MITRE ATT&CK mapping

---

## Hardening & Network Segmentation

This section covers the defensive controls implemented in the lab to reduce identity attack exposure and improve resilience against common authentication-based threats.

### 🛡 Windows LAPS Deployment

Windows LAPS was deployed across the domain to reduce local administrator password reuse and limit lateral movement opportunities.

- **Control Objective:** Unique local administrator passwords per host with automatic rotation
- **Validation:** Confirmed through PowerShell, Active Directory Users and Computers, and Event Viewer
- **Why it matters:** Reduces shared local admin risk and limits credential reuse across systems

**Documentation:** [`hardening/laps-hardening.md`](./hardening/laps-hardening.md)

---

### 🔐 Kerberos Hardening

Kerberos authentication was hardened to reduce credential theft and offline cracking risk.

- **Controls Implemented:** AES-only Kerberos encryption, Kerberoasting exposure review, and preauthentication validation across user accounts
- **Validation:** Confirmed using live Kerberos telemetry from Event IDs 4768 and 4769
- **Why it matters:** Strengthens Kerberos authentication security and helps reduce weak ticket exposure in the domain

**Documentation:** [`hardening/kerberos-hardening.md`](./hardening/kerberos-hardening.md)

---

### 🧱 Firewall Segmentation with pfSense

A lightweight pfSense firewall VM was deployed to move the lab away from a flat VirtualBox network and onto a routed internal subnet.

- **Control Objective:** Place core lab systems behind a dedicated firewall boundary and reduce unrestricted host-to-host communication
- **Validation:** Confirmed Kali, the Domain Controller, Windows client, and Splunk server could communicate through the new `192.168.50.0/24` lab segment
- **Why it matters:** Creates a stronger base for network segmentation, controlled attack paths, and future firewall rule testing

**Documentation:** [`firewall-segmentation.md`](./firewall-segmentation.md)

---

## Dashboards

Custom Splunk dashboards provide SOC-level visibility into authentication activity, Kerberos security posture, and signs of identity abuse across the environment.

### 📊 Kerberos Security Posture Dashboard

Provides continuous visibility into Kerberos service ticket activity and domain Kerberos security controls.

- **Coverage:** Kerberos service ticket activity and encryption type usage
- **Use Case:** AES-only enforcement validation and kerberoasting exposure monitoring
- **Why it matters:** Helps identify weak encryption use, service account exposure, and configuration regressions

**Documentation:** [`dashboards/kerberos-security-posture.md`](./dashboards/kerberos-security-posture.md)

---

### 📊 Authentication Pressure Dashboard

Provides analyst visibility into failed authentication activity and common account targeting patterns.

- **Coverage:** Failed authentication volume, source IP targeting, and account targeting trends
- **Use Case:** Password spray identification and failed-to-successful authentication correlation
- **Why it matters:** Helps analysts spot authentication abuse quickly and review potential compromise patterns

**Documentation:** [`dashboards/authentication-pressure-dashboard.md`](./dashboards/authentication-pressure-dashboard.md)

---

## Key Takeaways

- Identity-based attacks generate high-value telemetry when Windows authentication auditing is configured correctly and centrally ingested into a SIEM.
- Kerberos security depends on **detection, hardening, and continuous validation**, not just alerting on known attack tools or signatures.
- Enforcing AES-only Kerberos encryption and verifying preauthentication settings reduces exposure to Kerberoasting and AS-REP roasting.
- Service accounts remain a key identity attack surface and should be monitored, hardened, and validated through live authentication telemetry.
- Kerberos detections can also act as **regression controls**, helping identify security drift and the return of weaker legacy configurations.
- SOC dashboards improve visibility into authentication posture and help analysts spot risk early and respond to suspicious activity faster.
- Linking detections, hardening controls, and dashboards creates a full identity security lifecycle that reflects real SOC operations.
- The lab evolved from a flat network into a firewall-backed subnet, showing how detection engineering work can be paired with improved network architecture and segmentation planning.

---

## Next Improvements

Planned next steps for the project include:

- Apply the renewed Splunk Developer license
- Validate event ingestion from the Domain Controller and Windows client after the subnet migration
- Define and test pfSense firewall rules between Kali, endpoint, and infrastructure systems
- Group membership abuse detection and monitoring for privileged roles
- Additional Kerberos abuse detections and regression controls
- Expanded SOC dashboards for identity posture and authentication visibility
- Further detection tuning, false positive reduction, and SOC playbook development

---

## Project Status

The lab has been migrated from the original flat `192.168.10.0/24` network to a firewall-backed `192.168.50.0/24` subnet. Splunk Universal Forwarder outputs have been updated to use the new Splunk server address at `192.168.50.10:9997`, with TCP connectivity confirmed from both the Domain Controller and Windows client.

Current follow-up work focuses on applying the renewed Splunk Developer license, validating event ingestion after the subnet migration, and adding firewall rule testing.

---
