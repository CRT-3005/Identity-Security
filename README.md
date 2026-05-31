# Identity Security Project

## Objective

This project demonstrates identity security monitoring in an Active Directory lab from a SOC perspective. Using Splunk, it covers authentication telemetry collection, detection engineering, alert correlation, analyst investigation, identity hardening validation, and firewall-backed segmentation testing.

The lab focuses on Kerberos and NTLM abuse, privileged account activity, service account risk, dashboard-driven monitoring, and network segmentation controls to show how identity threats can be detected, investigated, and reduced through defensive controls.

---

## At a Glance

- Active Directory identity security lab built in VirtualBox
- Originally deployed on a flat `192.168.10.0/24` network for detection and hardening work
- Migrated behind pfSense onto a routed `192.168.50.0/24` main lab subnet
- Kali moved to a dedicated pfSense `ATTACK_NET` subnet on `192.168.60.0/24`
- Splunk-based detection engineering for Kerberos, NTLM, and SMB authentication abuse
- SOC playbooks for alert investigation and response
- Hardening validation for Windows LAPS and Kerberos controls
- Dashboards for authentication pressure and Kerberos security posture
- Firewall rule testing for Splunk, Domain Controller, and attacker subnet traffic paths
- Enumeration-driven firewall refinement using Kali tools including `nmap`, `ldapsearch`, and `enum4linux-ng`
- ATTACK_NET least-privilege hardening with explicit allow rules and default deny behaviour

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

The lab simulates a small enterprise Active Directory environment used to generate, detect, investigate, and reduce identity-based risk.

The environment was originally built on a flat VirtualBox network using the `192.168.10.0/24` subnet. This supported the initial detection engineering, hardening validation, dashboard creation, and SOC playbook development.

After the core identity security work was completed, the lab was migrated behind a lightweight pfSense firewall onto a routed main lab subnet, `192.168.50.0/24`. Kali was later moved to a dedicated `ATTACK_NET` subnet, `192.168.60.0/24`, so traffic from the attacker host to core infrastructure traverses pfSense and can be filtered.

**Domain:** `ADProject.local`  
**Original Network:** `192.168.10.0/24`  
**Main Lab Subnet:** `192.168.50.0/24` behind pfSense  
**ATTACK_NET Subnet:** `192.168.60.0/24` behind pfSense  
**Main Lab Gateway:** `192.168.50.1`  
**ATTACK_NET Gateway:** `192.168.60.1`

### Host Overview

| Hostname | Role | Operating System | Purpose |
|---|---|---|---|
| ADDC01 | Domain Controller | Windows Server 2022 | AD DS, DNS, authentication logging |
| TARGET-PC | Workstation | Windows 11 Pro | Domain-joined identity testing |
| SPLUNK01 | SIEM | Ubuntu Server 22.04 | Log ingestion, correlation, and detection |
| KALI | Attack Host | Kali Linux | Kerberos, NTLM, SMB, LDAP, and enumeration testing |
| pfSense | Firewall / Gateway | pfSense CE | Lab gateway, routed subnets, and firewall rule testing |

### IP Addressing

| System | Role | Original IP | Current IP |
|---|---|---:|---:|
| pfSense LAN | Main lab gateway | N/A | `192.168.50.1` |
| pfSense ATTACK_NET | Attacker subnet gateway | N/A | `192.168.60.1` |
| Domain Controller | AD DS / DNS | `192.168.10.7` | `192.168.50.20` |
| Splunk Server | SIEM | `192.168.10.10` | `192.168.50.10` |
| Windows 11 Client | Domain-joined workstation | `192.168.10.100` | `192.168.50.110` |
| Kali Linux | Attack simulation host | `192.168.10.250` | `192.168.60.100` |

### Network Configuration

The current architecture places core lab systems behind pfSense on the `192.168.50.0/24` subnet. Kali resides on the separate `192.168.60.0/24` `ATTACK_NET` subnet. This means traffic from Kali to Splunk and the Domain Controller must traverse pfSense before reaching the main lab subnet.

Splunk Universal Forwarders on ADDC01 and TARGET-PC forward Windows logs to Splunk over TCP `9997`. After the subnet migration, the forwarder outputs were updated to point to the Splunk server at `192.168.50.10:9997`.

Firewall rule testing confirmed that pfSense can block `ATTACK_NET` access to Splunk Web, the Splunk receiving port, Domain Controller LDAP, Domain Controller SMB, Domain Controller LDAPS, and Domain Controller NetBIOS while preserving trusted Windows log forwarding.

Kali enumeration testing added further validation. `enum4linux-ng` showed that LDAPS TCP `636` and NetBIOS TCP `139` were still reachable after the first LDAP and SMB restrictions. These findings were confirmed with `nmap`, blocked in pfSense, and retested until LDAP, LDAPS, SMB, and NetBIOS were filtered from `ATTACK_NET`.

The final firewall phase disabled the broad temporary `ATTACK_NET` allow rule. Explicit allow rules now preserve DNS, Kerberos, and selected ICMP validation paths, while unmatched traffic from `ATTACK_NET` is denied by default.

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
- Firewall rule validation across routed lab subnets
- Enumeration-driven firewall policy refinement from Kali
- Least-privilege firewall policy validation
- Default deny testing and validation
- Segmentation testing while preserving required SIEM ingestion

---

## Tools Used

- **Splunk Developer Edition**
- **Splunk Universal Forwarder**
- **Splunk Add-on for Windows**
- **Active Directory (Windows Server 2022)**
- **Windows 11 Pro**
- **Kali Linux**
- **Kerbrute**
- **CrackMapExec**
- **nmap**
- **ldapsearch**
- **enum4linux-ng**
- **pfSense CE**
- **VirtualBox**

---

## Workflow Overview

The project follows a SOC workflow from telemetry generation to detection, investigation, hardening, and segmentation validation.

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
   pfSense routes the main lab and attacker subnets, allowing firewall rules to control traffic between Kali, Splunk, and the Domain Controller.

9. **Firewall Rule Testing**  
   Allowed and blocked traffic paths are tested while Splunk ingestion is validated after each change.

10. **Enumeration-Driven Refinement**  
    Kali tools are used to check real enumeration paths and identify services that need extra firewall restrictions.

11. **Least-Privilege Hardening**  
    The broad temporary ATTACK_NET allow rule is disabled and replaced with explicit allow rules plus default deny behaviour.

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

A lightweight pfSense firewall VM was deployed to move the lab away from a flat VirtualBox network and onto routed internal subnets.

- **Control Objective:** Place core lab systems behind a firewall boundary and move Kali to a dedicated routed attacker subnet
- **Validation:** Confirmed Kali, the Domain Controller, Windows client, and Splunk server could route through pfSense
- **Why it matters:** Provides enforceable segmentation because attacker-to-infrastructure traffic now traverses pfSense

**Documentation:** [`firewall-segmentation.md`](./firewall-segmentation.md)

---

### 🧪 Firewall Rule Testing

Firewall rule testing validated controlled traffic between `ATTACK_NET` and key infrastructure systems.

- **Control Objective:** Restrict unnecessary attacker subnet access to Splunk and Domain Controller services
- **Validated Splunk Blocks:** Splunk Web TCP `8000` and Splunk receiving TCP `9997`
- **Validated Domain Controller Blocks:** LDAP TCP `389`, SMB TCP `445`, LDAPS TCP `636`, and NetBIOS TCP `139`
- **Enumeration Validation:** `enum4linux-ng` identified LDAPS and NetBIOS exposure after the first LDAP/SMB restrictions, which were then blocked and retested with `nmap`
- **Least-Privilege Validation:** Broad ATTACK_NET access was removed by disabling the temporary allow rule and retaining only explicit allow rules
- **Preserved Paths:** DNS TCP/UDP `53`, Kerberos TCP/UDP `88`, ICMP routing validation, and trusted Windows log forwarding
- **Default Deny:** Unmatched ATTACK_NET traffic to the internet and TARGET-PC was blocked
- **Why it matters:** Demonstrates tested segmentation controls while confirming required identity telemetry still reaches Splunk

**Documentation:** [`firewall-rule-testing.md`](./firewall-rule-testing.md)

---

### 📋 ATTACK_NET Policy State

The current ATTACK_NET policy state documents the active restrictions, retained testing paths, disabled temporary allow rule, and current least-privilege model.

- **Control Objective:** Summarise current attacker subnet policy after firewall rule validation
- **Current State:** Explicit allow and block rules are in place, and the temporary broad allow rule is disabled
- **Blocked Paths:** Splunk Web, Splunk receiving, LDAP, SMB, LDAPS, NetBIOS, unmatched TARGET-PC traffic, and unmatched internet traffic from `ATTACK_NET`
- **Allowed Paths:** DNS to ADDC01, Kerberos to ADDC01, and selected ICMP validation paths
- **Why it matters:** Shows the move from permissive testing access to least-privilege segmentation

**Documentation:** [`firewall-rule-policy-state.md`](./firewall-rule-policy-state.md)

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
- Kerberos security depends on detection, hardening, and continuous validation, not just alerting on known attack tools or signatures.
- Enforcing AES-only Kerberos encryption and verifying preauthentication settings reduces exposure to Kerberoasting and AS-REP roasting.
- Service accounts remain a key identity attack surface and should be monitored, hardened, and validated through live authentication telemetry.
- Kerberos detections can also act as regression controls, helping identify security drift and the return of weaker legacy configurations.
- SOC dashboards improve visibility into authentication posture and help analysts spot risk early and respond to suspicious activity faster.
- Linking detections, hardening controls, dashboards, and firewall validation creates a fuller identity security lifecycle that reflects real SOC operations.
- The lab evolved from a flat network into a routed pfSense design, proving that firewall rules only enforce traffic that traverses the firewall.
- Moving Kali to a dedicated `ATTACK_NET` subnet enabled tested segmentation between attacker tooling, Splunk, and Domain Controller services.
- Enumeration testing with Kali improved the firewall policy by identifying additional LDAPS and NetBIOS exposure after the first LDAP and SMB blocks.
- Disabling the temporary allow rule demonstrated least-privilege policy design and default deny behaviour for unmatched ATTACK_NET traffic.

---

## Next Improvements

Planned next steps for the project include:

- Build privileged group membership change detection and monitoring
- Add investigation notes for Event IDs `4728`, `4729`, `4732`, `4733`, `4756`, and `4757`
- Additional Kerberos abuse detections and regression controls
- Expanded SOC dashboards for identity posture and authentication visibility
- Further detection tuning, false positive reduction, and SOC playbook development
- Use BOTSv3 for wider SPL practice and analyst workflow development

---

## Project Status

The lab has been migrated from the original flat `192.168.10.0/24` network to a firewall-backed routed design. Core infrastructure now resides on the `192.168.50.0/24` main lab subnet, while Kali resides on the dedicated `192.168.60.0/24` `ATTACK_NET` subnet.

Splunk Universal Forwarder outputs have been updated to use the Splunk server address at `192.168.50.10:9997`, with TCP connectivity confirmed from both the Domain Controller and Windows client. The renewed Splunk Developer license has been applied and post-migration event ingestion has been validated from ADDC01 and TARGET-PC.

Firewall rule testing has validated that pfSense can block `ATTACK_NET` access to Splunk Web, the Splunk receiving port, Domain Controller LDAP, Domain Controller SMB, Domain Controller LDAPS, and Domain Controller NetBIOS while preserving trusted Windows log forwarding and controlled DNS/Kerberos testing paths.

Kali enumeration testing showed a practical refinement loop: identify exposed services with attacker tools, confirm exposure with `nmap`, block the traffic in pfSense, retest the result, and then validate Splunk ingestion.

ATTACK_NET least-privilege hardening is now complete. The temporary broad allow rule has been disabled, explicit allow rules preserve DNS, Kerberos, and selected ICMP validation paths, and unmatched traffic is denied by default. Splunk ingestion remains functional from the main lab subnet.

Current follow-up work can now move back to identity detection engineering, with privileged group membership monitoring as the next recommended detection area.

---
