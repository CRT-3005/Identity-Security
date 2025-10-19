# Identity Security Project

## Objective
The objective of this lab is to demonstrate identity-based threat detection and monitoring using **Splunk Enterprise** as the SIEM platform.  
This project focuses on detecting suspicious authentication activity and network behavior within an **Active Directory domain**.  
It expands upon the [Active Directory Project](https://github.com/CRT-3005/AD-Project) by leveraging Splunk to ingest, analyze, and visualize Windows and Sysmon logs related to identity security events.

## Lab Environment
The lab environment replicates a small enterprise network to simulate identity attacks and corresponding detections.

| Hostname | Role | Operating System | Purpose |
|-----------|------|------------------|----------|
| **ADDC01** | Domain Controller | Windows Server 2022 | Hosts Active Directory, DNS, and Sysmon for event logging |
| **Win10Client** | Workstation | Windows 10 Enterprise | Joined to the domain for user activity and testing |
| **SplunkServer** | SIEM | Ubuntu Server 22.04 | Hosts Splunk Enterprise for log ingestion, parsing, and alerting |

### Network Configuration
All systems operate within the same internal network segment.  
Splunk Universal Forwarders are deployed on **ADDC01** and **Win10Client** to forward Windows Event Logs and Sysmon logs to **SplunkServer** over TCP port **9997**.

<img width="668" height="650" alt="Identity-Security-Project drawio" src="https://github.com/user-attachments/assets/c3a53811-9936-403d-8c00-c92c57458f50" />

## Skills Learned
- Configuration of Splunk Universal Forwarders for Windows event ingestion  
- Analysis of authentication failures and network telemetry within Splunk  
- Correlation of security events to detect potential identity abuse  
- Understanding of MITRE ATT&CK techniques related to credential access and lateral movement  
- Development of Splunk search queries for custom detection use cases  

## Tools Used
- **Splunk Enterprise** – Security Information and Event Management (SIEM) platform  
- **Windows Event Logging** – Native Windows auditing for authentication and system activity  
- **Sysmon** – Advanced event logging for process creation and network connection telemetry  
- **Active Directory** – Provides centralized authentication and user management  
- **VirtualBox / VMware Workstation** – Virtualization environment for the lab infrastructure  

## Workflow Overview
1. **Log Generation:** Windows and Sysmon generate authentication and network events.  
2. **Log Forwarding:** Splunk Universal Forwarders send event data to Splunk Enterprise.  
3. **Data Indexing:** Splunk indexes and parses Windows and Sysmon data.  
4. **Detection Development:** Search queries are created to identify identity-related threats.  
5. **Alerting and Visualization:** Alerts and dashboards display notable activity for analysis.  

## Steps

### Step 1 – Configure Splunk Data Ingestion
Splunk Universal Forwarders were configured on both **ADDC01** and **Win10Client** to forward the following logs:
- **Windows Security Logs** (authentication activity – Event IDs 4624 and 4625)
- **Sysmon Logs** (process and network telemetry – Event IDs 1 and 3)

Configuration details and setup steps are documented in the [Active Directory Project](https://github.com/CRT-3005/AD-Project).

---

### Step 2 – Failed Logon Detection (Event ID 4625)
**Objective:** Detect repeated failed logon attempts that may indicate brute-force or credential stuffing activity.  

**Example Splunk Search:**
```spl
index=windows EventCode=4625
| stats count by user, ComputerName, Logon_Type, IpAddress
| where count > 5
