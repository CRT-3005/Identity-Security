# Identity Security Project

## Objective
The objective of this lab is to demonstrate identity-based threat detection and monitoring using **Splunk Enterprise** as the SIEM platform.  
This project focuses on detecting suspicious authentication activity and network behavior within an **Active Directory domain**.  
It expands upon the [Active Directory Project](https://github.com/CRT-3005/AD-Project) by ingesting, analysing, and visualising Windows and Sysmon logs for identity security purposes.

---

## Table of Contents
1. [Lab Environment](#lab-environment)  
2. [Skills Learned](#skills-learned)  
3. [Tools Used](#tools-used)  
4. [Workflow Overview](#workflow-overview)  
5. [Project Documentation](#project-documentation)

---

## Lab Environment

The lab environment replicates a small enterprise network designed to simulate identity attacks and corresponding detections.

<img width="668" height="650" alt="Identity-Security-Project drawio" src="https://github.com/user-attachments/assets/60b1b91c-0bcd-4537-ad26-8a5a4577fdc9" />

**Domain:** ADProject.local  
**Network:** 192.168.10.0/24  

**Splunk Server:** 192.168.10.10  
**Domain Controller:** 192.168.10.7  
**Windows 11 Client:** 192.168.10.100  
**Attacker (Kali Linux):** 192.168.10.250  

### Host Overview

| Hostname | Role | Operating System | Purpose |
|----------|------|------------------|---------|
| **ADDC01** | Domain Controller | Windows Server 2022 | AD DS, DNS, Sysmon logging |
| **Win11Client** | Workstation | Windows 11 Pro | Domain-joined workstation for identity testing |
| **SplunkServer** | SIEM | Ubuntu Server 22.04 | Splunk Enterprise indexer/search head |
| **Kali** | Attacker | Kali Linux | Identity attack simulations (Kerbrute, etc.) |

### Network Configuration
All systems operate on the same NAT/Internal network (192.168.10.0/24).  
**Splunk Universal Forwarders** on ADDC01 and Win11Client forward logs to the Splunk server over TCP **9997**.

---

## Skills Learned
- Deployment & configuration of Splunk Universal Forwarders  
- Windows and Sysmon event ingestion into Splunk  
- Authentication log analysis (Kerberos, NTLM, 4624/4625)  
- Identity threat detection (Kerberos spray, failed logons, Sysmon events)  
- Mapping detections to MITRE ATT&CK  
- Building SIEM queries and detection workflows  

---

## Tools Used
- **Splunk Enterprise** – SIEM platform  
- **Splunk Add-on for Windows** – Field extraction normalization  
- **Active Directory (Windows Server 2022)**  
- **Windows 11 Enterprise Client**  
- **Sysmon v14 + SwiftOnSecurity config**  
- **Kali Linux** – Kerbrute & attack tooling  
- **VirtualBox** – Virtual lab environment  

---

## Workflow Overview
1. **Log Generation** – Windows eventing + Sysmon produce authentication and process telemetry  
2. **Log Forwarding** – Splunk UF ships logs to the SIEM  
3. **Indexing & Field Extraction** – Splunk parses Windows & Sysmon data  
4. **Detection Development** – Identify Kerberos spray, process events, failed logons  
5. **Analysis & Visualisation** – Examine identity-related alerts in Splunk  

---

## 📘 Project Documentation

### 🔧 Environment Setup & Configuration
Covers Splunk UF installation, log forwarding, index creation, Sysmon setup, Windows 11 upgrade, and validation.

👉 **https://github.com/CRT-3005/Identity-Security/blob/baae7b9afea79c1de6d4903108037e632b5d2731/configuration.md**

---

### 🔐 Identity Attack Detection & Analysis
Kerberos password spraying (Kerbrute), Windows Security Event analysis, and Splunk detection logic.

👉 **https://github.com/CRT-3005/Identity-Security/blob/baae7b9afea79c1de6d4903108037e632b5d2731/identity-attack-detections.md**

---
