# 🔐 SMB Authentication Abuse Detection (NTLM)

This section documents a **successful SMB authentication** using previously compromised NTLM credentials and demonstrates how this activity is logged on the Domain Controller and detected in Splunk.

The goal is to bridge **credential access** and **post-compromise authentication activity**, which is a common SOC investigation path after a password spray succeeds.

---

## 🎯 Objective

- Use valid NTLM credentials obtained from a password spray
- Authenticate to the Domain Controller over SMB (Logon Type 3)
- Observe Windows Security Event Logs
- Validate detection and baseline behavior in Splunk

---

## 🧨 Attack Execution (Kali Linux)

Using **CrackMapExec**, SMB authentication was attempted against the Domain Controller using the compromised credentials for `VDinkley`.

```bash
crackmapexec smb 192.168.10.7 \
  -d ADProject.local \
  -u VDinkley \
  -p Welcome123
```

<img width="1278" height="136" alt="VDinkley SMB attack" src="https://github.com/user-attachments/assets/9f70f1fb-e9b9-4666-9f19-e5ed94a731a4" />

**Figure 1 – SMB Authentication from Kali**  
Successful NTLM authentication over SMB using valid domain credentials.

---

## 🪵 Windows Event Log Evidence (Domain Controller)

A successful SMB authentication generates **Event ID 4624** with:

- **Logon Type:** 3 (Network)
- **Account Name:** VDinkley
- **Source IP:** 192.168.10.250
- **Authentication Package:** NTLM

<img width="1306" height="677" alt="VDinkley SMB 4624 EventData" src="https://github.com/user-attachments/assets/8b5751dc-2a25-48ed-ae50-b6b546ea0ad6" />

**Figure 2 – Event ID 4624 (Logon Type 3)**  
The Domain Controller logs a successful network logon using NTLM credentials.

---

## 🔎 Detection in Splunk – Targeted View

To confirm visibility, the following SPL was used to extract SMB logons originating from the attacker host:

```spl
index=identity sourcetype="WinEventLog:SecurityAll" earliest=-60m
| rex field=_raw "EventID>(?<EventID>\d+)<"
| search EventID=4624
| rex field=_raw "Data Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| rex field=_raw "Data Name='LogonType'>(?<LogonType>\d+)<"
| where LogonType="3" AND IpAddress="192.168.10.250"
| table _time host TargetUserName IpAddress LogonType
| sort -_time
```

<img width="1866" height="468" alt="Splunk SMB VDinkley" src="https://github.com/user-attachments/assets/54c5d1c5-dbbd-4858-870d-276781933229" />

**Figure 3 – Splunk SMB Logon Detection**  
Splunk confirms successful SMB logons from the attacker IP using VDinkley’s account.

---

## 📊 Baseline Comparison (Normal Activity)

A broader view of **Event ID 4624** was used to establish baseline behavior:

```spl
index=identity sourcetype="WinEventLog:SecurityAll" earliest=-60m
| rex field=_raw "EventID>(?<EventID>\d+)<"
| search EventID=4624
| rex field=_raw "Data Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='LogonType'>(?<LogonType>\d+)<"
| table _time host TargetUserName LogonType
| sort -_time
```

<img width="1862" height="718" alt="Splunk SMB baseline" src="https://github.com/user-attachments/assets/9f2e18fe-2d78-4b4d-9b5e-2558300fed87" />

**Figure 4 – Baseline 4624 Logon Activity**  
Baseline shows frequent service and machine account logons, highlighting why correlation and context are critical.

---

## 🔍 Analyst Notes

- SMB logons (Logon Type 3) are extremely common in Active Directory
- Single 4624 events are **not suspicious by themselves**
- Risk emerges when:
  - Logon follows failed 4625 attempts
  - Source IP is unusual
  - Account recently failed authentication
  - Activity occurs outside baseline patterns

This step demonstrates **post-compromise authentication**, not privilege escalation yet.

---

## 🎯 MITRE ATT&CK Mapping

| Technique | Name | Description |
|--------|------|-------------|
| T1078 | Valid Accounts | Use of legitimate credentials |
| T1021.002 | SMB/Windows Admin Shares | Remote authentication via SMB |
| TA0001 | Initial Access | Follow-on access after credential compromise |

---

## 🧩 Summary

This stage validates:

- Successful NTLM authentication after password spray
- Event ID 4624 (Logon Type 3) visibility
- Splunk’s ability to distinguish attacker-driven logons from baseline noise

This forms the foundation for **privilege escalation**, **lateral movement**, and **correlation-based detections**, which are natural next steps in the lab.
