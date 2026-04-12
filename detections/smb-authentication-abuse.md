# 🔐 SMB Authentication Abuse Detection (NTLM)

This detection documents a successful SMB authentication using previously compromised NTLM credentials and shows how that activity is logged on the Domain Controller and identified in Splunk.

The aim is to connect **credential access** to **post-compromise authentication activity**, which is a common SOC investigation path after a password spray succeeds.

---

## 🎯 Objective

The objective of this detection is to:

- Use valid NTLM credentials obtained through a password spray
- Authenticate to the Domain Controller over SMB using **Logon Type 3**
- Observe the resulting Windows Security events
- Validate visibility and baseline context in Splunk

---

## 🧨 Attack Execution (Kali Linux)

Using **CrackMapExec**, SMB authentication was attempted against the Domain Controller with the compromised credentials for `VDinkley`.

```bash
crackmapexec smb 192.168.10.7 \
  -d ADProject.local \
  -u VDinkley \
  -p Welcome123
```

<img width="1278" height="136" alt="Successful SMB authentication from Kali" src="https://github.com/user-attachments/assets/9f70f1fb-e9b9-4666-9f19-e5ed94a731a4" />

**Figure 1 – SMB Authentication from Kali**  
Successful NTLM authentication over SMB using valid domain credentials.

---

## 🪵 Windows Event Log Evidence (Domain Controller)

A successful SMB authentication generates **Event ID 4624** with the following key values:

- **Logon Type:** 3 (Network)
- **Account Name:** VDinkley
- **Source IP:** 192.168.10.250
- **Authentication Package:** NTLM

<img width="1306" height="677" alt="Event ID 4624 logon type 3 for SMB authentication" src="https://github.com/user-attachments/assets/8b5751dc-2a25-48ed-ae50-b6b546ea0ad6" />

**Figure 2 – Event ID 4624 (Logon Type 3)**  
The Domain Controller logs a successful network logon using NTLM credentials.

---

## 🔍 Detection Workflow

This detection was developed using a simple validation workflow:

1. Generate successful SMB authentication from the attacker host
2. Confirm the resulting Windows Security event on the Domain Controller
3. Extract and review the activity in Splunk
4. Compare the result against normal 4624 baseline behaviour

---

## Step 1 – Detection in Splunk (Targeted View)

To confirm visibility, the following SPL was used to extract SMB logons originating from the attacker host.

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

<img width="1866" height="468" alt="Splunk SMB logon detection results" src="https://github.com/user-attachments/assets/54c5d1c5-dbbd-4858-870d-276781933229" />

**Figure 3 – Splunk SMB Logon Detection**  
Splunk confirms successful SMB logons from the attacker IP using `VDinkley`.

---

## Step 2 – Baseline Comparison (Normal Activity)

A broader view of **Event ID 4624** was used to establish baseline behaviour.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" earliest=-60m
| rex field=_raw "EventID>(?<EventID>\d+)<"
| search EventID=4624
| rex field=_raw "Data Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='LogonType'>(?<LogonType>\d+)<"
| table _time host TargetUserName LogonType
| sort -_time
```

<img width="1862" height="718" alt="Baseline Event ID 4624 logon activity" src="https://github.com/user-attachments/assets/9f2e18fe-2d78-4b4d-9b5e-2558300fed87" />

**Figure 4 – Baseline 4624 Logon Activity**  
The baseline shows frequent service and machine account logons, highlighting why a single `4624` event is not suspicious on its own and why context matters.

---

## 🕵️ Analyst Notes

- SMB logons (`Logon Type 3`) are common in Active Directory environments
- Single `4624` events are **not suspicious by themselves**
- Risk increases when:
  - The logon follows earlier `4625` failures
  - The source IP is unusual
  - The account recently failed authentication elsewhere
  - The activity falls outside the normal baseline

This stage demonstrates **post-compromise authentication activity**, not privilege escalation.

---

## ⚠️ False Positive Considerations

The following scenarios may generate similar SMB authentication patterns and should be reviewed during investigation:

- Legitimate remote administration from trusted systems
- Service or application access using valid domain credentials
- Scheduled tasks or automation authenticating over SMB
- Lab or support activity involving manual account validation

Analysts should review source IP ownership, account context, timing, and recent authentication history before escalation.

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1078 | Valid Accounts | Use of legitimate credentials |
| T1021.002 | SMB/Windows Admin Shares | Remote authentication via SMB |
| TA0001 | Initial Access | Follow-on access after credential compromise |

---

## 📝 Summary

This detection validates successful NTLM authentication after a password spray and confirms visibility of **Event ID 4624 (Logon Type 3)** in Splunk.

By comparing the attacker-driven SMB logon against normal 4624 baseline activity, the detection shows how analysts can separate meaningful post-compromise authentication behaviour from expected domain noise. This provides a useful foundation for later correlation with privilege escalation or lateral movement activity.
