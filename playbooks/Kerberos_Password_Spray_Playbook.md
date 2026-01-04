# 🔐 SOC Incident Response Playbook  
## Kerberos Authentication Guessing Detection (Single User)

This playbook defines the **standard SOC response workflow** when a Kerberos authentication guessing alert fires in Splunk.  
It is designed to support **Tier 1 SOC analysts** with clear triage steps, escalation criteria, and response actions for Kerberos-based credential guessing against Active Directory.

This playbook aligns to your lab scenario where **Kerbrute** was used to attempt authentication for a **single target user** (for example `JNeutron`) via the KDC on the Domain Controller.

---

## 📌 Alert Overview

| Field | Value |
|------|------|
| **Alert Name** | Kerberos Authentication Guessing Detected |
| **Severity** | Medium → High (if successful logon observed) |
| **Detection Type** | Scheduled correlation alert |
| **Authentication Protocol** | Kerberos |
| **MITRE ATT&CK** | T1110.001 – Password Guessing, T1110.003 – Password Spraying (if expanded to multiple users) |
| **Data Source** | Windows Security Event Logs (Kerberos Authentication Service) |
| **Primary Events** | 4768, 4771 |
| **SIEM** | Splunk Enterprise |
| **Index** | `identity` |

---

## 🎯 Detection Objective

Detect repeated **Kerberos authentication failures** against the **same user** originating from a single source IP within a short time window.  
This is useful for identifying brute-force style guessing or focused credential testing attempts before compromise.

---

## 🚨 Alert Trigger Conditions

The alert triggers when:

- Kerberos authentication events are observed from the Domain Controller  
- **EventID 4768** and or **EventID 4771** are present  
- A single source IP generates **three or more failures** against the same user inside **five minutes**

---

## 🔍 Evidence Query (Extraction and Review)

Use this query for fast validation and evidence collection. It extracts the key fields directly from XML Security logs.

```spl
index=identity host=ADDC01 source="WinEventLog:Security" earliest=-10m
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "(?i)<Data Name=\"TargetUser(?:Name|Name)\">(?<TargetUserName>[^<]+)"
| rex field=_raw "(?i)<Data Name=\"IpAddress\">(?<IpAddress>[^<]*)"
| where _indextime>=relative_time(now(), "-5m")
| search EventID=4768 OR EventID=4771
| table _time _indextime EventID TargetUserName IpAddress host
| sort -_indextime
```

---

## 🔎 Correlation Search (Alert SPL)

Use this query as the scheduled alert search for the single-user guessing scenario.

```spl
index=identity host=ADDC01 source="WinEventLog:Security" earliest=-5m
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4768 OR EventID=4771
| rex field=_raw "(?i)<Data Name=\"TargetUser(?:Name|Name)\">(?<TargetUserName>[^<]+)"
| rex field=_raw "(?i)<Data Name=\"IpAddress\">(?<IpAddress>[^<]*)"
| bucket _time span=5m
| stats count as failures by IpAddress, TargetUserName, _time
| where failures >= 3
| sort -_time
```

### Suggested Scheduling
- **Schedule:** Every 5 minutes (`*/5 * * * *`)
- **Time Range:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Trigger Mode:** Once per execution

---

## 🧑‍💻 Tier 1 Analyst Triage Workflow

### Step 1 – Validate the Alert

**Key questions:**
- Is the source IP expected for this environment (admin jump box, management network)?
- How many failures occurred in the window?
- Is the activity isolated to one account?

**Pivot for quick summary:**
```spl
index=identity host=ADDC01 source="WinEventLog:Security" earliest=-30m
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4768 OR EventID=4771
| rex field=_raw "(?i)<Data Name=\"TargetUser(?:Name|Name)\">(?<TargetUserName>[^<]+)"
| rex field=_raw "(?i)<Data Name=\"IpAddress\">(?<IpAddress>[^<]*)"
| stats count as failures min(_time) as first_seen max(_time) as last_seen by IpAddress, TargetUserName
| convert ctime(first_seen) ctime(last_seen)
| sort -failures
```

---

### Step 2 – Check for Successful Authentication

If the attacker guesses correctly, you may observe a successful logon shortly after.

**Pivot for successful logon activity:**
```spl
index=identity sourcetype="WinEventLog:SecurityAll" earliest=-30m
| rex field=_raw "EventID>(?<EventID>\d+)<"
| search EventID=4624
| rex field=_raw "Data Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| table _time TargetUserName IpAddress
| sort -_time
```

**Interpretation:**
- No 4624 events: attempted guessing only  
- 4624 present for the same user and source IP: potential compromise  

---

### Step 3 – Assess Account Risk

Check whether the targeted account is privileged or high value.

**On the Domain Controller:**
```powershell
Get-ADUser JNeutron -Properties Enabled, LockedOut, LastLogonDate, MemberOf | 
Select-Object Enabled, LockedOut, LastLogonDate, MemberOf
```

---

## 🚦 Incident Classification

| Condition | Classification |
|---------|---------------|
| Repeated 4768 or 4771 against one user | Suspicious activity |
| Failures followed by a 4624 from same source IP | Confirmed compromise |
| Privileged account targeted | High severity incident |

---

## 🛡️ Containment Actions

### Immediate Actions
- Reset password for the targeted account if risk is high
- Investigate source IP ownership (workstation, Kali attacker, unknown)
- If appropriate, isolate or block the source host on the network

### If Compromise Suspected
- Disable the affected account
- Force credential reset and revoke sessions
- Review recent activity for the user (logons, processes, remote access)

---

## 🔐 Hardening and Prevention Recommendations

- Enforce strong password policies and remove weak default passwords
- Set account lockout thresholds appropriate for the environment
- Restrict where administrative accounts can authenticate
- Monitor both Kerberos and NTLM pathways
- Use LAPS to reduce lateral movement risk if a workstation is compromised

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|-----------|-------------|
| Credential Access | T1110.001 | Password Guessing |
| Credential Access | T1110.003 | Password Spraying (if expanded to multiple users) |
| Credential Access | TA0006 | Credential Access (tactic) |

---

## 📄 Playbook Metadata

| Field | Value |
|------|------|
| **Author** | SOC Analyst |
| **Last Reviewed** | YYYY-MM-DD |
| **Applies To** | Active Directory environments monitored via Splunk |

---

## ✅ Playbook Status

This playbook supports consistent Tier 1 handling for Kerberos authentication guessing activity and complements the NTLM password spray detection and playbook in this project.
