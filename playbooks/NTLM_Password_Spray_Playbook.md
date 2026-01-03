# 🧭 SOC Incident Response Playbook  
## NTLM Password Spray Detection

This playbook defines the **standard SOC response workflow** when the *NTLM Password Spray Detected* correlation alert fires in Splunk.

It is designed to support **Tier 1 SOC analysts** by providing clear triage steps, escalation criteria, and response actions for identity-based attacks against Active Directory.

---

## 📌 Alert Overview

| Field | Value |
|------|------|
| **Alert Name** | NTLM Password Spray Detected |
| **Severity** | Medium → High (if successful logon observed) |
| **Detection Type** | Scheduled correlation alert |
| **Authentication Protocol** | NTLM |
| **MITRE ATT&CK** | T1110.003 – Password Spraying |
| **Data Source** | Windows Security Event Log (EventID 4625) |
| **SIEM** | Splunk Enterprise |

---

## 🎯 Detection Objective

Identify password spraying activity by correlating:

- Multiple NTLM authentication failures  
- From a single source IP address  
- Targeting multiple distinct user accounts  
- Within a defined time window  

This detection aims to identify **credential-guessing attacks** before they result in account compromise or lateral movement.

---

## 🚨 Alert Trigger Conditions

The alert triggers when:

- **EventID 4625** (failed logon) is observed  
- The same source IP targets **three or more distinct accounts**  
- Activity occurs within a **five-minute window**  

The alert is evaluated every five minutes using a scheduled correlation search.

---

## 🧑‍💻 Tier 1 Analyst Triage Workflow

### Step 1 – Validate the Alert

Confirm that the activity represents suspicious behaviour and not a false positive.

**Key questions:**
- Is the source IP internal or external?
- How many unique user accounts were targeted?
- Did the failures occur in rapid succession?
- Does the pattern resemble automation?

**Splunk Pivot:**
```spl
index=identity sourcetype="WinEventLog:SecurityAll" EventCode=4625
| stats dc(TargetUserName) as unique_accounts by IpAddress
```

---

### Step 2 – Check for Successful Authentication

Determine whether the password spray resulted in a successful logon.

**Splunk Pivot:**
```spl
index=identity sourcetype="WinEventLog:SecurityAll" EventCode=4624
| rex field=_raw "Data Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| table _time TargetUserName IpAddress LogonType
```

**Interpretation:**

| Result | Meaning |
|------|--------|
| No 4624 events | Attempted attack only |
| 4624 present | Confirmed credential compromise |

---

### Step 3 – Assess Scope and Impact

If authentication succeeded, assess the extent of access.

**Review:**
- Which account authenticated successfully?
- Was the account privileged?
- What logon type was used (e.g. Network, RDP)?
- Were additional systems accessed?

**Relevant Events:**
- **4624** – Successful logon  
- **4672** – Special privileges assigned  
- **4688** – Process creation  

---

## 🚦 Incident Classification

| Condition | Classification |
|---------|---------------|
| Only 4625 failures | Suspicious activity |
| 4625 followed by 4624 | Confirmed compromise |
| Privileged account involved | High severity incident |

---

## 🛡️ Containment Actions

### Immediate Actions
- Disable affected account(s)
- Reset compromised credentials
- Terminate active sessions
- Block source IP where appropriate

### Short-Term Actions
- Review recent authentication history
- Audit group memberships
- Validate no persistence mechanisms were created

---

## 🔐 Hardening & Prevention Recommendations

- Enforce strong password policies
- Implement account lockout thresholds
- Restrict or phase out NTLM where possible
- Enable MFA for privileged accounts
- Use LAPS to prevent lateral movement
- Monitor repeated authentication failures

---

## 🧠 Lessons Learned

- Password spraying is low-noise but detectable with correlation
- NTLM authentication produces reliable failure telemetry (EventID 4625)
- Detection latency is expected with scheduled alerts
- Behaviour-based detection is more effective than single-event alerts

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|-----------|-------------|
| Credential Access | T1110.003 | Password Spraying |
| Initial Access | T1078 | Valid Accounts |
| Lateral Movement | T1021 | Remote Services |

---

## 📄 Playbook Metadata

| Field | Value |
|------|------|
| **Author** | SOC Analyst |
| **Last Reviewed** | YYYY-MM-DD |
| **Applies To** | Active Directory environments monitored via Splunk |

---

## ✅ Playbook Status

This playbook supports **consistent, repeatable incident handling** for NTLM password spray activity and complements the NTLM correlation alert implemented in this project.
