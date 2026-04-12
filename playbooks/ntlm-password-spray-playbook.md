# 🧭 SOC Incident Response Playbook  
## NTLM Password Spray Response

This playbook defines the standard SOC response workflow when the **NTLM Password Spray Detected** correlation alert fires in Splunk.

It is designed to support **Tier 1 SOC analysts** by providing clear triage steps, escalation criteria, and response actions for identity-based attacks against Active Directory.

---

## 📌 Alert Overview

| Field | Value |
|---|---|
| **Alert Name** | NTLM Password Spray Detected |
| **Severity** | Medium → High (if successful logon observed) |
| **Detection Type** | Scheduled correlation alert |
| **Authentication Protocol** | NTLM |
| **MITRE ATT&CK** | T1110.003 – Password Spraying |
| **Data Source** | Windows Security Event Log (`Event ID 4625`) |
| **SIEM** | Splunk Enterprise |
| **Index** | `identity` |

---

## 🎯 Detection Objective

Identify password spraying activity by correlating:

- Multiple NTLM authentication failures
- From a single source IP address
- Targeting multiple distinct user accounts
- Within a defined time window

This supports early identification of credential-guessing attacks before they lead to account compromise or lateral movement.

---

## 🚨 Alert Trigger Conditions

The alert triggers when:

- **Event ID 4625** (failed logon) is observed
- The same source IP targets **three or more distinct accounts**
- The activity occurs within a **five-minute window**

The alert is evaluated every five minutes using a scheduled correlation search.

---

## 🔎 Correlation Search (Alert SPL)

Use this query as the scheduled alert search for NTLM password spray detection.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" earliest=-15m
| rex field=_raw "EventID>(?<EventID>\d+)<"
| search EventID=4625
| rex field=_raw "Data Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| bucket _time span=5m
| stats dc(TargetUserName) as unique_accounts count by IpAddress, _time
| where unique_accounts >= 3
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

Confirm that the activity represents suspicious behaviour and not an expected false positive.

Key questions:

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
| sort -_time
```

Interpretation:

| Result | Meaning |
|---|---|
| No 4624 events | Attempted attack only |
| 4624 present | Possible credential compromise |

---

### Step 3 – Assess Scope and Impact

If authentication succeeded, assess the extent of access.

Review:

- Which account authenticated successfully?
- Was the account privileged?
- What logon type was used, such as network logon or RDP?
- Were additional systems accessed?

Relevant events:

- **4624** – Successful logon
- **4672** – Special privileges assigned
- **4688** – Process creation

---

## 🚦 Incident Classification

| Condition | Classification |
|---|---|
| Only 4625 failures | Suspicious activity |
| 4625 followed by 4624 | Confirmed compromise |
| Privileged account involved | High severity incident |

---

## 🛡️ Containment Actions

### Immediate Actions

- Disable affected account(s) where appropriate
- Reset compromised credentials
- Terminate active sessions
- Block the source IP if justified by the environment

### Short-Term Actions

- Review recent authentication history
- Audit group memberships
- Validate that no persistence mechanisms were created

---

## 🔐 Hardening and Prevention Recommendations

- Enforce strong password policies
- Configure account lockout thresholds appropriate to the environment
- Restrict or phase out NTLM where possible
- Enable MFA for privileged accounts where available
- Use LAPS to reduce lateral movement risk
- Monitor repeated authentication failures across both user and source IP context

---

## 🧠 Lessons Learned

- Password spraying is low-noise but detectable through correlation
- NTLM authentication generates reliable failed logon telemetry through **Event ID 4625**
- Detection latency is expected with scheduled alerts
- Behaviour-based detection is more effective than relying on single-event alerts

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Credential Access | T1110.003 | Password Spraying |
| Initial Access | T1078 | Valid Accounts |
| Lateral Movement | T1021 | Remote Services |

---

## 📄 Playbook Metadata

| Field | Value |
|---|---|
| **Author** | SOC Analyst |
| **Last Reviewed** | YYYY-MM-DD |
| **Applies To** | Active Directory environments monitored via Splunk |

---

## ✅ Playbook Status

This playbook supports consistent Tier 1 handling for NTLM password spray activity and complements the NTLM correlation alert implemented in this project.
