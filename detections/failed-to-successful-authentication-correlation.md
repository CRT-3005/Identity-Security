# 🔐 Failed → Successful Authentication Correlation

This detection identifies suspicious authentication behaviour where multiple failed logon attempts are followed by a successful logon for the same user from the same source IP address within a short time window.

It is based on Windows Security events collected from a lab-based Active Directory environment and is designed to highlight higher-confidence authentication compromise scenarios.

---

## 🎯 Objective

The objective of this detection is to identify possible account compromise by correlating failed authentication attempts (Event ID 4625) followed by a successful authentication (Event ID 4624). This improves detection fidelity by prioritising cases where an attacker may have successfully guessed or obtained valid credentials.

---

## 🔍 Detection Workflow

This detection was developed using a structured SOC tuning approach:

1. Review failed and successful authentication activity together to understand normal retry behaviour
2. Build an untuned correlation to identify initial matches
3. Apply controlled tuning to reduce false positives while preserving malicious signal

---

## Step 1 – Correlation Baseline

Before building the correlation logic, failed and successful authentication events were reviewed together to understand normal retry behaviour.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" ("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| table _time EventID TargetUserName IpAddress
| sort _time
```

<img width="1881" height="812" alt="Correlation baseline" src="https://github.com/user-attachments/assets/10b008cf-66fb-4bde-908b-760719a80469" />

**Figure 1 – Authentication Activity Timeline (Failed and Successful Logons)**  
Baseline view of failed and successful authentication events before correlation or tuning.

---

## Step 2 – Untuned Correlation Detection

An initial correlation detection was created to identify users who experienced both failed and successful authentication attempts from the same IP address within a short time window.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" ("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| eval is_fail=if(EventID="4625",1,0)
| eval is_success=if(EventID="4624",1,0)
| bin _time span=10m
| stats sum(is_fail) as fails sum(is_success) as successes earliest(_time) as first_seen latest(_time) as last_seen by TargetUserName IpAddress
| where fails>=1 AND successes>=1
| sort -fails
```

<img width="1878" height="448" alt="Failed to successful authentication correlation" src="https://github.com/user-attachments/assets/f0c4972f-5fb2-4a6b-9036-de0c3704bede" />

**Figure 2 – Untuned Failed → Successful Authentication Correlation**  
Initial correlation results showing both legitimate behaviour and false positives.

---

## Step 3 – Tuned Correlation Detection

Controlled tuning was applied to reduce false positives while preserving malicious signal.

### Tuning Decisions
- Excluded localhost activity (`127.0.0.1`)
- Excluded machine accounts (accounts ending in `$`)
- Required more failures than successes
- Applied a minimum failure threshold

```spl
index=identity sourcetype="WinEventLog:SecurityAll" ("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| search NOT IpAddress="127.0.0.1"
| search NOT TargetUserName="*$"
| eval is_fail=if(EventID="4625",1,0)
| eval is_success=if(EventID="4624",1,0)
| bin _time span=10m
| stats sum(is_fail) as fails sum(is_success) as successes earliest(_time) as first_seen latest(_time) as last_seen by TargetUserName IpAddress
| where fails>=3 AND successes>=1 AND fails>successes
| sort -fails
```

<img width="1874" height="455" alt="Tuned failed to successful authentication correlation" src="https://github.com/user-attachments/assets/6d568557-4f3f-468d-ba49-99758fb58378" />

**Figure 3 – Tuned Failed → Successful Authentication Correlation**  
Final tuned detection showing higher-confidence authentication compromise scenarios.

---

## ⚠️ False Positive Considerations

The following scenarios may still generate false positives and should be validated during investigation:

- Users mistyping passwords before successfully authenticating
- Administrative activity from trusted systems
- Automated scripts or scheduled tasks performing authentication retries
- Lab or testing activity involving account validation

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1110 | Brute Force | Adversaries attempt to gain access to accounts by guessing credentials. |
| T1110.003 | Password Spraying | Testing one password across multiple accounts to avoid lockouts. |
| TA0006 | Credential Access | Core tactic involving theft or abuse of credentials. |

---

## 📝 Summary

This detection identifies cases where repeated failed logons are followed by a successful authentication from the same source IP within a short time window.

By correlating Event IDs 4625 and 4624 and applying controlled tuning, the detection reduces benign retry noise and helps surface higher-confidence account compromise scenarios that warrant analyst investigation.
