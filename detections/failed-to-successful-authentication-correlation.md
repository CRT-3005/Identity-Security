# 🔐 Failed → Successful Authentication Correlation

This detection is based on Windows Security authentication events collected from a lab-based Active Directory environment. It focuses on identifying suspicious authentication behaviour where multiple failed logon attempts are followed by a successful logon for the same user from the same source IP address within a short time window.

---

## 🎯 Objective

The objective of this detection is to identify potential account compromise by correlating failed authentication attempts (EventID 4625) followed by successful authentication (EventID 4624). This approach increases detection fidelity by prioritising scenarios where an attacker may have successfully guessed or obtained valid credentials.

---

## 🔍 Detection Workflow

This detection was developed using a structured SOC tuning approach consisting of baseline analysis, an untuned correlation, and controlled tuning to reduce false positives.

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

<img width="1881" height="812" alt="Correlation basline" src="https://github.com/user-attachments/assets/10b008cf-66fb-4bde-908b-760719a80469" />

**Figure 1 – Authentication Activity Timeline (Failed and Successful Logons)**  
Baseline view of failed and successful authentication events prior to correlation or tuning.

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

<img width="1878" height="448" alt="Failed - Successful" src="https://github.com/user-attachments/assets/f0c4972f-5fb2-4a6b-9036-de0c3704bede" />

**Figure 2 – Untuned Failed → Successful Authentication Correlation**  
Initial correlation results showing both legitimate behaviour and false positives.

---

## Step 3 – Tuned Correlation Detection

Controlled tuning was applied to reduce false positives while preserving malicious signal.

### Tuning decisions:
- Excluded localhost activity (127.0.0.1)
- Excluded machine accounts (accounts ending in $)
- Required more failures than successes
- Applied minimum failure threshold

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

<img width="1874" height="455" alt="Tuned correlation" src="https://github.com/user-attachments/assets/6d568557-4f3f-468d-ba49-99758fb58378" />

**Figure 3 – Tuned Failed → Successful Authentication Correlation**  
Final tuned detection showing high-confidence authentication compromise scenarios.

---

## ⚠️ False Positive Considerations

The following scenarios may generate false positives and should be validated during investigation:

- Users mistyping passwords before successfully authenticating
- Administrative activity from trusted systems
- Automated scripts or scheduled tasks performing authentication retries
- Lab or testing activity involving account validation

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1110 | Brute Force | Adversaries attempt to gain access to accounts by guessing credentials. |
| T1110.003 | Password Spraying | Testing one password across multiple accounts to avoid lockouts. |
| TA0006 | Credential Access | Core tactic involving theft or abuse of credentials. |

---

## 📝 Summary

This detection demonstrates end-to-end identification of potential account compromise through authentication correlation.

1. Multiple failed authentication attempts occur for a user  
2. A successful authentication follows from the same source IP  
3. Windows Security logs record both events (4625 and 4624)  
4. Splunk correlates events within a defined time window  
5. Tuned logic reduces benign behaviour while preserving attack signal  

This detection reflects common SOC escalation logic used to prioritise high-confidence identity threats.
