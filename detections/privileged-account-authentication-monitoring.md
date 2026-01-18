# 🔐 Privileged Account Authentication Monitoring

This detection is based on Windows Security authentication events collected from a lab-based Active Directory environment. It focuses on identifying potentially suspicious authentication activity involving privileged accounts, with an emphasis on reducing noise from expected administrative behaviour.

---

## 🎯 Objective

The objective of this detection is to monitor authentication activity involving privileged accounts and identify high-risk scenarios such as unexpected network-based logons or abnormal authentication patterns, while minimising false positives through evidence-based tuning.

---

## 🔍 Detection Workflow

This detection was developed using a structured SOC tuning approach consisting of baseline analysis, an untuned detection to highlight noise, and controlled tuning to surface meaningful security signals.

---

## Step 1 – Privileged Account Baseline

Before building detection logic, a baseline of normal privileged account authentication behaviour was established.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" ("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| search TargetUserName="Administrator"
| table _time EventID TargetUserName IpAddress
| sort _time
```

<img width="1885" height="706" alt="Privileged account authentication activity" src="https://github.com/user-attachments/assets/73499259-d1b5-4701-9096-d4bef8af0391" />

**Figure 1 – Privileged Account Authentication Activity – Baseline**  
Baseline view of successful and failed authentication events involving the built-in Administrator account.

---

## Step 2 – Untuned Privileged Account Detection

An initial detection was created to alert on any privileged account authentication activity without contextual filtering.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" ("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| search TargetUserName="Administrator"
| stats count by EventID IpAddress
| sort -count
```

<img width="1901" height="490" alt="Untuned Privileged Account Authentication Detection" src="https://github.com/user-attachments/assets/1a9aa24d-e091-4cb6-a246-6d7ace23e1c3" />

**Figure 2 – Untuned Privileged Account Authentication Detection**  
Untuned detection output showing high volumes of benign administrative activity, demonstrating excessive noise.

---

## Step 3 – Tuned Privileged Account Detection

Controlled tuning was applied to reduce false positives and focus on higher-risk authentication scenarios.

### Tuning decisions:
- Excluded localhost activity (127.0.0.1)
- Excluded IPv6 loopback (::1)
- Excluded link-local IPv6 addresses (fe80::*)

```spl
index=identity sourcetype="WinEventLog:SecurityAll" ("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| search TargetUserName="Administrator"
| search NOT IpAddress="127.0.0.1"
| search NOT IpAddress="::1"
| search NOT IpAddress="fe80:*"
| stats count by EventID IpAddress
| sort -count
```

<img width="1883" height="414" alt="Tuned Privileged Account Authentication Detection" src="https://github.com/user-attachments/assets/2e65cd8b-0c02-45c9-b237-ec4532b8bcb0" />

**Figure 3 – Tuned Privileged Account Authentication Detection**  
Tuned detection output highlighting low-volume, higher-risk privileged authentication events suitable for investigation.

---

## ⚠️ False Positive Considerations

The following scenarios may generate false positives and should be reviewed during investigation:

- Legitimate administrative activity performed remotely from trusted systems  
- Scheduled tasks or automation using privileged credentials  
- System processes that do not populate a source IP address  
- Lab or testing activity involving privileged account usage  

Authentication events without a source IP address should be reviewed in conjunction with host context and logon type before escalation.

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|-------------|------|-------------|
| TA0006 | Credential Access | Adversaries attempt to obtain or abuse credentials. |
| T1078 | Valid Accounts | Use of legitimate credentials to access systems. |

---

## 📝 Summary

This detection demonstrates a structured approach to monitoring privileged account authentication activity in an Active Directory environment.

1. Normal administrative authentication behaviour was established through baseline analysis  
2. An untuned detection highlighted the inherent noise of privileged account activity  
3. Controlled tuning removed benign local authentication patterns  
4. The final detection surfaces low-volume, higher-risk privileged authentication events  

This approach reflects real-world SOC practices for balancing visibility and alert fidelity when monitoring high-value accounts.
