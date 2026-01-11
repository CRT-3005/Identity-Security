# 🧪 Detection Tuning – Password Spray

This detection is based on Windows Security authentication events collected from a lab-based Active Directory environment and focuses on identifying password spraying activity through failed network logons.

---

## 🎯 Objective

The objective of this detection is to identify password spraying activity by detecting multiple failed authentication attempts from a single source IP address against multiple user accounts within a short time window, while minimising false positives through controlled, evidence based tuning.

This detection focuses on Windows Security authentication events and demonstrates a structured SOC tuning workflow.

---

## 🔍 Step 1 – Authentication Baseline

Before tuning any detection logic, a baseline of normal authentication behaviour was established using Windows Security events.

### 📊 Baseline Authentication Activity (EventID 4624 / 4625)

<img width="1862" height="814" alt="Baseline" src="https://github.com/user-attachments/assets/893a2f5b-3d6d-4604-a482-6c906b5cc0ac" />

**Figure 1 – Baseline Authentication Activity (EventID 4624 / 4625)**  
Raw authentication baseline showing successful (4624) and failed (4625) logons across users and logon types prior to any tuning or exclusions.

---

### 📈 Successful Logon Types (EventID 4624)

<img width="1879" height="460" alt="Successful logons" src="https://github.com/user-attachments/assets/8ebb26b9-843b-4db7-bb85-0b794e06d459" />

**Figure 2 – Successful Logon Types Baseline (EventID 4624)**  
Distribution of successful authentication logon types. Network based logons (LogonType 3) dominate, which is expected in a domain environment.

---

## 🧠 Step 2 – Untuned Detection Replay

An initial password spray detection was replayed against the baseline data without tuning to observe alert behaviour and identify false positives.

### 🚨 Untuned Password Spray Detection

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4625</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| bin _time span=5m
| stats dc(TargetUserName) as unique_users values(TargetUserName) as users count as attempts by _time IpAddress
| where unique_users >= 3
| sort -attempts
```

<img width="1873" height="764" alt="Untuned password spray detection" src="https://github.com/user-attachments/assets/42f980a7-4f2d-421b-8e01-7a3362fe764f" />

**Figure 3 – Untuned Password Spray Detection (Initial Results)**  
The untuned detection surfaced repeated failed authentication attempts from a single internal IP address against multiple user accounts within short time windows, consistent with password spraying behaviour.

---

## 🛠️ Step 3 – Detection Tuning

Controlled tuning was applied based on baseline observations to reduce false positives while preserving detection coverage.

### ✅ Tuning Decisions

- Excluded localhost authentication attempts (127.0.0.1)
- Excluded machine accounts (accounts ending in $)
- Increased the minimum number of distinct users required to trigger

### 🎯 Tuned Password Spray Detection

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4625</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| search NOT IpAddress="127.0.0.1"
| search NOT TargetUserName="*$"
| bin _time span=5m
| stats dc(TargetUserName) as unique_users values(TargetUserName) as users count as attempts by _time IpAddress
| where unique_users >= 5
| sort -attempts
```

<img width="1867" height="766" alt="Tuned password spray" src="https://github.com/user-attachments/assets/4df02c7c-4e14-4806-9090-d1b4190ea22f" />

**Figure 4 – Tuned Password Spray Detection (Reduced False Positives)**  
The tuned detection continues to identify password spraying behaviour while significantly reducing benign and lab generated noise.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1110.003 | Password Spraying | Testing one password across multiple accounts to avoid account lockout. |
| TA0006 | Credential Access | Core tactical goal to obtain or guess valid credentials. |

---

## Summary

This detection demonstrates end-to-end identification of password spraying activity in an Active Directory environment.

1. An attacker performs a password spray against multiple domain user accounts  
2. The Domain Controller records failed authentication attempts (EventID 4625)  
3. Splunk ingests and parses Windows Security logs  
4. The detection correlates failed logons across multiple users and a single source IP  
5. An analyst identifies authentication behaviour consistent with password spraying
