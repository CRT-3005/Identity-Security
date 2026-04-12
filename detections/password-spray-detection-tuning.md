# 🧪 Detection Tuning – Password Spray

This page documents the tuning process used to refine a password spray detection built from Windows Security authentication events in a lab-based Active Directory environment.

The focus is on identifying password spraying through failed network logons while reducing false positives through controlled, evidence-based tuning.

---

## 🎯 Objective

The objective of this detection is to identify password spraying activity by detecting multiple failed authentication attempts from a single source IP address against multiple user accounts within a short time window, while minimising false positives through structured tuning.

This page demonstrates a practical SOC workflow for validating and refining identity-based detections.

---

## 🔍 Detection Workflow

The tuning process followed a structured approach:

1. Establish a baseline of normal authentication behaviour
2. Replay the untuned detection against baseline activity
3. Apply tuning changes based on observed false positives
4. Re-run the detection and compare the results

---

## Step 1 – Authentication Baseline

Before tuning the detection logic, a baseline of normal authentication behaviour was established using Windows Security events.

### Baseline Authentication Activity (Event ID 4624 / 4625)

<img width="1862" height="814" alt="Baseline authentication activity" src="https://github.com/user-attachments/assets/893a2f5b-3d6d-4604-a482-6c906b5cc0ac" />

**Figure 1 – Baseline Authentication Activity (Event ID 4624 / 4625)**  
Raw authentication baseline showing successful (`4624`) and failed (`4625`) logons across users and logon types before any tuning or exclusions.

---

### Successful Logon Types (Event ID 4624)

<img width="1879" height="460" alt="Successful logon types baseline" src="https://github.com/user-attachments/assets/8ebb26b9-843b-4db7-bb85-0b794e06d459" />

**Figure 2 – Successful Logon Types Baseline (Event ID 4624)**  
Distribution of successful authentication logon types. Network-based logons (`LogonType 3`) dominate, which is expected in a domain environment.

---

## Step 2 – Untuned Detection Replay

An initial password spray detection was replayed against the baseline data without tuning to observe alert behaviour and identify false positives.

### Untuned Password Spray Detection

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
The untuned detection surfaced repeated failed authentication attempts from a single internal IP address against multiple user accounts within short time windows, consistent with password spraying behaviour but still containing false positives.

---

## Step 3 – Detection Tuning

Controlled tuning was applied based on baseline observations to reduce false positives while preserving detection coverage.

### Tuning Decisions

- Excluded localhost authentication attempts (`127.0.0.1`)
- Excluded machine accounts (accounts ending in `$`)
- Increased the minimum number of distinct users required to trigger

### Tuned Password Spray Detection

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

<img width="1867" height="766" alt="Tuned password spray detection" src="https://github.com/user-attachments/assets/4df02c7c-4e14-4806-9090-d1b4190ea22f" />

**Figure 4 – Tuned Password Spray Detection (Reduced False Positives)**  
The tuned detection continues to identify password spraying behaviour while reducing benign and lab-generated noise.

---

## ⚠️ False Positive Considerations

The following scenarios may generate alerts that resemble password spraying behaviour and should be evaluated during investigation:

- Administrative or IT testing activity where multiple user accounts are intentionally authenticated from a single system
- Automated scripts or lab tooling performing repeated authentication attempts across multiple accounts
- Misconfigured services or applications using invalid or expired credentials against several accounts
- Identity management or monitoring tools validating credentials during synchronisation or health checks
- Internal systems performing bulk authentication checks, particularly in lab or testing environments

Analysts should validate the source IP, targeted account set, timing, and operational context before escalating alerts as confirmed password spraying activity.

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1110.003 | Password Spraying | Testing one password across multiple accounts to avoid account lockout. |
| TA0006 | Credential Access | Core tactical goal of obtaining or guessing valid credentials. |

---

## 📝 Summary

This page documents the tuning process used to improve a password spray detection in an Active Directory environment.

By baselining authentication behaviour, replaying the untuned logic, and applying targeted exclusions and thresholds, the detection retained visibility of password spraying activity while reducing false positives and improving operational value for analysts.
