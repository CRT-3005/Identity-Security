# 📊 Authentication Pressure Dashboard

The Authentication Pressure dashboard provides SOC-level visibility into authentication activity across the environment, helping analysts identify abnormal logon behaviour, password spraying, and possible credential compromise.

The dashboard is configured for operational monitoring while still retaining historical views that demonstrate attack activity and detection validation across the lab.

---

## 🎯 Dashboard Objective

The objective of this dashboard is to support analyst review of authentication pressure by showing:

- Authentication success versus failure trends
- Targeted user accounts
- Source IP attribution
- Attack-relevant logon types
- Password spray behaviour
- Failed-to-successful authentication correlation

This allows analysts to move from high-level authentication visibility to focused compromise review within a single dashboard.

---

## Dashboard Scope

This dashboard uses Windows Security Event IDs:

- **4624** – Successful logon
- **4625** – Failed logon

The dashboard focuses on authentication pressure rather than all authentication activity. The aim is to highlight failed logons, targeted accounts, attacker source systems, and patterns consistent with password spraying or compromised credentials.

---

## Time Range Design

The dashboard is configured for **operational monitoring using a 24-hour default view**, while individual panels retain broader historical ranges where required to demonstrate lab activity and attack evidence.

- **Panel 1:** Last 24 hours
- **Panel 2:** Last 30 days
- **Panels 3–6:** All time

This design allows the dashboard to function as a practical SOC monitoring view while still showing validated detection behaviour from across the lab timeline.

---

## Panel 1 – Authentication Failure Volume (4625)

**Time Range:** Last 24 Hours  
**Purpose:** Establish a baseline of authentication activity and identify spikes in failed logons.

```spl
index=identity sourcetype="WinEventLog:SecurityAll"
("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex field=_raw "(?i)<EventID>(?<EventID>\d+)</EventID>"
| eval result=case(EventID="4624","Success", EventID="4625","Failure")
| timechart span=1h count by result
```

<img width="1005" height="279" alt="Authentication success vs failure volume" src="https://github.com/user-attachments/assets/5e55c13b-b262-4069-a16e-96d4efa8b20c" />

**Figure 1 – Authentication Success vs Failure Volume**  
Shows the hourly volume of successful and failed authentication activity to help analysts spot spikes, drift, or unusual failure pressure.

---

## Panel 2 – Top Accounts by Failed Authentication Attempts

**Time Range:** Last 30 Days  
**Purpose:** Identify accounts being targeted by authentication failures.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4625</EventID>"
| rex field=_raw "(?i)<Data\s+Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| search TargetUserName!=""
| search NOT TargetUserName="*$"
| stats count as failures by TargetUserName
| sort -failures
| head 10
```

<img width="1010" height="282" alt="Top accounts by failed authentication attempts" src="https://github.com/user-attachments/assets/4dcb8c0e-1461-414f-a701-585125be1220" />

**Figure 2 – Top Accounts by Failed Authentication Attempts**  
Highlights which accounts are receiving the highest volume of failed authentication attempts and may be under targeted pressure.

---

## Panel 3 – Top Source IPs by Failed Authentication Attempts

**Time Range:** All Time  
**Purpose:** Identify the origin of authentication pressure.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4625</EventID>"
| rex field=_raw "(?i)<Data\s+Name='IpAddress'>(?<IpAddress>[^<]+)<"
| search IpAddress!="" AND IpAddress!="-"
| search NOT IpAddress="127.0.0.1"
| search NOT IpAddress="::1"
| search NOT IpAddress="fe80:*"
| eval IpAddress=replace(IpAddress,"::ffff:","")
| stats count as failures by IpAddress
| sort -failures
| head 10
```

<img width="1009" height="89" alt="Top source IPs by failed authentication attempts" src="https://github.com/user-attachments/assets/eda32ede-a2fa-4f5e-a243-b1228b91af0e" />

**Figure 3 – Top Source IPs by Failed Authentication Attempts**  
Shows which IP addresses are responsible for the most failed authentication attempts and helps identify likely attacker systems or noisy sources.

---

## Panel 4 – Attack-Relevant Logon Types (3 and 10)

**Time Range:** All Time  
**Purpose:** Classify authentication attempts by attack-relevant logon types.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4625</EventID>"
| rex field=_raw "(?i)<Data\s+Name='LogonType'>(?<LogonType>[^<]+)<"
| search LogonType="3" OR LogonType="10"
| stats count by LogonType
| sort -count
```

<img width="1006" height="283" alt="Attack-relevant logon types" src="https://github.com/user-attachments/assets/ab3a501f-f28b-42f3-aaa1-cb92559c4cb2" />

**Figure 4 – Attack-Relevant Logon Types**  
Breaks failed authentication activity into network and remote-interactive logon types commonly associated with brute force, password spraying, or lateral movement attempts.

---

## Panel 5 – Password Spray Indicator – Distinct Users per Source IP

**Time Range:** All Time  
**Purpose:** Identify password spraying behaviour by detecting a single source IP targeting multiple user accounts within a short time window.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4625</EventID>"
| rex field=_raw "(?i)<Data\s+Name='IpAddress'>(?<IpAddress>[^<]+)<"
| rex field=_raw "(?i)<Data\s+Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| search IpAddress!="" AND IpAddress!="-"
| search NOT IpAddress="127.0.0.1"
| search NOT TargetUserName="*$"
| bin _time span=30m
| stats dc(TargetUserName) as distinct_users by _time IpAddress
| where distinct_users >= 3
| timechart span=30m max(distinct_users) by IpAddress
```

<img width="1006" height="223" alt="Password spray indicator distinct users per source IP" src="https://github.com/user-attachments/assets/939165d7-5e41-4d09-887c-d6ef00378656" />

**Figure 5 – Password Spray Indicator (Distinct Users per Source IP)**  
Highlights source IPs that target multiple distinct users in a short period, which is a strong behavioural indicator of password spraying.

---

## Panel 6 – Failed → Successful Authentication Correlation (10-Minute Window)

**Time Range:** All Time  
**Purpose:** Identify accounts that experienced failed authentication attempts followed by successful logons, indicating possible credential compromise.

```spl
index=identity sourcetype="WinEventLog:SecurityAll"
("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex field=_raw "(?i)<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "(?i)<Data\s+Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "(?i)<Data\s+Name='IpAddress'>(?<IpAddress>[^<]+)<"
| search TargetUserName!=""
| search NOT TargetUserName="*$"
| eval IpAddress=coalesce(IpAddress,"-")
| eval IpAddress=replace(IpAddress,"::ffff:","")
| search IpAddress!="-"
| search NOT IpAddress="127.0.0.1"
| search NOT IpAddress="::1"
| search NOT IpAddress="fe80:*"
| bin _time span=10m
| eval is_fail=if(EventID="4625",1,0)
| eval is_success=if(EventID="4624",1,0)
| stats sum(is_fail) as fails sum(is_success) as successes earliest(_time) as first_seen latest(_time) as last_seen by TargetUserName IpAddress
| where fails>=1 AND successes>=1
| convert ctime(first_seen) ctime(last_seen)
| sort -fails
```

<img width="1005" height="88" alt="Failed to successful authentication correlation" src="https://github.com/user-attachments/assets/08b9749f-2e5e-4d64-95df-029aafbb7792" />

**Figure 6 – Failed → Successful Authentication Correlation**  
Highlights accounts where repeated failures are followed by a successful authentication from the same source, which may indicate successful guessing or credential compromise.

---

## Threshold Rationale

- **Distinct users ≥ 3 within 30 minutes**  
  Selected to highlight password spray behaviour in a small lab while reducing benign noise.

- **Failed → successful correlation within 10 minutes**  
  Designed to highlight possible credential compromise rather than normal user error.

- **LogonType filtering (3 and 10)**  
  Focused on network-based authentication commonly associated with brute force and lateral movement activity.

---

## Analyst Workflow

The dashboard is intended to be used in sequence:

1. Review overall authentication volume for spikes or anomalies
2. Identify the most targeted accounts
3. Identify the most active source IPs
4. Review attack-relevant logon types
5. Validate spray behaviour through distinct-user patterns
6. Investigate possible compromise through failed-to-successful correlation

---

## Security Posture Interpretation

- A lack of recent spikes suggests stable authentication behaviour
- Historical spray activity should be visible through Panels 2, 3, and 5
- Failed-to-successful correlations help validate compromise-focused detection logic
- Persistent concentration around a single source IP or account set may justify deeper investigation

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1110 | Brute Force | Password guessing and spraying |
| T1078 | Valid Accounts | Successful use of compromised credentials |
| TA0006 | Credential Access | Credential abuse activity |

---

## 📝 Summary

This dashboard is operationally configured around a 24-hour monitoring view while preserving longer historical panels to demonstrate validated attack activity from across the lab.

It provides a practical SOC workflow for reviewing authentication pressure, identifying password spray behaviour, and spotting possible credential compromise through failed-to-successful authentication patterns.
