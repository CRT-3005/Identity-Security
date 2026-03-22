# 📊 Authentication Pressure Dashboard

The Authentication Pressure dashboard provides visibility into authentication activity across the environment, allowing analysts to quickly identify abnormal login behaviour, password spraying, and potential credential compromise.

This dashboard is configured for operational monitoring while still enabling historical analysis of authentication activity.

---

## Dashboard Scope

This dashboard leverages Windows Security Event IDs:

- **4624** – Successful logon  
- **4625** – Failed logon  

It focuses on:

- Authentication success vs failure trends  
- Targeted user accounts  
- Source IP attribution  
- Attack vector classification  
- Password spraying behaviour  
- Failed → successful authentication correlation

---

## Time Range Design

The dashboard is configured for **operational monitoring using a 24-hour default view**, while individual panels demonstrate historical lab activity where required.

- **Panel 1:** Last 24 hours (operational monitoring)  
- **Panel 2:** Last 30 days (recent historical activity)  
- **Panel 3–6:** All time (full lab validation and attack evidence)  

This approach allows the dashboard to function as a real SOC monitoring tool while still showcasing detection capability.

---

## Panel 1 – Authentication Failure Volume (4625)
**Time Range: Last 24 Hours**
**Purpose:**  
Establish a baseline of authentication activity and identify spikes in failed logons.

```spl
index=identity sourcetype="WinEventLog:SecurityAll"
("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex field=_raw "(?i)<EventID>(?<EventID>\d+)</EventID>"
| eval result=case(EventID="4624","Success", EventID="4625","Failure")
| timechart span=1h count by result
```

<img width="1005" height="279" alt="Authentication Success vs Failure Volume" src="https://github.com/user-attachments/assets/5e55c13b-b262-4069-a16e-96d4efa8b20c" />

**Figure 1 – Authentication Success vs Failure Volume**

---

## Panel 2 – Top Accounts by Failed Authentication Attempts
**Time Range: Last 30 Days**
**Purpose:**  
Identify accounts being targeted by authentication failures.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4625</EventID>"
| rex field=_raw "(?i)<Data\s+Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| search TargetUserName!=""
| search NOT TargetUserName="*$"
| stats count as failures by TargetUserName
| sort -failures
| head 10
```

<img width="1010" height="282" alt="Top Accounts by Failed Authentication Attempts" src="https://github.com/user-attachments/assets/4dcb8c0e-1461-414f-a701-585125be1220" />

**Figure 2 – Top Accounts by Failed Authentication Attempts**

---

## Panel 3 – Top Source IPs by Failed Authentication Attempts
**Time Range: All Time**
**Purpose:**  
Identify the origin of authentication pressure.

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

<img width="1009" height="89" alt="Top Source IPs by Failed Authentication Attempts" src="https://github.com/user-attachments/assets/eda32ede-a2fa-4f5e-a243-b1228b91af0e" />

**Figure 3 – Top Source IPs by Failed Authentication Attempts**

---

## Panel 4 – Attack-Relevant Logon Types (3 & 10)
**Time Range: All Time**
**Purpose:**  
Classify authentication attempts by attack-relevant logon types.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4625</EventID>"
| rex field=_raw "(?i)<Data\s+Name='LogonType'>(?<LogonType>[^<]+)<"
| search LogonType="3" OR LogonType="10"
| stats count by LogonType
| sort -count
```

<img width="1006" height="283" alt="Attack-Relevant Logon Types" src="https://github.com/user-attachments/assets/ab3a501f-f28b-42f3-aaa1-cb92559c4cb2" />

**Figure 4 – Attack-Relevant Logon Types**

---

## Panel 5 – Password Spray Indicator – Distinct Users per Source IP
**Time Range: All Time**
**Purpose:**  
Identify password spraying behaviour by detecting a single source IP targeting multiple user accounts within a short time window.

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

<img width="1006" height="223" alt="Password Spray Indicator (Distinct Users per Source IP)" src="https://github.com/user-attachments/assets/939165d7-5e41-4d09-887c-d6ef00378656" />

**Figure 5 – Password Spray Indicator (Distinct Users per Source IP)**

---

## Panel 6 – Failed → Successful Authentication Correlation (10m Window)
**Time Range: All Time**
**Purpose:**  
Identify accounts that experienced authentication failures followed by successful login attempts, indicating potential credential compromise.

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

<img width="1005" height="88" alt="Failed vs Successful Authentication Correlation" src="https://github.com/user-attachments/assets/08b9749f-2e5e-4d64-95df-029aafbb7792" />

**Figure 6 – Failed → Successful Authentication Correlation**

---

## Threshold Rationale

- **Distinct users ≥ 3 within 30 minutes**  
  Selected to highlight password spray behaviour in a small lab while reducing noise.

- **Failed → Successful correlation within 10 minutes**  
  Designed to detect probable credential compromise rather than user error.

- **LogonType filtering (3, 10)**  
  Focused on network-based authentication commonly associated with brute force and lateral movement.

---

## Analyst Workflow

This dashboard is intended to be used sequentially:

1. Review authentication volume for anomalies (Panel 1)
2. Identify targeted accounts (Panel 2)
3. Identify source of activity (Panel 3)
4. Determine attack method (Panel 4)
5. Validate spray behaviour (Panel 5)
6. Investigate potential compromise (Panel 6)

---

## Security Posture Interpretation

- A lack of recent spikes indicates stable authentication behaviour  
- Historical spray activity is clearly identifiable through Panels 2, 3, and 5  
- Failed → successful correlations confirm detection logic effectiveness  

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1110 | Brute Force | Password guessing and spraying |
| T1078 | Valid Accounts | Successful use of compromised credentials |
| TA0006 | Credential Access | Credential abuse activity |

---

## Summary

This dashboard is operationally configured for a 24-hour monitoring window but for this purpose historical entries were gathered to show how the panels operate.
