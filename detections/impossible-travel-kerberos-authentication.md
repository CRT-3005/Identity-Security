# 🌍 Impossible Travel Authentication Detection (Kerberos-Based)

This detection identifies scenarios where a single user successfully authenticates from multiple source locations within a short time window, indicating possible credential misuse.

It is based on Kerberos authentication telemetry collected from a lab-based Active Directory environment and is designed to highlight suspicious use of valid credentials without relying on failed logon activity.

---

## 🎯 Objective

The objective of this detection is to identify impossible or highly unlikely authentication patterns where valid credentials are used from multiple locations in rapid succession. This behaviour may indicate credential theft, token reuse, or session hijacking.

---

## ⚙️ Environment Preparation

To generate Kerberos authentication telemetry from a non-Windows host, Kerberos client utilities were installed and configured on Kali Linux.

### Kerberos Client Installation (Kali)

```bash
sudo apt update
sudo apt install -y krb5-user
```

During installation:

- The default Kerberos realm was set to the Active Directory domain in **uppercase**
- The Kerberos server was configured as the Domain Controller hostname

### Hostname Resolution

Kerberos requires reliable name resolution to contact the Key Distribution Center (KDC).

In this lab environment, Kali did not resolve the Domain Controller hostname through DNS, so `/etc/hosts` was updated manually:

```text
192.168.10.7  ADDC01 ADPROJECT.LOCAL
```

This step was required so `kinit` could successfully contact the Kerberos KDC.

---

## 🔍 Detection Workflow

This detection was developed using a structured SOC tuning approach:

1. Generate Kerberos authentication from multiple source systems
2. Inspect and normalize Kerberos authentication events
3. Correlate successful authentications across a short time window
4. Identify impossible travel patterns

---

## Step 1 – Kerberos Authentication Baseline

Kerberos authentication was generated from both a Windows host and a Kali Linux host using valid domain credentials.

```spl
index=identity sourcetype="WinEventLog:SecurityAll"
("<EventID>4768</EventID>" OR "<EventID>4769</EventID>")
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| table _time EventID TargetUserName IpAddress
| sort _time
```

<img width="1885" height="619" alt="Kerberos authentication activity - multiple source IPs" src="https://github.com/user-attachments/assets/4b358f9d-bb0b-4c11-b4f6-76d4fdcc4c5d" />

**Figure 1 – Kerberos Authentication Activity – Multiple Source IPs**  
Baseline view showing Kerberos authentication events for the same user originating from different source IP addresses.

---

## Step 2 – Normalized Kerberos Authentication Events

Before correlation, Kerberos authentication events were normalized to support reliable detection logic.

```spl
index=identity sourcetype="WinEventLog:SecurityAll"
("<EventID>4768</EventID>" OR "<EventID>4769</EventID>")
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| eval user=lower(replace(TargetUserName,"@.*",""))
| eval ip=replace(IpAddress,"::ffff:","")
| search NOT ip="127.0.0.1"
| search NOT ip="::1"
| search NOT ip="fe80:*"
| table _time user EventID ip
| sort _time
```

<img width="1868" height="812" alt="Normalized Kerberos authentication events - multiple sources" src="https://github.com/user-attachments/assets/cf76e0c9-3519-4a2f-9f9b-3061aae35193" />

**Figure 2 – Kerberos Authentication Activity by User and Source IP**  
Kerberos authentication events normalized to user and source IP. Localhost and link-local addresses were excluded to focus on meaningful network-based authentication activity before correlation.

---

## Step 3 – Impossible Travel Detection Logic

The final detection identifies users authenticating from multiple distinct IP addresses within a 30-minute window.

```spl
index=identity sourcetype="WinEventLog:SecurityAll"
("<EventID>4768</EventID>" OR "<EventID>4769</EventID>")
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| eval user=lower(replace(TargetUserName,"@.*",""))
| eval ip=replace(IpAddress,"::ffff:","")
| search NOT ip="127.0.0.1"
| search NOT ip="::1"
| search NOT ip="fe80:*"
| bin _time span=30m
| stats dc(ip) as unique_ips values(ip) as ip_list by _time user
| where unique_ips >= 2
| sort -unique_ips
```

<img width="1877" height="514" alt="Impossible travel authentication detection - Kerberos" src="https://github.com/user-attachments/assets/8d9491e0-3eed-4eb0-932c-00843927e68d" />

**Figure 3 – Impossible Travel Authentication Detection – Kerberos**  
Correlation identifying a single user authenticating from multiple distinct source IP addresses within a short time window, indicative of possible credential misuse.

---

## ⚠️ False Positive Considerations

The following scenarios may generate false positives and should be considered during investigation:

- VPN reconnects or split-tunnel configurations
- Jump hosts or bastion systems used for administration
- Dual-homed systems with multiple network interfaces
- Credential validation or health-check tooling
- Lab or testing environments with overlapping sessions

Analysts should validate source IP ownership, authentication timing, and user context before escalation.

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| TA0006 | Credential Access | Adversaries attempt to obtain or abuse valid credentials. |
| T1078 | Valid Accounts | Use of legitimate credentials for unauthorized access. |
| T1550 | Use of Stolen Credentials | Abuse of authentication material without password guessing. |

---

## 📝 Summary

This detection identifies users who authenticate successfully from multiple distinct source IP addresses within a short time window using Kerberos telemetry.

By normalizing Event IDs 4768 and 4769 and correlating successful authentication activity across multiple systems, the detection helps surface higher-confidence signs of credential misuse that may otherwise avoid failed-logon-based analytics.
