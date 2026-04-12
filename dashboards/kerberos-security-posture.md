# 📊 Kerberos Security Posture Dashboard

## 🎯 Objective

The Kerberos Security Posture dashboard provides continuous visibility into Kerberos authentication activity, ticket encryption strength, and Kerberoasting exposure within the Active Directory domain.

Its purpose is to help analysts confirm that Kerberos remains securely configured, detect encryption regressions early, and review service account exposure through live authentication telemetry.

---

## Dashboard Scope

This dashboard focuses on **Kerberos service ticket activity** and uses Windows Security **Event ID 4769** to assess:

- Kerberos service ticket volume and usage patterns
- Encryption types used for issued service tickets
- Presence of Kerberoast-relevant service accounts
- Detection of weak or legacy Kerberos encryption

All data is sourced from Domain Controller security logs ingested into Splunk.

---

## Panel 1 – Kerberos Service Ticket Volume Over Time

**Purpose:** Establish a baseline of Kerberos service ticket activity and identify abnormal spikes or drops in ticket issuance.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| timechart span=1h count
```

<img width="974" height="336" alt="Kerberos service ticket volume over time" src="https://github.com/user-attachments/assets/17f69b68-0453-436d-a8a3-6e193249df93" />

**Figure 1 – Kerberos Service Ticket Volume Over Time**  
Shows the overall volume of Kerberos service ticket requests across time to support baseline monitoring and anomaly review.

---

## Panel 2 – Kerberos Ticket Encryption Types

**Purpose:** Validate that Kerberos tickets are being issued using strong encryption algorithms.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='TicketEncryptionType'>(?<EncryptionType>[^<]+)<"
| stats count by EncryptionType
| sort -count
```

<img width="970" height="297" alt="Kerberos ticket encryption types distribution" src="https://github.com/user-attachments/assets/9f9d02b9-f1ae-4047-bb61-3eb52404c367" />

**Figure 2 – Kerberos Ticket Encryption Types Distribution**  
Shows which encryption types are present in issued service tickets and helps verify that AES-based encryption remains the standard.

---

## Panel 3 – Kerberoast-Relevant Service Tickets

**Purpose:** Identify Kerberos service tickets associated with user-based service accounts.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| search NOT ServiceName="*$"
| search NOT ServiceName="krbtgt"
| stats count by ServiceName
| sort -count
```

<img width="968" height="296" alt="Kerberoast-relevant service tickets" src="https://github.com/user-attachments/assets/afd27b32-b4d0-4cdc-8885-0064a418d035" />

**Figure 3 – Kerberoast-Relevant Service Tickets**  
Highlights service tickets linked to user-based service accounts, which are more relevant to Kerberoasting exposure than computer accounts or `krbtgt`.

---

## Panel 4 – Non-AES Kerberos Service Tickets (Critical)

**Purpose:** Detect Kerberos service tickets issued using weak or legacy encryption.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| rex field=_raw "(?i)<Data\s+Name='TicketEncryptionType'>(?<EncryptionType>[^<]+)<"
| search NOT ServiceName="*$"
| search NOT ServiceName="krbtgt"
| where EncryptionType!="0x12" AND EncryptionType!="0xffffffff"
| stats count as ticket_count by ServiceName
```

<img width="965" height="157" alt="Non-AES Kerberos service tickets" src="https://github.com/user-attachments/assets/26175a6e-d15b-4b9b-b1f5-58e8fdeb015d" />

**Figure 4 – Non-AES Kerberos Service Tickets**  
Any non-zero result in this panel represents a high-severity condition that may indicate encryption regression, legacy configuration, or increased Kerberoasting exposure.

---

## Panel 5 – Top Kerberos Service Ticket Requesters

**Purpose:** Provide visibility into the most frequently requested Kerberos services.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| stats count by ServiceName
| sort -count
| head 10
```

<img width="967" height="294" alt="Top Kerberos service ticket requesters" src="https://github.com/user-attachments/assets/8beab1ed-f166-4719-b36a-aacf3c3b9c44" />

**Figure 5 – Top Kerberos Service Ticket Requesters**  
Shows which services receive the most Kerberos service ticket requests and helps analysts understand normal service usage during triage or posture review.

---

## Analyst Usage

SOC analysts should use this dashboard as a **continuous Kerberos health and risk monitoring view**.

Recommended usage:

- **Daily review:**  
  Confirm that Kerberos ticket volume and encryption posture remain consistent with the established baseline.

- **Encryption validation:**  
  Verify that Panel 2 shows only AES-based encryption types such as `0x12`, and that no weak or unexpected encryption types appear.

- **Exposure assessment:**  
  Review Panel 3 to identify user-based service accounts requesting Kerberos tickets that may warrant further hardening or investigation.

- **Incident response trigger:**  
  Treat any non-zero result in **Panel 4 – Non-AES Kerberos Service Tickets** as a high-severity condition requiring immediate investigation.

- **Triage support:**  
  Use Panel 5 to identify which services are most active during investigations or post-alert review.

This dashboard supports both **proactive posture monitoring** and **reactive incident triage** for Kerberos-related threats.

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1558.003 | Kerberoasting | Kerberos service ticket cracking |
| TA0006 | Credential Access | Credential abuse |

---

## 📝 Summary

This dashboard provides continuous visibility into Kerberos ticket activity, encryption strength, and service account exposure within the Active Directory environment.

It supports ongoing validation of Kerberos hardening, helps identify weak encryption regressions quickly, and gives analysts a practical view for monitoring Kerberoasting exposure through live authentication telemetry.
