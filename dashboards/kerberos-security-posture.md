# 📊 Kerberos Security Posture Dashboard

## Objective

The Kerberos Security Posture dashboard provides continuous visibility into Kerberos authentication activity, ticket encryption strength, and Kerberoasting exposure within the Active Directory domain.

This dashboard is designed to validate Kerberos hardening controls, detect configuration regressions, and support SOC analysts in identifying high-risk Kerberos behavior before credential compromise occurs.

---

## Dashboard Scope

This dashboard focuses on **Kerberos service ticket activity** and leverages Windows Security Event ID **4769** to assess:

- Kerberos service ticket volume and usage patterns
- Encryption types used for issued service tickets
- Presence of Kerberoastable service accounts
- Detection of weak or legacy Kerberos encryption

All data is sourced from Domain Controller security logs ingested into Splunk.

---

## Panel 1 – Kerberos Service Ticket Volume Over Time

**Purpose:**  
Establish a baseline of Kerberos service ticket activity and identify abnormal spikes or drops in ticket issuance.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| timechart span=1h count
```

<img width="974" height="336" alt="Kerberos Ticket Volume Over Time" src="https://github.com/user-attachments/assets/17f69b68-0453-436d-a8a3-6e193249df93" />

**Figure 1 – Kerberos Service Ticket Volume Over Time**  

---

## Panel 2 – Kerberos Ticket Encryption Types

**Purpose:**  
Validate that Kerberos tickets are being issued using strong encryption algorithms.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='TicketEncryptionType'>(?<EncryptionType>[^<]+)<"
| stats count by EncryptionType
| sort -count
```

<img width="970" height="297" alt="Kerberos Ticket Encryption Types" src="https://github.com/user-attachments/assets/9f9d02b9-f1ae-4047-bb61-3eb52404c367" />

**Figure 2 – Kerberos Ticket Encryption Types Distribution**  

---

## Panel 3 – Kerberoast-Relevant Service Tickets

**Purpose:**  
Identify Kerberos service tickets associated with user-based service accounts.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| search NOT ServiceName="*$"
| search NOT ServiceName="krbtgt"
| stats count by ServiceName
| sort -count
```

<img width="968" height="296" alt="Kerberoast-Relevant Service Tickets" src="https://github.com/user-attachments/assets/afd27b32-b4d0-4cdc-8885-0064a418d035" />

**Figure 3 – Kerberoast-Relevant Service Tickets**  

---

## Panel 4 – Non-AES Kerberos Service Tickets (Critical)

**Purpose:**  
Detect Kerberos service tickets issued using weak or legacy encryption.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| rex field=_raw "(?i)<Data\s+Name='TicketEncryptionType'>(?<EncryptionType>[^<]+)<"
| search NOT ServiceName="*$"
| search NOT ServiceName="krbtgt"
| where EncryptionType!="0x12" AND EncryptionType!="0xffffffff"
| stats count as ticket_count by ServiceName
```

<img width="965" height="157" alt="Non-AES Kerberos Service Tickets" src="https://github.com/user-attachments/assets/26175a6e-d15b-4b9b-b1f5-58e8fdeb015d" />

**Figure 4 – Non-AES Kerberos Service Tickets**  

---

## Panel 5 – Top Kerberos Service Ticket Requesters

**Purpose:**  
Provide visibility into the most frequently requested Kerberos services.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| stats count by ServiceName
| sort -count
| head 10
```

<img width="967" height="294" alt="Top Services Requesting Tickets" src="https://github.com/user-attachments/assets/8beab1ed-f166-4719-b36a-aacf3c3b9c44" />

**Figure 5 – Top Kerberos Service Ticket Requesters**  

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1558.003 | Kerberoasting | Kerberos service ticket cracking |
| TA0006 | Credential Access | Credential abuse |

---

## Summary

This dashboard provides continuous assurance that Kerberos authentication remains securely configured and resistant to Kerberoasting attacks.

