# 🥩 Kerberoasting Detection – Weak Kerberos Ticket Encryption

## Objective

The objective of this detection is to identify **Kerberoasting risk conditions** by alerting when a Kerberos **service ticket (Event ID 4769)** is issued using **weak or unexpected encryption**.

In a hardened domain enforcing **AES-only Kerberos encryption**, any non-AES service ticket is treated as a **high-confidence regression indicator** that may enable offline credential cracking of service account tickets.

---

## Detection Background

Kerberoasting is a credential access technique where an attacker requests Kerberos service tickets for service accounts and cracks them offline. The feasibility of this attack increases when service tickets are issued using weaker encryption types (for example RC4).

This detection focuses on **visibility and regression control**:
- Validate the environment is issuing **AES256 service tickets (0x12)**
- Filter out normal Kerberos noise (computer accounts and `krbtgt`)
- Alert only when a ticket is issued using **non-AES encryption** (excluding logging edge cases such as `0xffffffff`)

---

## Step 1 – Kerberos Service Ticket Encryption Baseline

The first step is to baseline Kerberos service ticket encryption types observed in the environment.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| rex field=_raw "(?i)<Data\s+Name='TicketEncryptionType'>(?<EncryptionType>[^<]+)<"
| stats count by ServiceName EncryptionType
| sort -count
```

<img width="986" height="421" alt="Kerberos Service Ticket Encryption Baseline" src="https://github.com/user-attachments/assets/863e4f40-5dbd-47eb-9243-1b21313e6bf5" />

**Figure 1 – Kerberos Service Ticket Encryption Baseline**  
Baseline Kerberos service ticket activity showing only AES256 ticket encryption (`0x12`) for core domain services.

---

## Step 2 – Kerberoast-Relevant Service Ticket Baseline

Kerberoasting targets **user-based service accounts**, not computer accounts. Computer accounts typically end with a `$`, and `krbtgt` is excluded as it is not a roastable service target.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| rex field=_raw "(?i)<Data\s+Name='TicketEncryptionType'>(?<EncryptionType>[^<]+)<"
| search NOT ServiceName="*$"
| search NOT ServiceName="krbtgt"
| stats count by ServiceName EncryptionType
| sort -count
```

<img width="980" height="398" alt="Kerberoast-Relevant Service Ticket Baseline" src="https://github.com/user-attachments/assets/92b54169-2694-4d0d-9310-e06814aecde6" />

**Figure 2 – Kerberoast-Relevant Service Ticket Baseline (Clean State)**  
Kerberos service ticket requests filtered to exclude computer accounts and `krbtgt`, showing no Kerberoast-relevant activity in the environment during the baseline window.

---

## Step 3 – Detection Logic: Non-AES Kerberos Service Tickets

This detection alerts when Kerberos service tickets are issued using **non-AES encryption** in Kerberoast-relevant contexts.

Notes:
- `0x12` represents AES256 tickets and is expected in this environment.
- `0xffffffff` can appear in Kerberos telemetry as an edge-case value where the encryption type is not explicitly logged. It is excluded to reduce noise.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| rex field=_raw "(?i)<Data\s+Name='TicketEncryptionType'>(?<EncryptionType>[^<]+)<"
| search NOT ServiceName="*$"
| search NOT ServiceName="krbtgt"
| where EncryptionType!="0x12" AND EncryptionType!="0xffffffff"
| stats count as ticket_count values(EncryptionType) as encryption_types by ServiceName
| sort -ticket_count
```

<img width="984" height="418" alt="Kerberoasting Detection Results - Non-AES Tickets" src="https://github.com/user-attachments/assets/1ce0d13d-f51a-4f68-8b01-5263da4cf640" />

**Figure 3 – Kerberoasting Detection Results (Non-AES Tickets)**  
Detection query returned no results, confirming no non-AES Kerberos service tickets were issued in Kerberoast-relevant contexts during the baseline period.

---

## False Positive Considerations

Legitimate reasons non-AES service tickets may appear include:
- Legacy systems or services that still require RC4 or older Kerberos settings
- Service account misconfiguration after migrations or domain functional level changes
- Temporary configuration drift during troubleshooting

Before escalation, validate:
- Whether the service is approved and documented
- Whether a change request exists for Kerberos or service account settings
- Whether the source hosts requesting tickets align with expected service usage

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1558.003 | Kerberoasting | Extracting Kerberos service tickets for offline password cracking |
| TA0006 | Credential Access | Attempts to obtain or reuse credentials |

---

## Summary

This detection provides a high-signal control for Kerberoasting risk by alerting only when Kerberos service tickets are issued using **non-AES encryption** in contexts relevant to service accounts.

In an AES-hardened domain, this becomes an effective regression detector that identifies configuration drift or suspicious ticket issuance that could enable offline cracking of service account tickets.
