# 🔐 Kerberos Hardening

## 🎯 Objective

The objective of this hardening activity is to reduce Kerberos-based credential abuse risk by enforcing stronger encryption for service ticket issuance within the Active Directory domain.

This is achieved by identifying insecure service account configurations, observing Kerberos ticket encryption in live authentication traffic, and applying and validating encryption hardening controls. The page builds directly on the detection engineering work in the Identity Security Project and focuses on preventative identity security controls validated through SIEM telemetry.

---

## 🔍 Background

Kerberos is the default authentication protocol used by Active Directory. While it provides strong authentication, misconfigured service accounts and legacy encryption support can expose an environment to:

- Kerberoasting attacks
- Offline password cracking
- Service account compromise
- Lateral movement

This lab establishes a service account baseline and validates Kerberos encryption hardening using live authentication traffic and Windows Security Event logs.

---

## Insecure Baseline – Service Account Creation

A traditional user-based service account was created to simulate a common enterprise misconfiguration.

- **Service Account:** `svc_backup`
- **Account Type:** User-based service account
- **Location:** `CN=Users`
- **Password Management:** Manual
- **SPN Registered:** Yes

The Service Principal Name (SPN) was registered using:

```powershell
setspn -A MSSQLSvc/backupserver.adproject.local svc_backup
```

<img width="399" height="528" alt="Service account properties for svc_backup" src="https://github.com/user-attachments/assets/ee86bb3d-b03b-493a-bc25-763411ee5503" />

**Figure 1 – Insecure Service Account Configuration (`svc_backup`)**  
Screenshot showing the `svc_backup` account configuration in Active Directory Users and Computers, including password settings and account type.

---

## Kerberos Ticket Generation (Attack Simulation)

Kerberos authentication and service ticket requests were generated from a Kali Linux host joined to the domain.

### Prerequisites

- `kinit` installed on Kali Linux
- `/etc/hosts` updated with the Domain Controller entry:

```text
192.168.10.7  ADDC01.adproject.local ADDC01
```

### Kerberos Authentication

```bash
kinit JNeutron@ADPROJECT.LOCAL
```

### Service Ticket Request

```bash
kvno MSSQLSvc/backupserver.adproject.local
```

This generated **Event ID 4769** on the Domain Controller, representing a Kerberos service ticket request for the service account.

<img width="769" height="444" alt="Kerberos service ticket request from Kali" src="https://github.com/user-attachments/assets/213f4a40-774d-46ff-9b52-83c5b0200e85" />

**Figure 2 – Kerberos Service Ticket Request from Kali**  
Screenshot showing successful `kinit`, `kvno`, and `klist` output on the Kali host.

---

## Kerberos Service Ticket Analysis (Baseline)

Kerberos service ticket encryption was analysed in Splunk.

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4769</EventID>"
| rex field=_raw "(?i)<Data\s+Name='ServiceName'>(?<ServiceName>[^<]+)<"
| rex field=_raw "(?i)<Data\s+Name='TicketEncryptionType'>(?<EncryptionType>[^<]+)<"
| search ServiceName="svc_backup"
| stats count by EncryptionType
| sort -count
```

<img width="1895" height="337" alt="Kerberos service ticket encryption baseline for svc_backup" src="https://github.com/user-attachments/assets/ddfc0ce1-751b-4bdf-9069-b518f222093a" />

**Figure 3 – Kerberos Service Ticket Encryption Baseline (`svc_backup`)**  
Baseline view of Kerberos service tickets issued for the `svc_backup` service account before hardening.

---

## Kerberos Policy Review

Kerberos policy settings were reviewed through Group Policy:

```text
Computer Configuration
 → Windows Settings
   → Security Settings
     → Account Policies
       → Kerberos Policy
```

Encryption configuration was also reviewed under:

```text
Network security: Configure encryption types allowed for Kerberos
```

<img width="406" height="496" alt="Kerberos encryption policy configuration before hardening" src="https://github.com/user-attachments/assets/86dc30cb-408c-4c33-94be-bed04259c511" />

**Figure 4 – Kerberos Encryption Policy Configuration (Pre-Hardening)**  
Screenshot showing Kerberos encryption settings before enforcing AES-only encryption.

---

## Kerberos Encryption Hardening

The following Kerberos encryption configuration was enforced to reduce credential exposure risk.

### Allowed Encryption Types

- AES128_HMAC_SHA1
- AES256_HMAC_SHA1

### Disallowed Encryption Types

- DES_CBC_CRC
- DES_CBC_MD5
- RC4_HMAC_MD5

Restricting Kerberos to AES-only encryption reduces the feasibility of RC4-based Kerberoasting attacks.

<img width="407" height="499" alt="Kerberos encryption policy configured for AES only" src="https://github.com/user-attachments/assets/ce088188-33eb-4c02-b607-28a7d324785c" />

**Figure 5 – Kerberos Encryption Policy Configured for AES Only**  
Screenshot showing Group Policy configured to allow only AES encryption types.

---

## Post-Hardening Validation

After applying the encryption restrictions, Kerberos authentication was re-tested from the Kali host using `kinit` and `kvno`.

Splunk analysis confirmed:

- Kerberos service tickets were successfully issued
- Ticket encryption was enforced using AES256
- `TicketEncryptionType = 0x12`

<img width="1897" height="345" alt="Kerberos service ticket encryption after hardening" src="https://github.com/user-attachments/assets/00811827-eb86-4887-b7e9-bb4b9222ca2d" />

**Figure 6 – Kerberos Service Ticket Encryption After Hardening**  
Splunk results confirming AES256 encryption for Kerberos service tickets issued to the `svc_backup` service account.

A small number of events report `TicketEncryptionType = 0xffffffff`, which indicates that the encryption type was not explicitly logged for that ticket request. This is expected for certain Kerberos system and referral tickets and does not represent the use of weak or legacy encryption.

---

## Kerberos Preauthentication Validation

Kerberos preauthentication was also validated to reduce AS-REP roasting exposure.

Enforcing Kerberos preauthentication ensures that attackers cannot request Ticket Granting Tickets without knowing the account password, which prevents AS-REP roasting and forces Kerberos authentication attempts to generate observable security telemetry.

<img width="406" height="531" alt="Kerberos preauthentication enforced on user account" src="https://github.com/user-attachments/assets/9a0ea9a1-9235-4949-b802-482017eacd50" />

**Figure 7 – Kerberos Preauthentication Enforced (User Account)**  
Screenshot confirming that Kerberos preauthentication remains enforced on the reviewed user account.

---

## ⚠️ False Positive Considerations

Kerberos service ticket requests are common in enterprise environments. Legitimate activity that may resemble attack behaviour includes:

- Backup services accessing databases
- Monitoring platforms using service accounts
- Scheduled jobs running under service principals

Kerberos-related alerts should be correlated with known service accounts, request frequency, source host context, and change management records before escalation.

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1558.003 | Kerberoasting | Offline cracking of Kerberos service tickets |
| T1558.004 | AS-REP Roasting | Abuse of accounts without preauthentication |
| TA0006 | Credential Access | Credential abuse |

---

## 📝 Summary

This hardening exercise shows how Kerberos risk can be identified, tested through live authentication activity, and reduced using policy-based controls validated through SIEM telemetry.

By reviewing insecure service account conditions, enforcing AES-only encryption, and confirming preauthentication settings, the lab demonstrates a practical defensive workflow for reducing Kerberos-based credential abuse risk.
