# 🔐 Windows LAPS Deployment & Hardening

Windows Local Administrator Password Solution (LAPS) was deployed and configured to strengthen identity security within the Active Directory lab environment.

This control ensures that **each Windows machine receives a unique, automatically rotated local administrator password**, which reduces the risk of lateral movement and credential reuse.

---

## 🎯 Objective

The objective of this hardening activity is to deploy and validate Windows LAPS so that local administrator passwords are unique per device, securely stored in Active Directory, and rotated automatically.

This page focuses on applying the control, confirming that it functions correctly, and showing its security value in the wider Identity Security Project.

---

## 📝 Why LAPS Matters

Without LAPS, organisations often reuse the same local administrator password across multiple systems. If an attacker compromises one workstation, they may be able to reuse those credentials across other systems.

LAPS reduces this risk by providing:

- Unique per-device administrator passwords
- Automatic password rotation
- Secure Active Directory-backed password storage
- Fine-grained access control
- Auditable password management activity

---

## Step 1 – Install Windows LAPS

### Domain Controller (Windows Server 2022)

```powershell
Import-Module LAPS
```

### Windows 11 Client (`TARGET-PC`)

```powershell
Add-WindowsCapability -Online -Name Windows.LAPS~~~~0.0.1.0
```

### Verification

```powershell
Get-WindowsCapability -Online | Where-Object {$_.Name -like "*LAPS*"}
```

---

## Step 2 – Configure the LAPS Group Policy

Path:

```text
Group Policy Management
→ Default Domain Policy
→ Computer Configuration
→ Administrative Templates
→ System
→ LAPS
```

Enabled settings:

- **Configure password backup directory** → `Active Directory`
- **Password settings** → `Enabled`
- **Do not allow password expiration longer than required** → `Enabled`
- **Enable password encryption** → `Enabled`

<img width="1147" height="334" alt="LAPS Group Policy configuration" src="https://github.com/user-attachments/assets/d8623067-1609-473b-a07b-7117dbdc0e2c" />

**Figure 1 – LAPS Group Policy Configuration**  
Password backup, rotation settings, and encryption configured in the Default Domain Policy.

The lab uses a password age of **30 days**, which means each client automatically rotates its local administrator password every 30 days unless manually forced earlier.

No manual schema extension was required because Windows Server 2022 includes support for modern Windows LAPS.

---

## Step 3 – Delegate Active Directory Permissions

The following command grants computer objects permission to update their own LAPS password attributes in Active Directory:

```powershell
Set-LapsADComputerSelfPermission -Identity "DC=ADPROJECT,DC=local"
```

<img width="747" height="82" alt="LAPS AD permission delegation" src="https://github.com/user-attachments/assets/c276db41-6cd3-451e-aa76-c0432f466806" />

**Figure 2 – Active Directory Permission Delegation**  
Computer objects in the domain are granted permission to update their own LAPS password attributes.

---

## Step 4 – Apply the LAPS Policy on the Client

```powershell
gpupdate /force
Invoke-LapsPolicyProcessing -Verbose
```

<img width="530" height="353" alt="LAPS policy processing on TARGET-PC" src="https://github.com/user-attachments/assets/3840fe0e-67df-42a8-becd-0308ae3be885" />

**Figure 3 – LAPS Policy Processing**  
`TARGET-PC` successfully processes the LAPS policy and writes its password attributes to Active Directory.

Successful output confirms that policy application and AD write permissions are working correctly.

---

## Step 5 – Verify Password Storage in Active Directory

To retrieve the stored LAPS password, authorised administrators can use:

```powershell
Get-LapsADPassword -Identity "TARGET-PC" -AsPlainText
```

Expected output:

```text
ComputerName  Password     ExpirationTimestamp
-----------   --------     -------------------
TARGET-PC     Xy3$...      2026-01-05 12:28:10
```

<img width="451" height="303" alt="LAPS password retrieval in PowerShell" src="https://github.com/user-attachments/assets/abd59935-438e-43a4-a7cf-8885fd164a54" />

**Figure 4 – LAPS Password Retrieval in PowerShell**  
The rotated password and its expiration timestamp are securely stored in Active Directory.

---

## 🔍 LAPS Event Logging

LAPS operational events can be reviewed in Event Viewer at:

```text
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ LAPS
→ Operational
```

### Event IDs Observed in This Lab

| Event ID | Meaning |
|---|---|
| 10018 | Password successfully backed up to Active Directory |
| 10055 | Encrypted password attributes processed |

### Additional Possible Events

| Event ID | Meaning |
|---|---|
| 10019 | Password rotation event |
| 10033 | LAPS policy validation |

The absence of Event IDs **10019** and **10033** is normal unless password expiration has passed, rotation is forced, or a policy issue exists.

<img width="676" height="751" alt="LAPS operational log events" src="https://github.com/user-attachments/assets/680f2787-5f1c-48d6-a6c0-4348206ec071" />

**Figure 5 – LAPS Operational Log (Events 10018 and 10055)**  
LAPS successfully logs password backup and encrypted password attribute processing. Rotation events appear only when password expiry is reached or a manual rotation is triggered.

---

## 🔧 Least Privilege Hardening

By default, highly privileged groups can read LAPS passwords. A better approach is to restrict access to a dedicated group.

```powershell
Set-LapsADPasswordReadPermission `
 -Identity "OU=Workstations,DC=ADPROJECT,DC=local" `
 -AllowedPrincipals "LAPS-ReadAdmins"
```

This applies **least privilege** by limiting which administrators can retrieve local administrator passwords.

---

## 🧰 Troubleshooting Summary

| Issue | Cause | Solution |
|---|---|---|
| RPC error `0x80070032` | Missing AD permissions | Run `Set-LapsADComputerSelfPermission` |
| No password written to AD | GPO not applied | Run `gpupdate /force` and verify policy application |
| LAPS cmdlets missing | Module not imported | Run `Import-Module LAPS` |
| No rotation events | Password not expired | Wait for expiration or force rotation |

---

## 🛡️ Security Impact

LAPS strengthens identity security by:

- Preventing lateral movement through shared local administrator passwords
- Reducing the value of stolen local credentials
- Supporting least privilege and Zero Trust principles
- Providing secure and auditable password retrieval

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | LAPS Benefit |
|---|---|---|
| T1078 | Valid Accounts | Unique local passwords prevent reuse across hosts |
| T1021 | Remote Services | Limits pivoting through SMB, WMI, or RDP with shared credentials |
| T1555 | Credentials from Password Stores | Retrieved local passwords are less useful across the environment |
| T1556 | Modify Authentication Process | Automatic rotation reduces the value of compromised credentials |

---

## 📝 Summary

This hardening activity demonstrates that Windows LAPS was successfully deployed and validated in the Active Directory lab.

The control was installed, configured through Group Policy, delegated correctly in Active Directory, applied on the client, and verified through password retrieval and operational event logging. As a result, local administrator passwords are now unique, centrally managed, and significantly less useful for lateral movement or credential reuse.
