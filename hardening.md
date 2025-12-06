# 🔐 Windows LAPS Deployment & Hardening

Windows Local Administrator Password Solution (LAPS) was deployed and configured to strengthen identity security within the Active Directory lab environment.  
This control ensures that **each Windows machine receives a unique, automatically rotated local administrator password**, reducing the risk of lateral movement and credential reuse by attackers.

---

## 📝 Why LAPS Matters
Without LAPS, organizations often reuse the same local administrator password across multiple systems.  
If an attacker compromises *one* workstation, they automatically gain privileged access to *all* workstations.

LAPS mitigates this risk by ensuring:

- Unique per-device administrator passwords  
- Automatic password rotation  
- Secure AD-backed password storage  
- Fine-grained access control  
- Full auditing capability  

---

## ✅ Step 1 – Install Windows LAPS

### Domain Controller (Windows Server 2022)
```powershell
Import-Module LAPS
```

### Windows 11 Client (TARGET-PC)
```powershell
Add-WindowsCapability -Online -Name Windows.LAPS~~~~0.0.1.0
```

Verify:
```powershell
Get-WindowsCapability -Online | Where-Object {$_.Name -like "*LAPS*"}
```

---

## ✅ Step 2 – Configure LAPS GPO

**Group Policy Management → Default Domain Policy → Computer Configuration → Administrative Templates → System → LAPS**

Enable:

- Configure password backup directory → **Active Directory**
- Password settings → **Enabled**
- Do not allow password expiration longer than required → **Enabled**
- Enable password encryption → **Enabled**

<img width="1147" height="334" alt="image" src="https://github.com/user-attachments/assets/d8623067-1609-473b-a07b-7117dbdc0e2c" />

**Figure 1 – LAPS Group Policy Configuration:** 
Password backup, rotation settings, and encryption configured in the Default Domain Policy.

The lab uses a password age of 30 days, meaning each client will automatically rotate its local administrator password every 30 days unless manually forced earlier.

No manual schema extension was required because Windows Server 2022 includes the modern LAPS schema by default.

---

## ✅ Step 3 – Delegate AD Permissions

Domain-level permission:
```powershell
Set-LapsADComputerSelfPermission -Identity "DC=ADPROJECT,DC=local"
```
<img width="747" height="82" alt="image" src="https://github.com/user-attachments/assets/c276db41-6cd3-451e-aa76-c0432f466806" />

**Figure 2 - AD Permission Delegation:**
Computers in the domain are granted the right to update their own LAPS password attributes.

---

## ✅ Step 4 – Apply LAPS Policy on Client

```powershell
gpupdate /force
Invoke-LapsPolicyProcessing -Verbose
```

<img width="530" height="353" alt="image" src="https://github.com/user-attachments/assets/3840fe0e-67df-42a8-becd-0308ae3be885" />

**Figure 3 - LAPS Policy Processing:**
TARGET-PC successfully processes the LAPS policy and writes its password attributes to AD.

Successful output indicates AD write permissions and policy application.

---

## ✅ Step 5 – Verify Password Storage in AD

Retrieve LAPS password (authorized admins only):

```powershell
Get-LapsADPassword -Identity "TARGET-PC" -AsPlainText
```

Expected:

```
ComputerName  Password     ExpirationTimestamp
-----------   --------     -------------------
TARGET-PC     Xy3$...      2026-01-05 12:28:10
```

<img width="451" height="303" alt="image" src="https://github.com/user-attachments/assets/abd59935-438e-43a4-a7cf-8885fd164a54" />

**Figure 4 – LAPS Password Retrieval in PowerShell:**
The rotated password and its expiration timestamp are securely stored in AD.

---

# 🔍 LAPS Event Logging (Operational Events)

Event Viewer path:

```
Event Viewer → Applications and Services Logs  
→ Microsoft → Windows → LAPS → Operational
```

### Event IDs Observed in This Lab:

| Event ID | Meaning |
|----------|---------|
| **10018** | Password successfully backed up to Active Directory |
| **10055** | Encrypted password attributes processed |

### Additional Possible Events (Not observed in this lab)

| Event ID | Meaning |
|----------|---------|
| **10019** | Password rotation event (only appears when password expiration occurs or rotation is manually forced) |
| **10033** | LAPS policy validation |

**Note:**  
The absence of EventIDs **10019** and **10033** is normal unless password expiration has passed or policy inconsistencies exist.

<img width="676" height="751" alt="image" src="https://github.com/user-attachments/assets/680f2787-5f1c-48d6-a6c0-4348206ec071" />

**Figure 5 - LAPS Operational Log (Events 10018 & 10055):**
LAPS successfully logs EventID 10018 (password backup) and 10055 (encrypted password storage). Other event IDs such as 10019 (password rotation) will only appear once the configured password expiration timestamp has passed or when a manual rotation is forced.

---

# 🔧 Least Privilege Hardening (Recommended)

By default, Domain Admins can read LAPS passwords.  
Best practice is to create a restricted group to limit who can retrieve them:

```powershell
Set-LapsADPasswordReadPermission `
 -Identity "OU=Workstations,DC=ADPROJECT,DC=local" `
 -AllowedPrincipals "LAPS-ReadAdmins"
```

This enforces **least privilege** and prevents unnecessary access to privileged credentials.

---

# 🧰 Troubleshooting Summary

| Issue | Cause | Solution |
|-------|--------|----------|
| RPC error 0x80070032 | Missing AD permissions | Run `Set-LapsADComputerSelfPermission` |
| No password written to AD | GPO not applied | Run `gpupdate /force` and verify GPO |
| LAPS cmdlets missing | Module not imported | `Import-Module LAPS` |
| No rotation events | Password not expired | Wait until expiration or force rotation |

---

# 🛡️ Security Impact

LAPS significantly increases identity security by:

- Preventing lateral movement using shared passwords  
- Blocking credential replay & pass-the-hash  
- Enforcing Zero Trust principles  
- Providing secure, auditable password retrieval  

---

# 🎯 MITRE ATT&CK Mapping

| Technique | Description | LAPS Benefit |
|----------|-------------|--------------|
| **T1078 – Valid Accounts** | Stolen local admin credentials | Unique passwords prevent reuse |
| **T1021 – Remote Services** | Pivoting via SMB/WMI/RDP | Each machine has different credentials |
| **T1555 – Credential Access** | Password/hash extraction | Dumped passwords become useless |
| **T1556 – Credential Abuse** | Reusing compromised creds | LAPS rotates automatically |

---

# 🧩 Final Summary

LAPS is now fully deployed and functioning:

- ✔ Installed on domain controller and clients  
- ✔ GPO configured and applied  
- ✔ AD permissions granted  
- ✔ Local admin passwords securely backed up  
- ✔ Password expiration and rotation working  
- ✔ Events verified in Event Viewer  

LAPS now serves as a core hardening control in the Identity Security project.
