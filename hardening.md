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

## 🔍 LAPS Event Logging

Location:

```
Event Viewer → Applications and Services Logs  
→ Microsoft → Windows → LAPS → Operational
```

Key events:

- **10018** – Password successfully backed up   
- **10055** – Encryption issues

<img width="676" height="751" alt="image" src="https://github.com/user-attachments/assets/680f2787-5f1c-48d6-a6c0-4348206ec071" />

**Figure 5 - LAPS Operational Log (Events 10018 & 10055):**
LAPS successfully logs EventID 10018 (password backup) and 10055 (encrypted password storage). Other event IDs such as 10019 (password rotation) will only appear once the configured password expiration timestamp has passed or when a manual rotation is forced.

Alternate events:
- **10019** – Password rotation  
- **10033** – Policy validation 

**Event 10019** - This event logs only under certain OS builds or when LAPS detects a policy inconsistency.
A healthy system with valid configuration may never generate EventID 10033.

**Event 10055 - This event logs only under certain OS builds or when LAPS detects a policy inconsistency.
A healthy system with valid configuration may never generate EventID 10033.

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

LAPS is now fully deployed:

- ✔ Installed on clients and DC  
- ✔ AD schema extended  
- ✔ GPO configured  
- ✔ Permissions granted  
- ✔ Password rotation working  
- ✔ Verified via ADUC, PowerShell, and Event Viewer  

LAPS is now a core hardening control in the Identity Security project.
