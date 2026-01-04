# 🔐 SOC Playbook – Kerberos Password Spray Detection

## 📌 Overview
This SOC playbook defines the **detection, triage, investigation, and response workflow** for a **Kerberos password spray attack** detected within an Active Directory environment.

The detection is based on **Kerberos AS-REQ failures** logged by the Domain Controller and ingested into **Splunk Enterprise**.  
This playbook aligns with **Tier 1 SOC analyst responsibilities** and reflects real-world operational procedures.

---

## 🎯 Detection Trigger

**Alert Name:** Kerberos Password Spray Detected  
**Data Source:** Windows Security Event Logs (Domain Controller)  
**SIEM:** Splunk Enterprise  
**Index:** `identity`

### Relevant Event IDs
- **4768** – Kerberos Authentication Service (TGT request)
- **4771** – Kerberos pre-authentication failed

---

## 🔍 Detection Logic (Splunk SPL)

```spl
index=identity host=ADDC01 earliest=-5m
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4768 OR EventID=4771
| rex field=_raw "Data Name=\"TargetUserName\">(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name=\"IpAddress\">(?<IpAddress>[^<]+)<"
| bucket _time span=5m
| stats count dc(TargetUserName) as unique_users by IpAddress, _time
| where count > 3
```

**Detection Goal:**  
Identify repeated Kerberos authentication failures originating from the same source IP within a short time window.

---

## 🧠 Analyst Triage (Tier 1)

### Initial Validation Checklist
- [ ] Confirm alert source is **Domain Controller**
- [ ] Validate source IP is external or suspicious
- [ ] Identify targeted username(s)
- [ ] Check time clustering of failures
- [ ] Review prior successful logons for affected account(s)

---

## 🔎 Investigation Steps

### 1️⃣ Validate Kerberos Failures
Confirm events in Splunk:
- EventID **4768**
- EventID **4771**
- Source IP matches attacker host
- Target account exists in AD

### 2️⃣ Check Account Status
On Domain Controller:
```powershell
Get-ADUser JNeutron -Properties LockedOut, LastLogonDate
```

### 3️⃣ Identify Scope
- Single-user spray or multi-user attempt
- Repeated attempts across time windows
- Correlate with NTLM alerts if present

---

## 🚨 Response Actions

### Immediate Actions
- [ ] Monitor targeted account for lockout or success
- [ ] Block attacker IP at firewall if external
- [ ] Increase logging verbosity if required

### Containment (If Escalated)
- [ ] Force password reset for targeted account
- [ ] Enable temporary account lockout
- [ ] Disable account if compromise suspected

---

## 🛡️ Prevention & Hardening Recommendations

- Enforce **strong password policies**
- Enable **account lockout thresholds**
- Use **Windows LAPS** to reduce lateral movement risk
- Limit Kerberos exposure via network segmentation
- Monitor AS-REQ failures continuously

---

## 🎯 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1110.003 | Password Spraying | Attempting one password across accounts |
| T1558 | Kerberos Ticket Abuse | Interaction with KDC during authentication |
| TA0006 | Credential Access | Attempt to obtain valid credentials |

---

## 🧾 Documentation & Reporting

### Evidence to Collect
- SPL search results
- Source IP and timestamp
- Targeted usernames
- Screenshot of Splunk detection

### Ticket Fields
- Alert Name
- Severity: **Medium**
- Impacted System: Domain Controller
- Recommendation: Password policy review

---

## ✅ Resolution Criteria
- No further Kerberos failures observed
- Source IP mitigated
- Account security validated
- Incident documented

---

## ⭐ Key Takeaways
- Kerberos attacks are **authentication-layer attacks**
- Detection relies on **correlation, not single events**
- SOC visibility into AS-REQ failures is critical
- Proper logging enables early detection

---

*This playbook complements the NTLM Password Spray Playbook and provides full authentication-layer coverage in the Identity Security project.*
