# 🔐 NTLM Password Spray Detection

Following the Kerberos authentication test, a second identity-focused attack was simulated, this time targeting **NTLM authentication**.  
This scenario demonstrates Splunk’s ability to detect credential-guessing attacks across both major Windows authentication protocols used in Active Directory.

While Kerberos failures generate **4768/4771**, NTLM authentication failures generate **EventID 4625**, which can reveal broad password spraying attempts across multiple identities.

---

## **Objective**

To execute and detect an NTLM password spray attack using **CrackMapExec (CME)** from the attacker machine (192.168.10.250), and verify that Splunk can ingest and analyze the resulting Windows Security events.

This demonstrates identity-focused detection coverage across NTLM authentication pathways.

---

## **Attack Execution (Kali Linux)**

A single-password spray was performed against several Active Directory accounts using CrackMapExec over SMB:

```bash
crackmapexec smb 192.168.10.7 \
  -d ADProject.local \
  -u /tmp/ad_users.txt \
  -p Winter2025!
```

<img width="1277" height="149" alt="NTLM-spray-CME" src="https://github.com/user-attachments/assets/338cf322-08ea-425c-979a-72ce1aa9cb6e" />

### **Figure 3 – CrackMapExec NTLM Password Spray Output**

CrackMapExec attempted authentication against six domain users using a single password (`Winter2025!`) and returned **STATUS_LOGON_FAILURE** for each of them:

- **JNeutron**  
- **JBravo**  
- **SCheeks**  
- **PStar**  
- **HMontana**  
- **VDinkley**

All failures originated from **192.168.10.250**, consistent with a classic NTLM password spray.

---

## **Log Ingestion Adjustment**

Because the default Security sourcetype was filtering certain events, the Domain Controller’s Universal Forwarder was updated to ensure all Security events were forwarded to Splunk:

```ini
[WinEventLog://Security]
disabled = 0
renderXml = true
sourcetype = WinEventLog:SecurityAll
index = identity
```

This custom sourcetype reliably forwarded **EventID 4625** for NTLM logon failures.

---

## **Extracting NTLM Failures From XML**

Since Security logs were ingested in XML format (`renderXml = true`), custom extraction was required to pull out the username and source IP from `<Data>` fields.

The SPL below extracts:

- EventID  
- TargetUserName  
- IpAddress  

```spl
index=identity sourcetype="WinEventLog:SecurityAll" earliest=-15m
| rex field=_raw "EventID>(?<EventID>\d+)<"
| search EventID=4625
| rex field=_raw "Data Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| table _time, EventID, TargetUserName, IpAddress
| sort -_time
```

<img width="1885" height="545" alt="image" src="https://github.com/user-attachments/assets/d443b42d-060e-48dd-abdd-d580dcf062e4" />

### **Figure 4 – Extracted NTLM Authentication Failures**

This output confirms:

- Six unique domain accounts failed authentication  
- All failures originated from **192.168.10.250**  
- All produced **EventID 4625**  
- All occurred within the same second, a strong indication of a spray attempt  

---

## 🔍 **NTLM Password Spray Detection Logic**

To detect NTLM password spray activity, a correlation rule was built to identify:

- Multiple authentication failures  
- From the same source IP  
- Targeting multiple distinct accounts  
- Inside a short time window  

```spl
index=identity sourcetype="WinEventLog:SecurityAll" earliest=-15m
| rex field=_raw "EventID>(?<EventID>\d+)<"
| search EventID=4625
| rex field=_raw "Data Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| bucket _time span=5m
| stats dc(TargetUserName) as unique_accounts count by IpAddress, _time
| where unique_accounts >= 3
| sort -_time
```

If an attacker fails to authenticate against three or more distinct accounts within five minutes, this SPL flags the activity as a password spray.

---

## **MITRE ATT&CK Mapping**

| Technique ID | Name | Description |
|--------------|------|-------------|
| **T1110.003** | Password Spraying | Testing a single password across many accounts |
| **T1078** | Valid Accounts | Potential follow-on if credentials are obtained |
| **TA0006** | Credential Access | Attempting to guess valid passwords |

---

## **Summary**

This NTLM attack validates Splunk’s ability to detect identity-focused threats across multiple authentication protocols:

- **CrackMapExec** performed a real-world NTLM password spray  
- **EventID 4625** failures were ingested via a custom Security sourcetype  
- **Regex extraction** parsed usernames and IPs from XML logs  
- A **behaviour based correlation detection** identified the spray  
- Together with the Kerberos test, this provides complete authentication-layer visibility  

This scenario reinforces the importance of SIEM-driven identity security monitoring and shows how Active Directory authentication activity can be analyzed to detect adversarial behaviour.

## 🔍 Detection Summary Table

This table compares the two identity-based attacks executed in the lab and summarizes how each was detected within Splunk.

| **Detection Type** | **Authentication Protocol** | **Event IDs Observed** | **Attack Tool** | **Target Accounts** | **Splunk Detection Logic** | **What It Reveals** |
|--------------------|-----------------------------|--------------------------|------------------|-----------------------|-----------------------------|-----------------------|
| **Kerberos Password Spray** | Kerberos | 4768, 4771 | Kerbrute | Single-user spray (`JNeutron`) | Regex-assisted extraction of Kerberos AS-REQ failures from Security XML | TGT requests with incorrect passwords, evidence of Kerberos authentication probing |
| **NTLM Password Spray** | NTLM | 4625 | CrackMapExec | Multi-user spray (`6 accounts`) | Correlation search counting distinct usernames per source IP within 5 minutes | Broad authentication failures across multiple accounts, evidence of automated NTLM spraying |

---

## ⭐ Key Takeaways

- **Identity-layer attacks are noisy when monitored correctly.**
  Even simple password spray attempts generate rich authentication telemetry across Kerberos and NTLM.

- **Kerberos and NTLM behave differently in logs.**
  Kerberos relies on AS-REQ failures (4768/4771), while NTLM produces failed logons (4625). Both require different SPL extraction techniques.

- **XML-formatted Security logs require custom field extraction.**
  Using `renderXml = true` improves fidelity but requires regex for fields like `TargetUserName` and `IpAddress`.

- **Detection relies on correlation, not single events.**
  Password sprays only become obvious when counting distinct usernames targeted within a time window.

- **Splunk Universal Forwarder configuration matters.**
  A custom sourcetype (`WinEventLog:SecurityAll`) ensured that no Security events were filtered out.

- **Realistic adversary emulation strengthens detection engineering.**
  Using Kerbrute and CrackMapExec mirrors real attacker behaviour and validates detection logic under real-world conditions.

- **This lab demonstrates full identity-attack visibility.**
  Both Kerberos and NTLM pathways were monitored, ingested, extracted, and correlated inside Splunk.

---

## ⏱ Alert Scheduling & Detection Latency

The NTLM password spray detection was implemented as a **scheduled Splunk correlation alert** rather than a real-time alert.

### Correlation Alert Configuration
- **Schedule:** Every 5 minutes (`*/5 * * * *`)
- **Time Range:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Trigger Mode:** Once per execution

<img width="752" height="656" alt="Splunk NTLM Password Spray Alert" src="https://github.com/user-attachments/assets/73d0932c-1973-4875-8acc-31c14d7df731" />

**Figure 5 – NTLM Password Spray Alert Configuration**  
Scheduled correlation alert configured to detect NTLM password spraying by correlating multiple authentication failures within a five-minute window.

Because Splunk evaluates scheduled alerts only at their defined interval, the NTLM password spray activity was detected on the **next scheduled execution** rather than immediately after the attack occurred.

This behaviour reflects real-world SOC operations, where authentication-based detections are evaluated over defined time windows to enable correlation, reduce noise, and improve alert fidelity.

### Operational Impact
- Short-lived password spray activity may complete within seconds
- Detection occurs when the correlation window is evaluated
- This delay is expected and acceptable in SOC environments
- Proper time-window alignment ensures reliable detection without duplicate alerts

---

<img width="1381" height="357" alt="Splunk NTLM Alert Trigger" src="https://github.com/user-attachments/assets/972c1708-045d-4215-8510-ee7ecaeece74" />

**Figure 6 – NTLM Password Spray Correlation Alert Triggered**  
The scheduled Splunk alert fired after evaluating authentication failures originating from a single source IP.

Upon triggering, the alert returned correlated results identifying the source IP and number of targeted accounts responsible for the password spray.

<img width="1897" height="433" alt="Splunk SPL NTLM Alert" src="https://github.com/user-attachments/assets/819e8066-04f8-42ca-8ade-b6c4e4925061" />

**Figure 7 – NTLM Password Spray Correlation Alert Results**  
The scheduled Splunk correlation alert successfully returned results confirming NTLM authentication failures across multiple domain accounts from a single source IP within the defined detection window.
