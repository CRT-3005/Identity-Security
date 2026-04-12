# 🔐 NTLM Password Spray Detection

This detection demonstrates how NTLM password spray activity against Active Directory can be identified in Splunk using Windows Security Event Logs.

Following the Kerberos authentication test, a second identity-focused attack was simulated against **NTLM authentication** using **CrackMapExec** from the Kali attacker machine. This validates detection coverage across both major Windows authentication protocols used in Active Directory.

While Kerberos failures commonly generate Event IDs **4768** and **4771**, NTLM authentication failures generate **Event ID 4625**, which can reveal broad password spraying attempts across multiple accounts.

---

## 🎯 Objective

The objective of this detection is to execute and identify an NTLM password spray attack using **CrackMapExec** from the attacker machine (`192.168.10.250`) and verify that Splunk can ingest and analyse the resulting Windows Security events.

This demonstrates identity-focused detection coverage across NTLM authentication pathways.

---

## ⚔️ Attack Execution (Kali Linux)

A single-password spray was performed against several Active Directory accounts using CrackMapExec over SMB.

```bash
crackmapexec smb 192.168.10.7 \
  -d ADProject.local \
  -u /tmp/ad_users.txt \
  -p Winter2025!
```

<img width="1277" height="149" alt="CrackMapExec NTLM password spray output" src="https://github.com/user-attachments/assets/338cf322-08ea-425c-979a-72ce1aa9cb6e" />

**Figure 1 – CrackMapExec NTLM Password Spray Output**  
CrackMapExec attempted authentication against six domain users using a single password (`Winter2025!`) and returned **STATUS_LOGON_FAILURE** for each account.

The activity targeted:

- **JNeutron**
- **JBravo**
- **SCheeks**
- **PStar**
- **HMontana**
- **VDinkley**

All failures originated from **192.168.10.250**, matching the pattern of a classic NTLM password spray.

---

## ⚙️ Log Ingestion Adjustment

Because the default Security sourcetype was filtering certain events, the Domain Controller's Universal Forwarder was updated to ensure all Security events were forwarded to Splunk.

```ini
[WinEventLog://Security]
disabled = 0
renderXml = true
sourcetype = WinEventLog:SecurityAll
index = identity
```

This custom sourcetype reliably forwarded **Event ID 4625** for NTLM logon failures.

---

## 🔍 Detection Workflow

This detection was developed using a structured SOC approach:

1. Generate NTLM authentication failures from a single source system
2. Extract usernames and source IP addresses from XML-formatted Security logs
3. Correlate multiple failures against distinct accounts within a short time window
4. Detect behaviour consistent with password spraying

---

## Step 1 – Extracting NTLM Failures From XML

Because Security logs were ingested in XML format (`renderXml = true`), custom extraction was required to pull the username and source IP from `<Data>` fields.

The SPL below extracts:

- Event ID
- TargetUserName
- IpAddress

```spl
index=identity sourcetype="WinEventLog:SecurityAll" earliest=-15m
| rex field=_raw "EventID>(?<EventID>\d+)<"
| search EventID=4625
| rex field=_raw "Data Name='TargetUserName'>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| table _time EventID TargetUserName IpAddress
| sort -_time
```

<img width="1885" height="545" alt="Extracted NTLM authentication failures" src="https://github.com/user-attachments/assets/d443b42d-060e-48dd-abdd-d580dcf062e4" />

**Figure 2 – Extracted NTLM Authentication Failures**  
The extracted results confirm that six unique domain accounts failed authentication, all from **192.168.10.250**, all with **Event ID 4625**, and all within the same second.

This is a strong indicator of password spray behaviour.

---

## Step 2 – NTLM Password Spray Detection Logic

To detect NTLM password spray activity, a correlation rule was built to identify:

- Multiple authentication failures
- From the same source IP
- Targeting multiple distinct accounts
- Within a short time window

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

If a single source fails authentication against three or more distinct accounts within five minutes, this detection flags the activity as potential password spraying.

---

## ⏱ Alert Scheduling & Detection Latency

The NTLM password spray detection was implemented as a **scheduled Splunk correlation alert** rather than a real-time alert.

### Correlation Alert Configuration

- **Schedule:** Every 5 minutes (`*/5 * * * *`)
- **Time Range:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Trigger Mode:** Once per execution

<img width="752" height="656" alt="Splunk NTLM password spray alert configuration" src="https://github.com/user-attachments/assets/73d0932c-1973-4875-8acc-31c14d7df731" />

**Figure 3 – NTLM Password Spray Alert Configuration**  
Scheduled correlation alert configured to detect NTLM password spraying by correlating multiple authentication failures within a five-minute window.

Because Splunk evaluates scheduled alerts only at the defined interval, the NTLM password spray activity was detected on the next scheduled execution rather than immediately after the attack occurred.

This reflects real SOC operations, where authentication-based detections are often evaluated over defined time windows to support correlation, reduce noise, and improve alert fidelity.

### Operational Impact

- Short-lived password spray activity may complete within seconds
- Detection occurs when the correlation window is evaluated
- This delay is expected and acceptable in SOC environments
- Proper time-window alignment improves reliability and reduces duplicate alerting

<img width="1381" height="357" alt="Splunk NTLM alert trigger" src="https://github.com/user-attachments/assets/972c1708-045d-4215-8510-ee7ecaeece74" />

**Figure 4 – NTLM Password Spray Correlation Alert Triggered**  
The scheduled Splunk alert fired after evaluating authentication failures originating from a single source IP.

Upon triggering, the alert returned correlated results identifying the source IP and the number of targeted accounts involved in the password spray.

<img width="1897" height="433" alt="Splunk NTLM alert results" src="https://github.com/user-attachments/assets/819e8066-04f8-42ca-8ade-b6c4e4925061" />

**Figure 5 – NTLM Password Spray Correlation Alert Results**  
The scheduled Splunk correlation alert returned results confirming NTLM authentication failures across multiple domain accounts from a single source IP within the defined detection window.

---

## ⚠️ False Positive Considerations

The following scenarios may generate similar NTLM authentication failure patterns and should be validated during investigation:

- Administrative scripts or tools testing multiple accounts
- Service validation or application testing using incorrect credentials
- Lab activity involving bulk account authentication checks
- Misconfigured automation repeatedly attempting logons against multiple users

Analysts should validate the source IP, account list, timing, and expected administrative context before escalation.

---

## 🧭 MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1110.003 | Password Spraying | Testing a single password across many accounts |
| T1078 | Valid Accounts | Potential follow-on if credentials are obtained |
| TA0006 | Credential Access | Attempting to guess valid passwords |

---

## 📝 Summary

This detection validates Splunk's ability to identify NTLM password spray activity through correlated Event ID 4625 failures.

CrackMapExec generated the authentication attempts from the Kali attacker host, the Domain Controller recorded the failed NTLM logons, and Splunk extracted and correlated the activity by source IP and targeted account count. Together with the Kerberos detection, this provides strong authentication-layer visibility across both major Active Directory logon pathways.
