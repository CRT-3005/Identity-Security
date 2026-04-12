# Detection Coverage

This folder contains the detection engineering work for the Identity Security project.

The detections focus on identity-based threats and authentication abuse within Active Directory, using Windows Security telemetry, Splunk correlation logic, and analyst-driven validation. Each detection is written to reflect a practical SOC use case, with supporting investigation context, validation steps, tuning considerations, and MITRE ATT&CK mapping where relevant.

## Detection Areas

### Kerberos Password Spray
Detects password spray activity against Kerberos authentication using Windows Security events and XML field extraction.

**Documentation:** `kerberos-password-spray.md`

---

### NTLM Password Spray
Detects NTLM password spray activity through repeated failed logons and source-based correlation.

**Documentation:** `ntlm-password-spray.md`

---

### SMB Authentication Abuse
Detects suspicious SMB authentication activity involving valid accounts and network logon patterns.

**Documentation:** `smb-authentication-abuse.md`

---

### Failed to Successful Authentication Correlation
Correlates repeated failed logons followed by a successful authentication within a short time window.

**Documentation:** `failed-to-successful-authentication-correlation.md`

---

### Privileged Account Authentication Monitoring
Monitors authentication activity involving privileged or high-value accounts.

**Documentation:** `privileged-account-authentication-monitoring.md`

---

### Impossible Travel Authentication
Detects successful Kerberos authentication from multiple source IPs within a short time period.

**Documentation:** `impossible-travel-kerberos-authentication.md`

---

### Kerberoasting – Weak Kerberos Encryption
Detects Kerberos service ticket activity using non-AES encryption in an AES-hardened domain.

**Documentation:** `kerberoasting-weak-encryption-detection.md`

---

### Password Spray Detection Tuning
Documents tuning decisions, false positive considerations, and detection refinement for password spray-related analytics.

**Documentation:** `password-spray-detection-tuning.md`

---

## Detection Methodology

Each detection page is designed to document more than the SPL alone. Where relevant, pages include:

- Detection objective
- Attack simulation or test method
- Relevant telemetry and Event IDs
- SPL logic
- Validation results
- Tuning and false positive considerations
- MITRE ATT&CK mapping

## Notes

These detections are intended to reflect realistic SOC workflows rather than isolated alert creation. The emphasis is on identifying high-signal identity activity, validating detections against live telemetry, and supporting repeatable investigation and response.
