# Identity Security Project

## Objective
Build on the existing AD-Project lab to secure identities, enable monitoring and detection, simulate identity-based attacks, and implement Zero Trust identity controls.

## Lab Environment

- **Windows Server (Domain Controller)**
  - ADDS, GPOs
  - **Sysmon** for detailed telemetry
  - **Wazuh Agent** to forward logs

- **Windows 10 Client(s)**
  - Domain-joined
  - **Sysmon**
  - **Wazuh Agent**

- **Ubuntu Server (Wazuh Manager)**
  - Receives events from agents
  - Applies detection rules (MITRE ATT&CK mapped)
  - Forwards data to the dashboard

- **Wazuh Dashboard**
  - Web UI for searching, alerting, and visualizing identity-related events

- **(Optional) Wazuh Indexer**
  - Backing datastore queried by the Wazuh Dashboard
  - (Installed automatically in the all-in-one setup)

- **Kali Linux (Attacker VM)**
  - Used to simulate identity attacks (PtH, Kerberoasting, token theft, phishing)

## Skills Learned
- Enforcing identity controls in AD (MFA, password policies, LAPS)
- Deploying **Wazuh Agents** to collect Windows/Sysmon telemetry
- Using the **Wazuh Dashboard** for detection, hunting, and visualization
- Simulating and detecting identity-focused attacks
- Applying Zero Trust (Conditional Access, JIT, PAW, passwordless)
- Writing identity governance policies and incident response playbooks

## Tools Used
- **Active Directory Domain Services (ADDS)**, **GPOs**
- **Sysmon**
- **Wazuh Manager**, **Wazuh Agent**
- **Wazuh Dashboard** (and **Wazuh Indexer** in all-in-one)
- **Kali Linux** (Mimikatz, Impacket, Evilginx)
- **LAPS**
- **draw.io** for lab diagrams

## Workflow Overview

1. **Extend AD Lab**
   - LAPS, stricter password policies, MFA

2. **Deploy Identity Monitoring**
   - Windows Event Logging + Sysmon
   - Forward with **Wazuh Agent** to **Wazuh Manager**
   - Detect and visualize in the **Wazuh Dashboard**

3. **Simulate Identity Attacks**
   - Pass-the-Hash, Kerberoasting, token theft (Kali)
   - Observe detections and investigate via the dashboard

4. **Implement Zero Trust Defenses**
   - Conditional Access, JIT admin, PAW, passwordless (e.g., FIDO2/WHfB)

5. **Document Governance**
   - Joiner/Mover/Leaver processes
   - Identity IR playbooks and SOC runbooks
