# Identity Security Project

## Objective
Build on the existing AD-Project lab to secure identities, enable monitoring and detection, simulate identity-based attacks, and implement Zero Trust identity controls.

## Lab Environment
Extend your AD-Project VMs:
* **Windows Server:** Domain Controller (ADDS) + Splunk Forwarder + Sysmon
* **Windows 10 Client:** Splunk Forwarder + Sysmon
* **Ubuntu Server:** Splunk Enterprise (SIEM)
* **Kali Linux:** Attacker VM
* **New:* Additional VMs as needed (e.g., Privileged Access Workstation, FIDO2 test box)

## Skills Learned
- Enforcing MFA and passwordless authentication (FIDO2, Windows Hello)
- Securing service accounts with LAPS and rotation
- Implementing Conditional Access and Just-in-Time admin access
- Creating Splunk dashboards focused on identity anomalies
- Detecting Pass-the-Hash, Kerberoasting, token-theft simulations
- Designing identity incident response playbooks

## Tools Used
- VirtualBox (or Hyper-V, VMware) for lab infrastructure
- Active Directory Domain Services (ADDS)
- Splunk Enterprise & Universal Forwarder
- Sysmon for detailed Windows telemetry
- Microsoft LAPS, Conditional Access tools, FIDO2 keys
- Kali Linux (Mimikatz, Impacket, Evilginx)
- Azure Entra ID or similar for Conditional Access simulation

## Workflow Overview
1. **Extend AD lab**: Add LAPS, enforce stricter password policies, enable MFA.
2. **Deploy identity monitoring**: Configure logging, adapt Splunk dashboards to detect identity risks.
3. **Simulate identity attacks**: Pass-the-Hash, Kerberoasting, token theft; observe what gets caught.
4. **Implement Zero Trust defenses**: Conditional Access, JIT access, PAW, passwordless logins.
5. **Document governance**: Joiner/Mover/Leaver, IR playbooks for identity incidents.

## Steps


