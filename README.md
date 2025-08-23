# Identity Security Project

## Objective
Build on the existing AD-Project lab to secure identities, enable monitoring and detection, simulate identity-based attacks, and implement Zero Trust identity controls.

## Lab Environment
This project builds on the original **AD-Project** lab, re-using the same VMs and extending them for identity security monitoring and detection.

- **Windows Server (Domain Controller)**
  - Active Directory Domain Services (ADDS)  
  - Group Policy Objects (GPOs)  
  - **Sysmon** for detailed event logging  
  - **Wazuh Agent** to forward logs  

- **Windows 10 Client(s)**
  - Domain-joined workstation(s)  
  - **Sysmon** for endpoint telemetry  
  - **Wazuh Agent** to forward logs  

- **Ubuntu Server (Wazuh Manager)**
  - Collects logs from agents  
  - Applies detection rules mapped to MITRE ATT&CK  
  - Forwards events to Kibana for visualization  

- **Kibana Dashboard**
  - Web interface for searching, alerting, and visualizing identity-related events  

- **Kali Linux (Attacker VM)**
  - Used to simulate real-world identity attacks (Pass-the-Hash, Kerberoasting, token theft, phishing, etc.)  

- **Optional Additional VMs**
  - **Privileged Access Workstation (PAW)** for admin tasks  
  - **FIDO2 / Passwordless Authentication test box**

## Skills Learned
- Enforcing identity security controls in Active Directory (MFA, password policies, LAPS)  
- Deploying and configuring **Wazuh Agents** to forward Sysmon and Windows Event logs  
- Building **Kibana dashboards** to detect and visualize identity risks  
- Simulating and detecting identity-based attacks (Pass-the-Hash, Kerberoasting, token theft)  
- Applying **Zero Trust principles**: Conditional Access, Just-in-Time access, Privileged Access Workstations (PAW), and passwordless authentication  
- Writing **identity governance policies** and **incident response playbooks** for compromised credentials and privilege abuse

## Tools Used
- **Active Directory Domain Services (ADDS)**  
- **Group Policy Objects (GPOs)** for enforcing security baselines  
- **Sysmon** for endpoint telemetry  
- **Wazuh Agents & Wazuh Manager** for log collection and detection  
- **Kibana** for visualization and monitoring  
- **Kali Linux** (Mimikatz, Impacket, Evilginx) for red team simulations  
- **Local Administrator Password Solution (LAPS)**  
- **draw.io** for network and lab topology diagrams

## Workflow Overview
1. **Extend AD Lab**
   - Add Local Administrator Password Solution (LAPS)  
   - Enforce stricter password policies  
   - Enable Multi-Factor Authentication (MFA)  

2. **Deploy Identity Monitoring**
   - Configure Windows Event Logging and Sysmon  
   - Forward events using the **Wazuh Agent**  
   - Use Wazuh rules and **Kibana dashboards** to detect identity risks  

3. **Simulate Identity Attacks**
   - Execute attacks such as Pass-the-Hash, Kerberoasting, and token theft using Kali Linux  
   - Observe what events are detected and how they surface in Wazuh/Kibana  

4. **Implement Zero Trust Defenses**
   - Apply Conditional Access policies  
   - Introduce Just-in-Time (JIT) administrative access  
   - Deploy a Privileged Access Workstation (PAW)  
   - Explore passwordless authentication (e.g., FIDO2, Windows Hello for Business)  

5. **Document Governance**
   - Define Joiner/Mover/Leaver identity processes  
   - Create Identity Incident Response (IR) playbooks  
   - Build runbooks for SOC use

## Steps

<img width="663" height="671" alt="Identity-Security-Project drawio" src="https://github.com/user-attachments/assets/268a16b5-fafd-4942-9287-db146bdabdff" />

**Figure 1 – Identity Security Network Topology:** Similar setup to AD-Project however Splunk changed out for Wazuh with Kibana dashboard for visualisation.

<img width="794" height="603" alt="Wazuh-NATNetwork" src="https://github.com/user-attachments/assets/ea49b024-4cd8-4fed-8d65-b5d91a598f05" />

**Figure 2 – Wazuh NAT Network:** The new Ubuntu VM which will run Wazuh has been spun up and added to the existing ADProject NAT Network. This will allow it to communicate with the already existing DC and Windows client that are also on the NAT network.

<img width="663" height="297" alt="Wazuh-netplan" src="https://github.com/user-attachments/assets/14306abf-3b67-498b-8fd5-23869893750f" />

**Figure 3 - netplan (static IP):** Edited netplan file to turn off DHCP and use assigned static IP of 192.168.10.20 with NAT network gateway of 192.168.10.1 and Google DNS. I then ran 'sudo netplan apply' to apply the netplan settings and 'sudo systemctl restart systemd-networkd' to restart to network interface.

<img width="1004" height="305" alt="netplan-applied" src="https://github.com/user-attachments/assets/0ca58c6b-f8b0-4434-8ba0-5dc84f91877b" />

**Figure 4 - netplan applied:** Running 'ip a' to confirm that the Wazuh VM is now using static IP of 192.168.10.20.

<img width="644" height="218" alt="ping from wazuh to dc" src="https://github.com/user-attachments/assets/8ae97529-2d0e-4404-9b63-3140af212394" />
<img width="456" height="205" alt="ping from dc to wazuh" src="https://github.com/user-attachments/assets/f075e297-7a01-45fc-8ec6-d5b506e52a3d" />

**Figure 5 - Connection check both ways between Wazuh and DC:** Now that Wazuh has static IP set on the NAT network the DC can successfully be pinged and the DC can successfully ping Wazuh.

<img width="1167" height="85" alt="Allow-ICMP-WazuhAgent" src="https://github.com/user-attachments/assets/e8604122-6c28-4c08-aeb6-9942a25a1dc6" />

**Figure 6 - Applying Firewall rules on DC:** ICMP has been allowed inbound for troubleshooting and TCP 1514 has been allowed outbound so the Wazuh agent can send data back to the Wazuh manager.















## Outcomes
- Hardened Active Directory environment with improved identity security controls  
- Successful deployment of a SIEM pipeline using **Wazuh + Kibana** instead of Splunk, demonstrating tool diversity  
- Detection and visualization of real-world identity attack techniques mapped to **MITRE ATT&CK**  
- Practical application of **Zero Trust Identity** concepts in a lab setting  
- Documentation of governance processes and **SOC-ready playbooks** for identity-related incidents  
- Enhanced portfolio project showcasing both **blue team defense** and **red team attack simulation** skills

