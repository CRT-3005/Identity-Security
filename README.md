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


## Steps

<img width="738" height="651" alt="Identity-Security-Project drawio" src="https://github.com/user-attachments/assets/b977b773-a4e6-4287-bede-ffa10570579c" />

**Figure 1 – Identity Security Network Topology:** Similar setup to AD-Project however Splunk changed out for Wazuh which is using the all in one installation including Wazuh dashboard access.

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

<img width="864" height="67" alt="downloading and installing Wazuh" src="https://github.com/user-attachments/assets/d62a826c-13d7-49ea-a1ed-5b87232aa24a" />

**Figure 7 - Downloading and running the Wazuh Installer:** 

<img width="936" height="70" alt="wazuh manager status" src="https://github.com/user-attachments/assets/e2be0030-bfcb-40ed-986e-1cf7438e070e" />
<img width="913" height="89" alt="wazuh dashboard status" src="https://github.com/user-attachments/assets/892ac551-f4ee-429c-857b-5ccbbac65997" />
<img width="934" height="69" alt="wazuh indexer status" src="https://github.com/user-attachments/assets/aa95655f-0544-438a-9c5f-4f407fa3895d" />

**Figure 8 - Verifying Wazuh services are active:** All 3 important services confirmed to be running

<img width="801" height="355" alt="wazuh config" src="https://github.com/user-attachments/assets/575c8db6-b49b-45e9-a9cb-e1744303e7e1" />

**Figure 9 - Config for Wazuh Dashboard:** YAML config configured for the Wazuh Dashboard

<img width="950" height="695" alt="accessing wazuh dashboard" src="https://github.com/user-attachments/assets/cb60ff1f-ccea-4f8a-8e13-7dfd8eeee853" />

**Figure 10 - Accessing the Wazuh Dashboard:** After confirming the services are running the dashboard can be accessed via https://192.168.10.20:5601

<img width="1097" height="20" alt="installing wazuh agent on DC" src="https://github.com/user-attachments/assets/3adc805b-0136-4d3e-881a-0850fb7851fc" />

**Figure 11 - Installing Wazuh agent on DC:** On the DC the latest stable version of the wazuh agent (at the time) is installed via silent powershell command

<img width="317" height="231" alt="DC wazuh agent config" src="https://github.com/user-attachments/assets/32139103-13d7-4fea-b8cf-fbbd65ed1df5" />

**Figure 12 - Verifying DC agent config:** Looking at the config file for the Wazuh agent confirms the silent install was successful

<img width="602" height="461" alt="registering agent on Wazuh Manager" src="https://github.com/user-attachments/assets/7cfe65d5-8ae2-4dea-b65a-31b64f37d129" />

**Figure 13 - Registering DC agent on Wazuh Manager:** The DC now needs to be added into Wazuh Manager and then an 'agent key' can be generated which is then imported onto the DC

<img width="772" height="87" alt="DC client keys" src="https://github.com/user-attachments/assets/7a5e2f8e-e1c1-477f-906f-48152d49837a" />
<img width="865" height="42" alt="DC client keys wazuh manager" src="https://github.com/user-attachments/assets/b3076051-1433-460e-8da4-32724f49f632" />

**Figure 14 - Agent key on DC and Wazuh Manager:** The agent key was added to the DC and then it replicated onto Wazuh Manager, this was confirmed using the command '/var/ossec/etc/client.keys'

<img width="1389" height="186" alt="DC online in wazuh dashboard" src="https://github.com/user-attachments/assets/ac99af7d-7da8-4f81-a31a-f1e86ed9acca" />

**Figure 15 - DC agent online in Wazuh Dashboard:** When loggging into the Wazuh Dashboard going to Agents Summary shows 1 active agent which is the DC that has just been configured.

<img width="771" height="72" alt="Win10 client keys" src="https://github.com/user-attachments/assets/a13ff637-8c7f-45a6-ad2f-097884c6c639" />
<img width="952" height="64" alt="Win10 client keys wazuh" src="https://github.com/user-attachments/assets/33da6640-a99e-4b2c-ac44-0a4a476f36f9" />

**Figure 16 - Windows 10 client keys:** The same process for agent install on the DC has been completed on the Windows 10 client as well. Entries are the same on both client.keys files for the Windows 10 client and on Wazuh Manager.

<img width="1385" height="229" alt="Win10 agent status" src="https://github.com/user-attachments/assets/ba430454-d472-4181-bacf-89a6ef580efb" />

**Figure 17 - Windows 10 client online in Wazuh Dashboard:** The Wazuh Dahsboard now shows 2 active agents on the Agents Summary screen and when clicking into this it confirms the DC (as setup before) and now the Windows 10 client. Both reproting in from their allocated IP addresses.

<img width="613" height="255" alt="image" src="https://github.com/user-attachments/assets/cc8f69ac-a5d0-45f0-8a94-3b2ef148ee05" />

**Figure 18 - Sysmon:** For both VMs Sysmon was also reinstalled as both machines had existing Sysmon config from the previous AD lab. In this lab the Sysmon config being used is from SwiftOnSecuritys github page. Sysmon itself along with the config file were placed into C:\Tools\Sysmon on both VMs.










## Outcomes
- Hardened AD environment with modern identity controls
- Working SIEM pipeline using **Wazuh Manager + Wazuh Dashboard** (vendor diversity from Splunk)
- Detections mapped to **MITRE ATT&CK** with real attack simulations
- Practical Zero Trust identity protections in a lab
- Governance docs and **SOC-ready playbooks** for identity incidents

