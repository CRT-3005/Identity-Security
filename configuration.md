# Configuration

<img width="536" height="579" alt="image" src="https://github.com/user-attachments/assets/751644ca-f84d-4133-a614-b9129915c264" />

**Figure 1 – Changing inputs.conf file :** 
Created new `inputs.conf` files for both the **Domain Controller** and **Windows 10 client** 
The configuration ensures Windows Event Logs (Security, System, Application) and Sysmon data are forwarded to the Splunk indexer.  
Each host uses the proper indexes (`identity`, `sysmon`, `endpoint`) for clean separation of telemetry.

<img width="634" height="109" alt="image" src="https://github.com/user-attachments/assets/4054d066-0f91-4d3d-8dd7-b042c5eedb7f" /> <img width="624" height="91" alt="image" src="https://github.com/user-attachments/assets/59aacf4f-bd53-41c5-a3c1-a685b8ce8c31" />

**Figure 2 – inputs.conf Location:**  
Instead of using the default `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`, the configuration files were moved into new app folders:
C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-DC\local
C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-Workstation\local
The original files in C:\Program Files\SplunkUniversalForwarder\etc\system\local had to be renamed to .bak so they were then ignored by Splunk.

<img width="661" height="244" alt="image" src="https://github.com/user-attachments/assets/2ee95f5b-58e5-4263-ab62-ed2eb979e736" />

**Figure 3 – app.conf Metadata File:**  
An `app.conf` file was created in each app’s `default` folder.  
This defines the app metadata (author, description, version) and ensures Splunk recognizes the app structure properly. Located in C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-DC\default & C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-Workstation\default

<img width="302" height="217" alt="image" src="https://github.com/user-attachments/assets/c77f3762-4e90-4c19-a82d-49f68146cff9" />

**Figure 4 – outputs.conf configuration:** 
An outputs.conf file was created in both the IdentityInputs-DC and IdentityInputs-Workstation app folders.
This file specifies the destination indexer (192.168.10.10:9997) for forwarded logs.

<img width="1025" height="97" alt="image" src="https://github.com/user-attachments/assets/80b2ac0f-bc45-4154-8eed-4128522db340" />

**Figure 5 – Verifying Splunk Receiver:** 
Command 'sudo /opt/splunk/bin/splunk display listen' confirms that the Splunk indexer is listening on port 9997 for incoming forwarder traffic.
The SSL hostname validation warning is expected in lab environments using self-signed certificates and does not affect functionality.

<img width="616" height="314" alt="image" src="https://github.com/user-attachments/assets/7c6a5322-7e92-4e6a-9ce1-3f6f2fc3f319" />

**Figure 6 – Verifying Active Forwarders:**
Aggregated host activity across identity, endpoint, and sysmon indexes. The query uses tstats, which returns statistical results (shown in the Statistics tab), confirming both ADDC01 and TARGET-PC are actively sending data.

<img width="113" height="223" alt="image" src="https://github.com/user-attachments/assets/c99e52ce-20f8-4814-a4c9-b4a4a86cda58" />

**Figure 7 – Index Creation:**
New indexes identity and sysmon were created to align with the forwarder configurations.
The existing endpoint index was retained from the previous Active Directory project.

<img width="666" height="459" alt="image" src="https://github.com/user-attachments/assets/df4a3ba4-7c8e-445b-8513-d401c640940f" />

**Figure 8 – Host Verification in Splunk:**
Search results confirm successful ingestion of Windows Event Logs from both the Domain Controller (ADDC01) and Windows 10 client (TARGET-PC).
Each host reports Security, System, and Application logs under their respective indexes (identity and endpoint).

<img width="1887" height="475" alt="image" src="https://github.com/user-attachments/assets/23f140ad-e6c7-42e5-87ec-603899c0a615" />

**Figure 9 – PowerShell Operational Logs:**
Confirms ingestion of PowerShell Operational events used for command execution monitoring.

<img width="1866" height="31" alt="image" src="https://github.com/user-attachments/assets/442327aa-6527-441e-8e1c-243dac251dba" />

**Figure 10 – Splunk Add-on for Microsoft Windows:**
Installed the official Splunk Add-on for Microsoft Windows on the Splunk Enterprise server to automatically parse and normalize Windows Event Logs and Sysmon data.
This add-on enables extraction of key fields such as EventCode, Image, User, and ParentImage, improving detection and analysis capabilities.

<img width="1885" height="538" alt="image" src="https://github.com/user-attachments/assets/8d4304a3-6f5d-4f8b-9e4f-7f96b7cb448f" />

**Figure 11 - Sysmon Event Verification:**
Sysmon telemetry is successfully ingested into Splunk under the sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.  
The search below confirms detection of Event ID 3 (network connection) and other Sysmon event codes.  
After installing the **Splunk Add-on for Microsoft Windows**, key fields such as `EventCode`, `Image`, and `User` are automatically extracted for deeper analysis.

index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-15m
| stats count by EventCode, Image

*Before moving onto attacks and detections the Windows 10 client VM was updated to Windows 11*
