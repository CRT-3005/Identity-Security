# Configuration

This document details the setup and configuration steps for the Identity Security project environment.  
It covers Splunk, Windows hosts, Sysmon, log forwarding pipelines, and the forwarder destination changes made after the pfSense network migration.

The lab was originally configured on the flat `192.168.10.0/24` network. After the core detections, hardening validation, dashboards, and SOC playbooks were built, the lab was migrated behind pfSense onto the `192.168.50.0/24` subnet. This required the Splunk Universal Forwarder outputs to be updated from the original Splunk indexer address to the new Splunk server address.

---

## Forwarder Input Configuration

<img width="536" height="579" alt="image" src="https://github.com/user-attachments/assets/751644ca-f84d-4133-a614-b9129915c264" />

**Figure 1 – Changing inputs.conf file**  
Created new `inputs.conf` files for both the **Domain Controller** and **Windows client**.

The configuration ensures Windows Event Logs and Sysmon data are forwarded to the Splunk indexer. Each host uses the proper indexes (`identity`, `sysmon`, `endpoint`) for clean separation of telemetry.

The configured sources include:

- Windows Security logs
- Windows System logs
- Windows Application logs
- Sysmon Operational logs
- PowerShell Operational logs

---

## Forwarder App Locations

<img width="634" height="109" alt="image" src="https://github.com/user-attachments/assets/4054d066-0f91-4d3d-8dd7-b042c5eedb7f" /> <img width="624" height="91" alt="image" src="https://github.com/user-attachments/assets/59aacf4f-bd53-41c5-a3c1-a685b8ce8c31" />

**Figure 2 – inputs.conf location**  
Instead of using the default path:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

the configuration files were moved into dedicated app folders:

```text
C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-DC\local
C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-Workstation\local
```

The original files in:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local
```

were renamed to `.bak` so they were ignored by Splunk.

This kept the forwarder configuration modular and easier to manage by host role.

---

## App Metadata

<img width="661" height="244" alt="image" src="https://github.com/user-attachments/assets/2ee95f5b-58e5-4263-ab62-ed2eb979e736" />

**Figure 3 – app.conf metadata file**  
An `app.conf` file was created in each app’s `default` folder.

This defines the app metadata, including:

- author
- description
- version

The files were located in:

```text
C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-DC\default
C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-Workstation\default
```

This helps Splunk recognise the app structure properly.

---

## Forwarder Output Configuration

<img width="302" height="217" alt="image" src="https://github.com/user-attachments/assets/c77f3762-4e90-4c19-a82d-49f68146cff9" />

**Figure 4 – outputs.conf configuration**  
An `outputs.conf` file was created in both the `IdentityInputs-DC` and `IdentityInputs-Workstation` app folders.

This file specifies the Splunk indexer destination for forwarded logs.

### Original Forwarder Destination

The lab originally forwarded logs to the Splunk server at:

```text
192.168.10.10:9997
```

This was the original Splunk server address on the flat VirtualBox lab network.

### Current Forwarder Destination

After the pfSense network migration, the Splunk server was moved to:

```text
192.168.50.10:9997
```

The Splunk Universal Forwarder outputs on both Windows systems were updated to use the new Splunk server address.

| Host | Role | Original Destination | Current Destination |
|---|---|---:|---:|
| ADDC01 | Domain Controller | `192.168.10.10:9997` | `192.168.50.10:9997` |
| TARGET-PC | Windows Client | `192.168.10.10:9997` | `192.168.50.10:9997` |

### Configuration Location

The active output configuration was stored in custom Splunk app paths rather than the default system local path.

On the Domain Controller, the active `outputs.conf` file was located at:

```text
C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-DC\local\outputs.conf
```

On the Windows client, the active `outputs.conf` file was located in the workstation forwarder app path:

```text
C:\Program Files\SplunkUniversalForwarder\etc\apps\IdentityInputs-Workstation\local\outputs.conf
```

The forwarding destination was updated from:

```ini
server = 192.168.10.10:9997
```

to:

```ini
server = 192.168.50.10:9997
```

After updating `outputs.conf`, the Splunk Universal Forwarder service was restarted on both Windows hosts.

```cmd
net stop SplunkForwarder
net start SplunkForwarder
```

---

## Forwarder Connectivity Validation After pfSense Migration

After the subnet migration, TCP connectivity to the Splunk receiving port was validated from both the Domain Controller and Windows client using:

```powershell
Test-NetConnection 192.168.50.10 -Port 9997
```

Both hosts returned:

```text
TcpTestSucceeded : True
```

This confirmed that the Domain Controller and Windows client could reach the Splunk server on TCP port `9997` after the move to the `192.168.50.0/24` subnet.

Full Splunk event ingestion validation will be completed after the renewed Splunk Developer license is applied and Splunk search access is restored.

---

## Verifying Splunk Receiver

<img width="1025" height="97" alt="image" src="https://github.com/user-attachments/assets/80b2ac0f-bc45-4154-8eed-4128522db340" />

**Figure 5 – Verifying Splunk Receiver**  
The following command confirmed that the Splunk indexer was listening on port `9997` for incoming forwarder traffic:

```bash
sudo /opt/splunk/bin/splunk display listen
```

The SSL hostname validation warning is expected in this lab environment because self-signed certificates are used. This does not affect basic forwarding functionality.

---

## Verifying Active Forwarders

<img width="616" height="314" alt="image" src="https://github.com/user-attachments/assets/7c6a5322-7e92-4e6a-9ce1-3f6f2fc3f319" />

**Figure 6 – Verifying Active Forwarders**  
Aggregated host activity across the `identity`, `endpoint`, and `sysmon` indexes confirmed both ADDC01 and TARGET-PC were actively sending data.

The query used `tstats`, which returns statistical results in the Statistics tab.

> Note: This validation was completed before the pfSense subnet migration, while the lab was still using the original `192.168.10.0/24` network.

---

## Index Creation

<img width="113" height="223" alt="image" src="https://github.com/user-attachments/assets/c99e52ce-20f8-4814-a4c9-b4a4a86cda58" />

**Figure 7 – Index Creation**  
New indexes were created to align with the forwarder configurations.

| Index | Purpose |
|---|---|
| `identity` | Windows authentication and identity telemetry |
| `sysmon` | Sysmon endpoint telemetry |
| `endpoint` | Existing endpoint telemetry from the earlier Active Directory project |

---

## Host Verification in Splunk

<img width="666" height="459" alt="image" src="https://github.com/user-attachments/assets/df4a3ba4-7c8e-445b-8513-d401c640940f" />

**Figure 8 – Host Verification in Splunk**  
Search results confirmed successful ingestion of Windows Event Logs from both the Domain Controller (`ADDC01`) and Windows client (`TARGET-PC`).

Each host reported Security, System, and Application logs under their respective indexes.

> Note: This validation was completed before the pfSense subnet migration. Post-migration ingestion validation is pending until the renewed Splunk Developer license is applied.

---

## PowerShell Operational Logs

<img width="1887" height="475" alt="image" src="https://github.com/user-attachments/assets/23f140ad-e6c7-42e5-87ec-603899c0a615" />

**Figure 9 – PowerShell Operational Logs**  
PowerShell Operational logs were ingested into Splunk and used for command execution monitoring.

---

## Splunk Add-on for Microsoft Windows

<img width="1866" height="31" alt="image" src="https://github.com/user-attachments/assets/442327aa-6527-441e-8e1c-243dac251dba" />

**Figure 10 – Splunk Add-on for Microsoft Windows**  
The official Splunk Add-on for Microsoft Windows was installed on the Splunk Enterprise server to parse and normalise Windows Event Logs and Sysmon data.

This add-on enables extraction of key fields such as:

- `EventCode`
- `Image`
- `User`
- `ParentImage`

These fields improve detection and analysis capability.

---

## Sysmon Event Verification

<img width="1885" height="538" alt="image" src="https://github.com/user-attachments/assets/8d4304a3-6f7b-4f8b-9e4f-8f96b7cb448f" />

**Figure 11 – Sysmon Event Verification**  
Sysmon telemetry was successfully ingested into Splunk under the sourcetype:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

The search below confirmed detection of Event ID 3 network connection events and other Sysmon event codes.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-15m
| stats count by EventCode, Image
```

After installing the Splunk Add-on for Microsoft Windows, fields such as `EventCode`, `Image`, and `User` were automatically extracted for deeper analysis.

---

## Windows 11 Client Upgrade

Before beginning identity attack simulations, the Windows 10 client VM was upgraded to **Windows 11** to reflect modern enterprise configurations and improve telemetry fidelity.

### Hardware Adjustments Required

| Setting | Old | Updated | Reason |
|---|---|---|---|
| **CPU Cores** | 1 | 2–4 | Windows 11 performance and compatibility |
| **RAM** | 2–4 GB | 8 GB | Windows 11 minimum requirement |
| **Firmware** | BIOS | UEFI (Enable EFI) | Mandatory for Windows 11 |
| **TPM** | N/A | Bypassed | VirtualBox does not natively support TPM 2.0 |
| **Disk** | 50–60 GB | Sufficient | Required for upgrade |

Configured via:

```text
VirtualBox → Settings → System → Motherboard / Processor
```

### Upgrade Process

1. Downloaded Windows 11 Installation Assistant
2. Passed compatibility checks after VM hardware changes
3. Ran in-place upgrade
4. Performed validation steps after upgrade

### Post-Upgrade Validation

- Splunk Universal Forwarder kept running
- Logs continued forwarding to indexer
- Sysmon remained operational
- Event IDs 4624, 4625, Kerberos, and Sysmon generated normally
- Host maintained domain membership and connectivity

This confirmed the Windows 11 endpoint still produced full identity telemetry.

---

## Current Validation Status

| Area | Status |
|---|---|
| Original forwarder ingestion on `192.168.10.0/24` | Validated |
| pfSense subnet migration to `192.168.50.0/24` | Completed |
| Forwarder outputs updated to `192.168.50.10:9997` | Completed |
| TCP connectivity to Splunk receiving port | Validated from ADDC01 and TARGET-PC |
| Full Splunk event ingestion after migration | Pending renewed Splunk Developer license |

---

## Next Steps

### 🔐 Next Phase – Identity Attack Detection

With the environment configured and validated across both hosts, the next phase focused on simulating real-world identity attacks and analysing Kerberos, Sysmon, and Windows Security telemetry in Splunk.

👉 **[Detection Coverage](https://github.com/CRT-3005/Identity-Security/blob/main/detections/README.md)**

### 📡 Post-Migration Validation

After the renewed Splunk Developer license is applied, the next validation step is to confirm that fresh events from ADDC01 and TARGET-PC are arriving in Splunk from the updated `192.168.50.10:9997` forwarder destination.
