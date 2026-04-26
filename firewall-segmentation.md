# 🛡️ Firewall Segmentation with pfSense

## Objective

The original lab operated on a flat VirtualBox network that allowed direct communication between the Domain Controller, Splunk server, Windows client, and Kali attack box. While this was fine for the initial build, it did not reflect a segmented network design.

To improve the security architecture of the lab, I deployed a lightweight pfSense firewall VM and migrated the lab onto a new routed internal subnet. This introduced a security boundary between internal lab hosts and upstream connectivity, while creating a base for future segmentation and firewall policy.

---

## Why I Added a Firewall

The initial lab design used a single flat network:

- Domain Controller
- Windows client
- Splunk server
- Kali Linux attack box

This made the environment easy to build, but it meant there was no dedicated control point for:

- north-south traffic
- default gateway enforcement
- network segmentation
- future allow and deny rules between hosts

By introducing pfSense, I was able to:

- place lab systems behind a firewall
- create a dedicated internal subnet
- use pfSense as the default gateway
- issue DHCP leases from the firewall
- support a staged migration away from the original flat network
- create a more realistic security model for attack simulation and detection engineering

---

## Architecture

### Before

```text
VirtualBox NAT / Flat ADProject network
|
+-- Domain Controller
+-- Windows Client
+-- Splunk Server
+-- Kali Linux
```

### After

```text
VirtualBox NAT
|
pfSense WAN (em0)
pfSense LAN (em1) - 192.168.50.1/24
|
+-- Kali Linux
+-- Domain Controller
+-- Windows Client
+-- Splunk Server
```

The firewall now sits between the internal lab segment and upstream connectivity.

---

## Firewall VM Configuration

| Setting | Value |
|---|---|
| Firewall Platform | pfSense CE |
| Hypervisor | VirtualBox |
| OS Type | FreeBSD (64-bit) |
| vCPU | 2 |
| RAM | 2 GB |
| Disk | 16 GB |
| WAN Adapter | NAT |
| LAN Adapter | Internal Network (`LAB_LAN`) |

### Interface Design

| Interface | Purpose | Value |
|---|---|---|
| WAN (`em0`) | Upstream connectivity | DHCP via VirtualBox NAT |
| LAN (`em1`) | Internal lab segment | `192.168.50.1/24` |

### DHCP Scope

| Setting | Value |
|---|---|
| DHCP Enabled | Yes |
| Range Start | `192.168.50.100` |
| Range End | `192.168.50.199` |

---

## Deployment Steps

### 1. Downloaded the pfSense ISO

I downloaded the pfSense Community Edition AMD64 installer ISO and attached it to a new VirtualBox VM.

<img width="578" height="652" alt="pfSense VM settings" src="https://github.com/user-attachments/assets/82e950b7-21a6-47d5-9f0e-e4a9dd1bd8e8" />

**Figure 1 – pfSense VM configuration in VirtualBox**

---

### 2. Created the pfSense VM

The VM was built with:

- 2 vCPU
- 2 GB RAM
- 16 GB disk
- FreeBSD (64-bit)

### 3. Configured the network adapters

The pfSense VM was configured with two adapters:

- **Adapter 1:** NAT for WAN connectivity
- **Adapter 2:** Internal Network named `LAB_LAN` for the internal lab segment

---

### 4. Installed pfSense

During installation:

- `em0` was assigned as the WAN interface
- `em1` was assigned as the LAN interface
- WAN was left on DHCP
- LAN was configured as `192.168.50.1/24`
- DHCP was enabled on the LAN interface
- UFS was selected instead of ZFS to keep the VM lightweight

<img width="565" height="247" alt="pfSense WAN assignment" src="https://github.com/user-attachments/assets/eaa9e0b9-1b4f-44ec-9540-936e52b69313" />

**Figure 2 – pfSense WAN interface assignment during installation**

---

### 5. Verified pfSense console status

After installation, pfSense showed:

- WAN on `10.0.2.15/24`
- LAN on `192.168.50.1/24`

This confirmed that both interfaces were active and correctly assigned.

<img width="677" height="405" alt="pfSense complete (interfaces)" src="https://github.com/user-attachments/assets/3e770a00-52f7-4afa-b584-1f73cef6eb45" />

**Figure 3 – pfSense console showing WAN and LAN interface status**

---

### 6. Migrated Kali first

Kali was selected as the first system to move behind the firewall because it was the lowest-risk host to test.

Its VirtualBox adapter was changed to:

- **Internal Network**
- **Name:** `LAB_LAN`

After booting Kali, the old static address from the previous `192.168.10.0/24` network was still present. This had to be removed so the system could use DHCP cleanly from pfSense.

---

### 7. Cleaned up stale Kali addressing

The old static IP configuration on Kali was removed, allowing the system to correctly receive:

- IP address: `192.168.50.100`
- default gateway: `192.168.50.1`

<img width="1036" height="347" alt="Kali LAB_LAN complete" src="https://github.com/user-attachments/assets/0c3f9e5b-689d-4fd7-b69b-c84be28ae2cb" />

**Figure 4 – Kali receiving the new 192.168.50.0/24 address**

---

## Initial Validation

### pfSense Interface Validation

The pfSense web GUI confirmed:

- WAN interface up on `10.0.2.15`
- LAN interface up on `192.168.50.1`

<img width="450" height="683" alt="pfSense GUI interface status" src="https://github.com/user-attachments/assets/2123ef3e-0bd2-42dc-8e65-4793ce00494b" />

**Figure 5 – pfSense interface status in the web GUI**

### DHCP Lease Validation

The DHCP lease table showed Kali had received:

- Hostname: `kali`
- IP address: `192.168.50.100`

This confirmed that pfSense was acting as the DHCP server for the new internal segment.

<img width="954" height="503" alt="pfSense GUI DHCP leases" src="https://github.com/user-attachments/assets/1b9aebb6-043a-4d5b-a2b4-09565321661a" />

**Figure 6 – DHCP lease issued to Kali from pfSense**

### Kali Network Validation

`ip a` confirmed Kali received an address on the new subnet.

`ip route` confirmed the default route was now:

```text
default via 192.168.50.1 dev eth0
```

### Connectivity Testing

The following tests were successful from Kali:

- `ping 192.168.50.1`
- `ping 8.8.8.8`
- `ping google.com`

This confirmed:

- local LAN connectivity
- successful routing through pfSense
- outbound internet access
- working DNS resolution

<img width="697" height="554" alt="Kali LAB_LAN connectivity" src="https://github.com/user-attachments/assets/c5db5d52-cb03-48b1-94fa-be03d226e910" />

**Figure 7 – Connectivity validation from Kali through pfSense**

---

## Extended Host Migration

After validating pfSense with Kali, I continued migrating the core lab systems onto the new `192.168.50.0/24` subnet behind the firewall.

The migration order was adjusted during testing. The Domain Controller was moved earlier than originally planned so that the Windows client could authenticate, resolve domain DNS, and perform administrative actions after being moved to the new network.

### Updated Host Addressing

| Host | Role | Previous IP | New IP | Gateway | DNS |
|---|---|---:|---:|---:|---:|
| pfSense | Firewall / Gateway | N/A | `192.168.50.1` | N/A | N/A |
| Splunk | SIEM | `192.168.10.10` | `192.168.50.10` | `192.168.50.1` | `192.168.50.20` |
| ADDC01 | Domain Controller / DNS | `192.168.10.7` | `192.168.50.20` | `192.168.50.1` | `127.0.0.1` |
| Target-PC | Windows Client | `192.168.10.100` | `192.168.50.110` | `192.168.50.1` | `192.168.50.20` |
| Kali | Attack Host | `192.168.10.250` | `192.168.50.100` | `192.168.50.1` | DHCP |

### Domain Controller Migration

The Domain Controller was moved to `LAB_LAN` and readdressed from `192.168.10.7` to `192.168.50.20`.

After the change, the DC was validated by confirming:

- connectivity to pfSense at `192.168.50.1`
- local DNS resolution using `127.0.0.1`
- `adproject.local` resolving to `192.168.50.20`

<img width="465" height="466" alt="Domain Controller migrated to the new firewall subnet" src="https://github.com/user-attachments/assets/85215087-5730-4b60-9457-9dd36b742b5c" />

**Figure 8 – Domain Controller migrated to the new firewall subnet**

### Windows Client Migration

The Windows client was moved to `LAB_LAN` and readdressed from `192.168.10.100` to `192.168.50.110`.

The client was configured with:

- default gateway: `192.168.50.1`
- DNS server: `192.168.50.20`

Validation confirmed:

- connectivity to pfSense
- connectivity to the Domain Controller
- successful DNS resolution for `adproject.local`

<img width="725" height="1126" alt="Windows client communicating with pfSense and the Domain Controller" src="https://github.com/user-attachments/assets/1fc16a64-e5a8-4144-bf05-5a91bf37f1e0" />

**Figure 9 – Windows client communicating with pfSense and the Domain Controller**

### Splunk Server Migration

The Splunk server was moved from `192.168.10.10` to `192.168.50.10`.

The updated Splunk network configuration used:

- IP address: `192.168.50.10/24`
- default gateway: `192.168.50.1`
- DNS server: `192.168.50.20`

After migration, Splunk network connectivity was validated from the new subnet. Splunk was reachable at `192.168.50.10`, and Splunk Web was accessible from the client at:

```text
http://192.168.50.10:8000
```

This confirmed that the Splunk server was reachable on the new subnet behind pfSense.

<img width="373" height="277" alt="Splunk server readdressed to the new subnet" src="https://github.com/user-attachments/assets/18fe7862-3d5f-472b-a41e-287e8ed3a7bd" />

**Figure 10 – Splunk server readdressed to the new subnet**

<img width="673" height="641" alt="Splunk connectivity validation on the new subnet" src="https://github.com/user-attachments/assets/743d5a81-b7c3-4843-a3de-089868c6cf7b" />

**Figure 11 – Splunk connectivity validation on the new subnet**

### Splunk License Note

During validation, Splunk Web was reachable at:

```text
http://192.168.50.10:8000
```

However, the installed Developer license had expired. This confirmed that the issue was related to Splunk licensing rather than firewall routing, DNS, or subnet migration.

<img width="749" height="420" alt="Splunk GUI reachable but license expired" src="https://github.com/user-attachments/assets/dc288250-2c53-4e94-9701-0731aefc8e3d" />

**Figure 12 – Splunk Web reachable but Developer license expired**

A new Splunk Developer license was requested so the lab could continue using Splunk Enterprise features for detection engineering, dashboards, and alerting.

---

## Troubleshooting Notes

### Kali retained its old static IP

After moving Kali to `LAB_LAN`, the VM still held its previous static address from the original `192.168.10.0/24` network.

This caused the interface to hold two addresses at once:

- old static IP from the original lab
- new DHCP lease from pfSense

<img width="1040" height="591" alt="Kali new LAB_LAN DHCP" src="https://github.com/user-attachments/assets/16f862e8-5c47-4f6c-95cd-c0186854b964" />

**Figure 13 – Kali temporarily holding both the old static address and new DHCP lease**

The stale address had to be removed before the network configuration was clean. The issue was resolved by removing the old static address from the Kali network profile so that the interface used only the DHCP lease issued by pfSense.

### Domain dependency during Windows client migration

When the Windows client was moved to `LAB_LAN`, it still had its old static IP settings from the `192.168.10.0/24` network. This meant it could not reach pfSense or the Domain Controller.

Because the machine was domain-joined, administrative actions were unreliable while the client could not contact the DC. The migration plan was adjusted so the Domain Controller was moved to the new subnet before completing the Windows client configuration.

This allowed the client to use the DC at `192.168.50.20` for DNS and domain services.

### Splunk Web reachable but license expired

After moving Splunk to `192.168.50.10`, the Splunk Web interface was reachable from the migrated client. This confirmed that routing and connectivity to Splunk were working through the new firewall-backed subnet.

Splunk Web then showed that the Developer license had expired. This was treated as a separate application licensing issue, not a firewall or routing issue.

---

## Security Outcome

Adding pfSense improved the lab in several ways:

- introduced a proper firewall boundary
- introduced planned static addressing for core infrastructure systems
- replaced the flat network design with a routed internal segment
- established a central default gateway for the new subnet
- created a base for future access control between hosts
- improved the realism of the environment from a blue-team and detection engineering perspective

This change supports future hardening such as:

- restricting Kali traffic to approved targets
- limiting direct access to infrastructure systems
- controlling which hosts can reach Splunk management services
- enforcing tighter segmentation between attacker, endpoint, and infrastructure systems

At this stage, the focus was on migration and validation. Restrictive host-to-host firewall rules will be added in a later phase.

---

## Next Steps

The firewall deployment and host migration have been completed for the main lab systems.

The next planned steps are:

1. apply the renewed Splunk Developer license
2. update Splunk Universal Forwarder outputs to use `192.168.50.10:9997`
3. validate event ingestion from the Domain Controller
4. validate event ingestion from the Windows client
5. define firewall rules between attacker, client, and infrastructure systems
6. document firewall rule testing and blocked traffic behaviour

---

## Summary

This change moved the lab away from a flat virtual network and introduced a dedicated firewall boundary using pfSense. The deployment was kept lightweight to fit within the available host resources while still providing a meaningful security improvement.

The migration was validated by placing Kali behind the new firewall, confirming DHCP lease assignment, routing, and internet access through pfSense.

The migration was then extended to the Domain Controller, Windows client, and Splunk server. This placed the core lab systems onto the new `192.168.50.0/24` subnet behind pfSense and created a stronger base for future segmentation, firewall rules, and Splunk-based monitoring.
