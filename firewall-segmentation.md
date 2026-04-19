# 🛡️ Firewall Segmentation with pfSense

## Objective

The original lab operated on a flat VirtualBox network that allowed direct communication between the Domain Controller, Splunk server, Windows client, and Kali attack box. While this was fine for the initial build, it did not reflect a segmented network design.

To improve the security architecture of the lab, I deployed a lightweight pfSense firewall VM and began migrating systems onto a new routed internal subnet. This introduced a security boundary between internal lab hosts and upstream connectivity, while creating a foundation for tighter traffic control and future firewall policy.

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
+-- Windows Client
+-- Splunk Server
+-- Domain Controller
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

## Validation

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

## Troubleshooting Notes

### Kali retained its old static IP

After moving Kali to `LAB_LAN`, the VM still held its previous static address from the original `192.168.10.0/24` network.

This caused the interface to hold two addresses at once:

- old static IP from the original lab
- new DHCP lease from pfSense

<img width="1040" height="591" alt="Kali new LAB_LAN DHCP" src="https://github.com/user-attachments/assets/16f862e8-5c47-4f6c-95cd-c0186854b964" />

**Figure 8 – Kali temporarily holding both the old static address and new DHCP lease**

The stale address had to be removed before the network configuration was clean. The issue was resolved by removing the old static address from the Kali network profile so that the interface used only the DHCP lease issued by pfSense.

### Why Kali was migrated first

Kali was moved before the Windows client, Splunk, or the Domain Controller because it was the least disruptive host to test. This reduced the risk of breaking:

- domain services
- DNS
- authentication
- Splunk ingestion

---

## Security Outcome

Adding pfSense improved the lab in several ways:

- introduced a proper firewall boundary
- replaced the flat network design with a routed internal segment
- established a central default gateway for the new subnet
- created a base for future access control between hosts
- improved the realism of the environment from a blue-team and detection engineering perspective

This change supports future hardening such as:

- restricting Kali traffic to approved targets
- limiting direct access to infrastructure systems
- controlling which hosts can reach Splunk management services
- enforcing tighter segmentation between attacker, endpoint, and infrastructure systems

---

## Next Steps

The firewall deployment was completed and validated using Kali as the first migrated host.

The next planned steps are:

1. move the Windows client behind pfSense
2. validate domain connectivity and DNS behaviour
3. move the Splunk server to the new subnet
4. move the Domain Controller last
5. define firewall rules between attacker, client, and infrastructure systems
6. document the impact of segmentation on Splunk data ingestion

---

## Summary

This change moved the lab away from a flat virtual network and introduced a dedicated firewall boundary using pfSense. The deployment was kept lightweight to fit within the available host resources while still providing a meaningful security improvement.

The migration was validated successfully by placing Kali behind the new firewall, confirming DHCP lease assignment, routing, and internet access through pfSense.
