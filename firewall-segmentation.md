# 🛡️ Firewall Segmentation with pfSense

## Objective

The original lab operated on a flat VirtualBox network that allowed direct communication between the Domain Controller, Splunk server, Windows client, and Kali attack box. While this was fine for the initial build, it did not reflect a segmented network design.

To improve the security architecture of the lab, I deployed a lightweight pfSense firewall VM and migrated the lab onto a routed internal subnet. This introduced a security boundary between lab hosts and upstream connectivity, while creating a base for firewall policy enforcement.

The segmentation work was later extended by moving Kali onto a dedicated `ATTACK_NET` subnet. This changed Kali-to-infrastructure traffic from same-subnet communication into routed traffic that traverses pfSense and can be filtered.

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
- routed attacker subnet testing
- network segmentation
- allow and block rules between attacker, endpoint, and infrastructure systems

By introducing pfSense, I was able to:

- place core lab systems behind a firewall
- create a dedicated main lab subnet
- create a separate routed attacker subnet
- use pfSense as the default gateway for both lab networks
- issue DHCP leases from the firewall
- support a staged migration away from the original flat network
- validate firewall rule enforcement between routed subnets
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

### Initial pfSense Migration

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

This placed the lab behind pfSense, but all lab systems still shared the same `192.168.50.0/24` subnet. That meant same-subnet host-to-host traffic did not traverse pfSense.

### Current Routed Segmentation Design

```text
VirtualBox NAT
|
pfSense WAN (em0)
|
+-- pfSense LAN (em1) - 192.168.50.1/24
|   |
|   +-- Domain Controller - 192.168.50.20
|   +-- Windows Client    - 192.168.50.110
|   +-- Splunk Server     - 192.168.50.10
|
+-- pfSense ATTACK_NET (em2) - 192.168.60.1/24
    |
    +-- Kali Linux - 192.168.60.100
```

The current design separates Kali from the main lab subnet. Traffic from Kali to Splunk or the Domain Controller now routes through pfSense, allowing firewall rules to enforce segmentation.

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
| ATTACK_NET Adapter | Internal Network (`ATTACK_NET`) |

### Interface Design

| Interface | Purpose | Value |
|---|---|---|
| WAN (`em0`) | Upstream connectivity | DHCP via VirtualBox NAT |
| LAN (`em1`) | Main lab subnet | `192.168.50.1/24` |
| ATTACK_NET (`em2`) | Routed attacker subnet | `192.168.60.1/24` |

### DHCP Scopes

| Interface | DHCP Status | Range Start | Range End |
|---|---|---:|---:|
| LAN | Enabled | `192.168.50.100` | `192.168.50.199` |
| ATTACK_NET | Enabled | `192.168.60.100` | `192.168.60.199` |

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

The pfSense VM was initially configured with two adapters:

- **Adapter 1:** NAT for WAN connectivity
- **Adapter 2:** Internal Network named `LAB_LAN` for the internal lab segment

A third adapter was later added for the dedicated attacker subnet:

- **Adapter 3:** Internal Network named `ATTACK_NET`

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

This confirmed that both initial interfaces were active and correctly assigned.

<img width="677" height="405" alt="pfSense complete interfaces" src="https://github.com/user-attachments/assets/3e770a00-52f7-4afa-b584-1f73cef6eb45" />

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

This was part of the first migration stage. Kali was later moved again to the dedicated `ATTACK_NET` subnet for routed firewall rule testing.

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

### Main Lab Addressing After Migration

| Host | Role | Previous IP | New IP | Gateway | DNS |
|---|---|---:|---:|---:|---:|
| pfSense LAN | Firewall / Gateway | N/A | `192.168.50.1` | N/A | N/A |
| Splunk | SIEM | `192.168.10.10` | `192.168.50.10` | `192.168.50.1` | `192.168.50.20` |
| ADDC01 | Domain Controller / DNS | `192.168.10.7` | `192.168.50.20` | `192.168.50.1` | `127.0.0.1` |
| Target-PC | Windows Client | `192.168.10.100` | `192.168.50.110` | `192.168.50.1` | `192.168.50.20` |
| Kali | Attack Host - initial stage | `192.168.10.250` | `192.168.50.100` | `192.168.50.1` | DHCP |

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

### Splunk Forwarder Update

After moving Splunk to `192.168.50.10`, the Splunk Universal Forwarder outputs on the Domain Controller and Windows client were updated from:

```text
192.168.10.10:9997
```

to:

```text
192.168.50.10:9997
```

TCP connectivity to the Splunk receiving port was confirmed from both Windows systems using:

```powershell
Test-NetConnection 192.168.50.10 -Port 9997
```

Both systems returned `TcpTestSucceeded: True`, confirming that the forwarders could reach the Splunk server on the new subnet.

### Splunk License and Ingestion Validation

During validation, Splunk Web was reachable at:

```text
http://192.168.50.10:8000
```

The installed Developer license had expired, which confirmed that the issue was related to Splunk licensing rather than firewall routing, DNS, or subnet migration.

<img width="749" height="420" alt="Splunk GUI reachable but license expired" src="https://github.com/user-attachments/assets/dc288250-2c53-4e94-9701-0731aefc8e3d" />

**Figure 12 – Splunk Web reachable but Developer license expired**

After applying a renewed Splunk Developer license, Splunk search access was restored. Fresh events from both `ADDC01` and `TARGET-PC` were then visible in Splunk, confirming that post-migration event ingestion was working after the subnet migration and forwarder updates.

---

## Routed Attacker Subnet Extension

After the initial pfSense migration, Kali and Splunk were still on the same `192.168.50.0/24` subnet. Testing showed that a pfSense LAN rule could not block Kali from reaching Splunk Web because same-subnet traffic did not traverse pfSense.

This created an important design lesson:

```text
A firewall can only enforce traffic that traverses it.
```

To resolve this, Kali was moved to a dedicated routed attacker subnet.

### Final Segmented Addressing

| Host | Role | Current Subnet | Current IP | Gateway | DNS |
|---|---|---|---:|---:|---:|
| pfSense LAN | Main lab gateway | `192.168.50.0/24` | `192.168.50.1` | N/A | N/A |
| pfSense ATTACK_NET | Attacker subnet gateway | `192.168.60.0/24` | `192.168.60.1` | N/A | N/A |
| Splunk | SIEM | `192.168.50.0/24` | `192.168.50.10` | `192.168.50.1` | `192.168.50.20` |
| ADDC01 | Domain Controller / DNS | `192.168.50.0/24` | `192.168.50.20` | `192.168.50.1` | `127.0.0.1` |
| Target-PC | Windows Client | `192.168.50.0/24` | `192.168.50.110` | `192.168.50.1` | `192.168.50.20` |
| Kali | Attack Host | `192.168.60.0/24` | `192.168.60.100` | `192.168.60.1` | DHCP |

### ATTACK_NET Validation

The `ATTACK_NET` interface was configured as `192.168.60.1/24`, with DHCP issuing addresses from `192.168.60.100` to `192.168.60.199`.

Kali received `192.168.60.100/24` and used `192.168.60.1` as its default gateway. Routing from Kali to the main lab subnet was validated through pfSense.

Detailed configuration screenshots and validation evidence are documented in:

- [`firewall-rule-testing.md`](./firewall-rule-testing.md)
- [`firewall-rule-policy-state.md`](./firewall-rule-policy-state.md)

---

## Firewall Rule Validation Summary

With Kali moved to `ATTACK_NET`, pfSense was able to enforce routed firewall rules between the attacker subnet and the main lab subnet.

Validated restrictions include:

| Source | Destination | Port | Result |
|---|---|---:|---|
| ATTACK_NET | Splunk `192.168.50.10` | TCP `8000` | Blocked |
| ATTACK_NET | Splunk `192.168.50.10` | TCP `9997` | Blocked |
| ATTACK_NET | ADDC01 `192.168.50.20` | TCP `389` | Blocked |
| ATTACK_NET | ADDC01 `192.168.50.20` | TCP `445` | Blocked |

The following paths remain available for controlled testing:

| Source | Destination | Port | Status |
|---|---|---:|---|
| ATTACK_NET | ADDC01 `192.168.50.20` | TCP `53` | Allowed |
| ATTACK_NET | ADDC01 `192.168.50.20` | TCP `88` | Allowed |
| ATTACK_NET | Splunk `192.168.50.10` | ICMP | Allowed |
| ATTACK_NET | ADDC01 `192.168.50.20` | ICMP | Allowed |

Splunk ingestion from ADDC01 and TARGET-PC remained functional after each firewall rule change.

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

Splunk Web then showed that the Developer license had expired. This was treated as a separate application licensing issue, not a firewall or routing issue. After the renewed Developer license was applied, search access was restored and event ingestion from both Windows hosts was validated.

### Same-subnet firewall limitation

The first attempt to block Kali access to Splunk Web did not work while Kali and Splunk were both on `192.168.50.0/24`.

This happened because the traffic stayed within the same Layer 2 subnet and did not route through pfSense. Moving Kali to `ATTACK_NET` resolved this limitation and allowed pfSense to enforce traffic between Kali and the main lab subnet.

---

## Security Outcome

Adding pfSense improved the lab in several ways:

- introduced a proper firewall boundary
- introduced planned static addressing for core infrastructure systems
- replaced the original flat network design with routed lab subnets
- established pfSense as the gateway for both main lab and attacker networks
- enabled firewall enforcement between Kali and infrastructure systems
- validated that attacker traffic to Splunk and Domain Controller services can be restricted
- confirmed that Splunk ingestion still works after firewall rule changes
- improved the realism of the environment from a blue-team and detection engineering perspective

This change supports security testing such as:

- restricting Kali traffic to approved targets
- limiting direct access to Splunk management and receiving services
- limiting direct access to high-value Domain Controller services
- validating segmentation controls without breaking identity telemetry
- moving toward explicit allow rules and default deny behaviour

---

## Next Steps

The firewall deployment, host migration, Splunk forwarder update, post-migration ingestion validation, routed attacker subnet creation, and initial firewall rule testing have been completed.

The next planned steps are:

1. replace the temporary `ATTACK_NET` allow rule with explicit allow rules
2. add default deny behaviour for unmatched `ATTACK_NET` traffic
3. validate that DNS, Kerberos, ICMP testing, and Splunk ingestion still work
4. update firewall documentation after final least-privilege testing

---

## Summary

This change moved the lab away from a flat virtual network and introduced a dedicated firewall boundary using pfSense. The deployment was kept lightweight to fit within the available host resources while still providing a meaningful security improvement.

The migration was validated by placing Kali behind the new firewall, confirming DHCP lease assignment, routing, and internet access through pfSense.

The migration was then extended to the Domain Controller, Windows client, and Splunk server. Splunk Universal Forwarder outputs were updated to use `192.168.50.10:9997`, and post-migration ingestion was validated from both Windows hosts.

The segmentation design was then improved by moving Kali to the dedicated `192.168.60.0/24` `ATTACK_NET` subnet. This allowed pfSense to enforce routed firewall rules against Splunk Web, the Splunk receiving port, Domain Controller LDAP, and Domain Controller SMB while preserving controlled DNS, Kerberos, ICMP, and trusted log forwarding paths.
