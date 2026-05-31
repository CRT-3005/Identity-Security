# 🧱 ATTACK_NET Firewall Policy State

## Objective

This document summarises the current pfSense `ATTACK_NET` firewall policy after completing routed firewall rule testing and least-privilege hardening in the Identity Security lab.

It records the active restrictions, retained testing paths, disabled temporary allow rule, and current security outcome for the attacker subnet.

---

## Current Network Context

| Component | Value |
|---|---|
| pfSense LAN | `192.168.50.1/24` |
| pfSense ATTACK_NET | `192.168.60.1/24` |
| Kali | `192.168.60.100/24` |
| SPLUNK01 | `192.168.50.10` |
| ADDC01 | `192.168.50.20` |
| TARGET-PC | `192.168.50.110` |

Kali now resides on a routed subnet, so traffic from `ATTACK_NET` to the main lab subnet traverses pfSense and can be filtered.

---

## Active ATTACK_NET Restrictions

| Source | Destination | Port | Action | Purpose |
|---|---|---:|---|---|
| ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | TCP `8000` | Block | Prevent ATTACK_NET access to Splunk Web |
| ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | TCP `9997` | Block | Prevent ATTACK_NET access to the Splunk receiving port |
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `389` | Block | Restrict LDAP enumeration from ATTACK_NET |
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `445` | Block | Restrict SMB access from ATTACK_NET |
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `636` | Block | Restrict LDAPS enumeration from ATTACK_NET |
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `139` | Block | Restrict NetBIOS session access from ATTACK_NET |

---

## Active ATTACK_NET Allow Rules

| Source | Destination | Port | Action | Purpose |
|---|---|---:|---|---|
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP/UDP `53` | Pass | DNS testing and name resolution validation |
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP/UDP `88` | Pass | Controlled Kerberos authentication testing |
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | ICMP | Pass | Basic routing validation to the Domain Controller |
| ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | ICMP | Pass | Basic routing validation to Splunk |

---

## Disabled Temporary Allow Rule

The previous broad temporary allow rule has now been disabled:

```text
Disabled | Pass | Source: ATTACK_NET subnets | Destination: any | Protocol: IPv4 any
```

This was the main least-privilege hardening step. `ATTACK_NET` no longer has broad access to the main lab subnet or the internet. Only explicitly approved traffic is allowed.

---

## Enumeration Validation Finding

Kali enumeration testing showed that blocking LDAP TCP `389` and SMB TCP `445` was not enough by itself.

`enum4linux-ng` identified two additional exposed Domain Controller paths from `ATTACK_NET`:

| Service | Port | Finding |
|---|---:|---|
| LDAPS | TCP `636` | Accessible from `ATTACK_NET` before the additional rule change |
| SMB over NetBIOS | TCP `139` | Accessible from `ATTACK_NET` before the additional rule change |

Follow-up `nmap` validation confirmed the additional exposure. New pfSense block rules were then added for TCP `636` and TCP `139`.

Post-rule `nmap` testing confirmed that the following Domain Controller enumeration services were filtered from `ATTACK_NET`:

| Service | Port | Final Result |
|---|---:|---|
| NetBIOS Session Service | TCP `139` | Filtered |
| LDAP | TCP `389` | Filtered |
| SMB | TCP `445` | Filtered |
| LDAPS | TCP `636` | Filtered |

DNS TCP/UDP `53` and Kerberos TCP/UDP `88` remain available for controlled identity testing.

---

## Least-Privilege Validation Results

After disabling the temporary allow rule, Kali was used to validate both approved and blocked paths.

### Allowed Traffic

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | ICMP ping | Successful |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | ICMP ping | Successful |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `53` DNS | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `88` Kerberos | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | DNS lookup for `adproject.local` | Successful |

### Blocked Traffic

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `139`, `389`, `445`, `636` | Filtered |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `8000`, `9997` | Filtered |
| Kali `192.168.60.100` | TARGET-PC `192.168.50.110` | TCP `445`, `3389` | Filtered |
| Kali `192.168.60.100` | `8.8.8.8` | ICMP ping | Blocked |
| Kali `192.168.60.100` | `github.com` | HTTPS curl | Failed / timed out |

### Splunk Ingestion

Splunk ingestion from the main lab subnet remained functional after least-privilege hardening.

| Host | Sourcetype | Result |
|---|---|---|
| ADDC01 | `WinEventLog` | Events received |
| TARGET-PC | `WinEventLog` | Events received |

---

## Current Security Interpretation

The current policy proves that pfSense can enforce routed segmentation between the attacker subnet and the main lab subnet using a least-privilege model.

The policy blocks direct ATTACK_NET access to:

- Splunk Web
- Splunk receiving port
- Domain Controller LDAP
- Domain Controller SMB
- Domain Controller LDAPS
- Domain Controller NetBIOS
- TARGET-PC SMB and RDP
- unmatched internet-bound traffic

At the same time, it keeps selected paths available for testing:

- DNS to the Domain Controller
- Kerberos to the Domain Controller
- ICMP routing validation to ADDC01 and SPLUNK01

This gives the lab a stronger segmented design while preserving controlled identity testing and trusted log forwarding.

---

## Current ATTACK_NET Rule Model

The current least-privilege policy uses this model:

| Order | Action | Source | Destination | Port | Purpose |
|---:|---|---|---|---:|---|
| 1 | Block | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `139` | Block NetBIOS |
| 2 | Block | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `636` | Block LDAPS |
| 3 | Block | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `445` | Block SMB |
| 4 | Block | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `389` | Block LDAP |
| 5 | Block | ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | TCP `9997` | Block Splunk receiving port |
| 6 | Block | ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | TCP `8000` | Block Splunk Web |
| 7 | Pass | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP/UDP `53` | DNS testing |
| 8 | Pass | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP/UDP `88` | Kerberos testing |
| 9 | Pass | ATTACK_NET subnets | ADDC01 `192.168.50.20` | ICMP | Routing validation |
| 10 | Pass | ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | ICMP | Routing validation |
| 11 | Disabled | ATTACK_NET subnets | Any | Any | Previous temporary allow rule |

Unmatched traffic is denied because no broad pass rule remains active beneath the explicit rules.

---

## Status

ATTACK_NET segmentation is operational and has been moved from testing mode to least privilege. Splunk Web, Splunk receiving, Domain Controller LDAP, SMB, LDAPS, and NetBIOS are blocked from the attacker subnet. DNS, Kerberos, and selected ICMP validation paths remain available. The temporary allow rule has been disabled, default deny behaviour has been validated, and Splunk ingestion remains functional from the main lab subnet.
