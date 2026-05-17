# 🧱 ATTACK_NET Firewall Policy State

## Objective

This document summarises the current pfSense `ATTACK_NET` firewall policy after completing routed firewall rule testing in the Identity Security lab.

It records the active restrictions, retained testing paths, and the next recommended hardening decision for the attacker subnet.

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

---

## Retained Testing Paths

| Source | Destination | Port | Status | Reason |
|---|---|---:|---|---|
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `53` | Allowed | DNS testing and name resolution validation |
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `88` | Allowed | Controlled Kerberos authentication testing |
| ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | ICMP | Allowed | Basic routing validation |
| ATTACK_NET subnets | ADDC01 `192.168.50.20` | ICMP | Allowed | Basic routing validation |

---

## Temporary Allow Rule

A broad temporary allow rule remains below the explicit block rules:

```text
Pass | Source: ATTACK_NET subnets | Destination: any | Protocol: IPv4 any
```

This rule is useful while the lab is still in testing mode because it allows new traffic flows to be measured before more restrictive policy is added.

This is not the final least-privilege design.

---

## Current Security Interpretation

The current policy proves that pfSense can enforce routed segmentation between the attacker subnet and the main lab subnet.

The policy now blocks direct ATTACK_NET access to:

- Splunk Web
- Splunk receiving port
- Domain Controller LDAP
- Domain Controller SMB

At the same time, it keeps selected paths available for testing:

- DNS
- Kerberos
- ICMP routing validation

This gives the lab a practical balance between segmentation and controlled identity testing.

---

## Next Hardening Decision

The next decision is whether to keep `ATTACK_NET` in testing mode or move it closer to least privilege.

| Option | Description | Best Use |
|---|---|---|
| Keep temporary allow rule | Continue testing one traffic flow at a time | Best while adding more detections and validations |
| Replace with explicit allow rules | Allow only required DNS, Kerberos, ICMP, and selected lab traffic | Best when converting this into a final segmented design |
| Add default deny rule | Block all unmatched `ATTACK_NET` traffic after explicit allows | Best for final policy validation |

For the current project stage, keeping the temporary allow rule is acceptable because firewall behaviour is still being measured and documented.

The final hardening phase should replace it with explicit allow rules and default deny behaviour.

---

## Recommended Final ATTACK_NET Rule Model

A future final policy could use this model:

| Order | Action | Source | Destination | Port | Purpose |
|---:|---|---|---|---:|---|
| 1 | Pass | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `53` | DNS testing |
| 2 | Pass | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `88` | Kerberos testing |
| 3 | Pass | ATTACK_NET subnets | ADDC01 `192.168.50.20` | ICMP | Routing validation |
| 4 | Pass | ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | ICMP | Routing validation |
| 5 | Block | ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | TCP `8000` | Block Splunk Web |
| 6 | Block | ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | TCP `9997` | Block Splunk receiving port |
| 7 | Block | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `389` | Block LDAP |
| 8 | Block | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP `445` | Block SMB |
| 9 | Block | ATTACK_NET subnets | Any | Any | Default deny |

The final order may change depending on later lab requirements, but the main goal is clear: move from broad testing access to explicit allowed traffic.

---

## Status

ATTACK_NET segmentation is operational. Splunk Web, Splunk receiving, Domain Controller LDAP, and Domain Controller SMB are blocked from the attacker subnet. DNS and Kerberos remain available for controlled testing. The temporary allow rule remains in place pending final least-privilege hardening.
