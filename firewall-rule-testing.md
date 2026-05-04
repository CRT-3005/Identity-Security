# 🧱 pfSense Firewall Rule Testing

## Objective

This document tracks the next phase of the Identity Security lab network segmentation work.

After migrating the lab from the original flat `192.168.10.0/24` network to the pfSense-backed `192.168.50.0/24` subnet, the next step is to define and test firewall rules between attacker, endpoint, and infrastructure systems.

The goal is to move beyond basic network migration and validate that pfSense can enforce controlled traffic flows while still allowing required identity telemetry to reach Splunk.

---

## Scope

This testing phase focuses on traffic between the following systems:

| Host | Role | IP Address |
|---|---|---:|
| pfSense | Firewall / Gateway | `192.168.50.1` |
| ADDC01 | Domain Controller / DNS | `192.168.50.20` |
| TARGET-PC | Windows Client | `192.168.50.110` |
| SPLUNK01 | SIEM | `192.168.50.10` |
| Kali | Attack Host | `192.168.50.100` |

---

## Planned Rule Testing Areas

The firewall rule testing phase will document:

- baseline LAN behaviour before restrictive rules are added
- required Active Directory and DNS traffic
- Splunk forwarding traffic on TCP `9997`
- Splunk Web access on TCP `8000`
- Kali access to infrastructure systems
- blocked traffic validation
- impact of firewall rules on detection engineering and event ingestion

---

## Baseline Connectivity

Before applying restrictive firewall rules, baseline connectivity was captured to show the starting state of the network.

### Baseline pfSense LAN Rule State

The pfSense LAN interface currently includes the default permissive LAN rule:

```text
IPv4 * | Source: LAN subnets | Destination: * | Port: * | Default allow LAN to any rule
```

This means hosts on the `192.168.50.0/24` LAN subnet can communicate broadly unless blocked by host firewalls or service-level controls.

<img width="951" height="374" alt="Baseline pfSense LAN rule configuration" src="https://github.com/user-attachments/assets/96389670-d95c-4a89-8f40-4dab3eb7734c" />

**Figure 1 – Baseline pfSense LAN rule configuration**

### Kali Network Baseline

Kali received its address from pfSense DHCP and used pfSense as its default gateway.

| Item | Result |
|---|---|
| Interface | `eth0` |
| IP Address | `192.168.50.100/24` |
| Default Gateway | `192.168.50.1` |
| Address Source | DHCP |

<img width="804" height="318" alt="Kali baseline IP address and routing through pfSense" src="https://github.com/user-attachments/assets/d039383d-3d0c-4009-b1db-89ec4a8b01af" />

**Figure 2 – Kali baseline IP address and routing through pfSense**

### Kali to Splunk Baseline

Kali was tested against the Splunk server to confirm baseline access before restrictive firewall rules were added.

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.50.100` | SPLUNK01 `192.168.50.10` | ICMP ping | Successful |
| Kali `192.168.50.100` | SPLUNK01 `192.168.50.10` | TCP `8000` | Open |
| Kali `192.168.50.100` | SPLUNK01 `192.168.50.10` | TCP `9997` | Open |

This confirmed that Kali could reach both Splunk Web and the Splunk receiving port under the default permissive LAN rule.

<img width="450" height="118" alt="Kali baseline access to Splunk Web and Splunk receiving port" src="https://github.com/user-attachments/assets/0840d936-6acb-4161-ad5a-b922d5eb4860" />

**Figure 3 – Kali baseline access to Splunk Web and Splunk receiving port**

### Kali to Domain Controller Baseline

Kali was tested against the Domain Controller to identify which identity services were reachable before adding restrictive firewall rules.

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.50.100` | ADDC01 `192.168.50.20` | ICMP ping | Successful |
| Kali `192.168.50.100` | ADDC01 `192.168.50.20` | TCP `53` | Open |
| Kali `192.168.50.100` | ADDC01 `192.168.50.20` | DNS lookup for `adproject.local` | Successful |
| Kali `192.168.50.100` | ADDC01 `192.168.50.20` | TCP `88` | Open |
| Kali `192.168.50.100` | ADDC01 `192.168.50.20` | TCP `389` | Not reachable |
| Kali `192.168.50.100` | ADDC01 `192.168.50.20` | TCP `445` | Not reachable |

### Kali to Windows Client Baseline

Kali was tested against the Windows client to confirm baseline endpoint reachability.

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.50.100` | TARGET-PC `192.168.50.110` | ICMP ping | Successful |
| Kali `192.168.50.100` | TARGET-PC `192.168.50.110` | TCP `445` | Timed out |

### Windows Client to Domain Controller Baseline

The Windows client was tested against the Domain Controller to confirm required domain traffic before firewall rules were tightened.

| Source | Destination | Test | Result |
|---|---|---|---|
| TARGET-PC `192.168.50.110` | ADDC01 `192.168.50.20` | TCP `53` | Successful |
| TARGET-PC `192.168.50.110` | ADDC01 `192.168.50.20` | TCP `88` | Successful |
| TARGET-PC `192.168.50.110` | ADDC01 `192.168.50.20` | TCP `389` | Successful |
| TARGET-PC `192.168.50.110` | ADDC01 `192.168.50.20` | TCP `445` | Successful |

This confirmed that required Windows domain traffic was working before firewall rules were changed.

<img width="708" height="214" alt="Windows client baseline access to required Domain Controller services" src="https://github.com/user-attachments/assets/2cd6e893-5530-4290-be0e-2d7adab08f4a" />

**Figure 4 – Windows client baseline access to required Domain Controller services**

### Splunk Forwarding Baseline

Forwarder connectivity to Splunk was validated from both Windows hosts.

| Source | Destination | Test | Result |
|---|---|---|---|
| TARGET-PC `192.168.50.110` | SPLUNK01 `192.168.50.10` | TCP `9997` | Successful |
| ADDC01 `192.168.50.20` | SPLUNK01 `192.168.50.10` | TCP `9997` | Successful |

### Baseline Observations

The baseline tests confirmed that the lab currently operates with broad LAN-level access because of the default pfSense LAN allow rule.

Key findings:

- Kali can reach pfSense, Splunk, the Domain Controller, and the Windows client at the network layer.
- Kali can access Splunk Web on TCP `8000` and the Splunk receiving port on TCP `9997`.
- Kali can reach Domain Controller DNS on TCP `53` and Kerberos on TCP `88`.
- Kali cannot reach LDAP TCP `389` or SMB TCP `445` on the Domain Controller during baseline testing.
- Kali can ping the Windows client, but SMB TCP `445` to the client times out.
- TARGET-PC can reach required Domain Controller services including DNS, Kerberos, LDAP, and SMB.
- ADDC01 and TARGET-PC can both reach Splunk on TCP `9997` for log forwarding.

The results show that pfSense is currently permissive at the LAN level, while Windows host firewall or service behaviour already limits some inbound access to Windows systems.

---

## Splunk Ingestion Baseline

Splunk searches confirmed that fresh events were arriving from both Windows hosts before applying restrictive firewall rules.

```spl
index=identity host=ADDC01 OR host=TARGET-PC earliest=-30m
| stats count by host sourcetype
```

This confirmed fresh data from both `ADDC01` and `TARGET-PC`.

<img width="1027" height="355" alt="Baseline Splunk ingestion before firewall rule changes" src="https://github.com/user-attachments/assets/73e37ac4-bb51-4d86-a74e-7033e9e6ad5f" />

**Figure 5 – Baseline Splunk ingestion before firewall rule changes**

A second validation query confirmed fresh Windows event telemetry from `TARGET-PC`:

```spl
index=identity host=TARGET-PC earliest=-15m
| rex "<EventID>(?<EventCode>\\d+)</EventID>"
| stats count by sourcetype EventCode
| sort sourcetype EventCode
```

Observed `TARGET-PC` event codes included:

| EventCode | Count | Notes |
|---:|---:|---|
| `566` | 1 | Windows event telemetry |
| `1500` | 1 | Windows event telemetry |
| `1501` | 1 | Windows event telemetry |
| `4624` | 10 | Successful logon activity |
| `4648` | 2 | Explicit credential logon activity |
| `6013` | 2 | System uptime event |

This confirmed that event ingestion was working before firewall restrictions were introduced.

<img width="1033" height="392" alt="TARGET-PC event code validation before firewall rule changes" src="https://github.com/user-attachments/assets/e84e2db6-80f2-4d89-b89b-67f7584dc72f" />

**Figure 6 – TARGET-PC event code validation before firewall rule changes**

---

## Proposed Firewall Rule Design

The final rules will aim to preserve required lab functionality while reducing unnecessary access between systems.

### Required Traffic

| Traffic Flow | Purpose | Action |
|---|---|---|
| TARGET-PC → ADDC01 | DNS, Kerberos, LDAP, SMB, domain services | Allow |
| ADDC01 → SPLUNK01 TCP `9997` | Windows log forwarding | Allow |
| TARGET-PC → SPLUNK01 TCP `9997` | Windows log forwarding | Allow |
| Admin workstation/client → SPLUNK01 TCP `8000` | Splunk Web access | Allow or restrict |
| LAN hosts → pfSense | Gateway and DNS forwarding where required | Allow |

### Candidate Restrictions

| Traffic Flow | Reason | Action |
|---|---|---|
| Kali → SPLUNK01 TCP `8000` | Prevent attacker host from accessing Splunk Web | Block |
| Kali → SPLUNK01 TCP `9997` | Prevent unnecessary access to Splunk receiving port | Block |
| Kali → ADDC01 unnecessary services | Reduce direct attacker access to infrastructure | Restrict |
| Kali → TARGET-PC unnecessary services | Limit attack path outside controlled testing | Restrict |

---

## Initial Firewall Rule Test

### Test 1 – Block Kali Access to Splunk Web

The first firewall rule test attempted to block Kali from accessing Splunk Web on TCP `8000`.

A block rule was created on the pfSense LAN interface with the following intent:

| Field | Value |
|---|---|
| Action | Block |
| Interface | LAN |
| Protocol | IPv4 TCP |
| Source | `192.168.50.100` |
| Destination | `192.168.50.10` |
| Destination Port | `8000` |
| Description | Block Kali access to Splunk Web |

The rule was placed above the default `LAN subnets to any` allow rule.

<img width="920" height="48" alt="pfSense rule blocking Kali access to Splunk Web" src="https://github.com/user-attachments/assets/685453bc-882a-4971-834e-539ecb2eff71" />

**Figure 7 – pfSense rule blocking Kali access to Splunk Web**

After applying the rule and resetting pfSense states, Kali was still able to connect to Splunk Web on TCP `8000`.

```bash
nc -vz 192.168.50.10 8000
```

The result still showed the port as open.

<img width="450" height="74" alt="Same-subnet Kali to Splunk traffic bypassing pfSense LAN rule" src="https://github.com/user-attachments/assets/eb9c811e-00c3-486f-83c1-7db73fffafeb" />

**Figure 8 – Same-subnet Kali to Splunk traffic bypassing pfSense LAN rule**

### Test Result

The firewall rule did not block the traffic because Kali and Splunk are on the same subnet:

```text
Kali:   192.168.50.100/24
Splunk: 192.168.50.10/24
Subnet: 192.168.50.0/24
```

Since both systems are on the same Layer 2 network, Kali communicates directly with Splunk through the VirtualBox internal network. That traffic does not route through pfSense, so the pfSense LAN firewall rule does not see or enforce the connection.

### Key Finding

This test confirmed an important segmentation limitation:

```text
A firewall can only enforce traffic that traverses it.
```

Placing all systems behind pfSense on a single subnet improves gateway control and provides a foundation for segmentation, but it does not provide true host-to-host segmentation between systems on the same subnet.

To enforce Kali-to-Splunk restrictions through pfSense, Kali must be moved onto a separate routed subnet or interface, such as an OPT network.

Example future design:

```text
Kali subnet: 192.168.60.0/24
pfSense OPT1: 192.168.60.1
Kali: 192.168.60.100
```

Traffic would then traverse pfSense before reaching the main lab subnet:

```text
Kali 192.168.60.100
|
pfSense OPT1 192.168.60.1
|
pfSense LAN 192.168.50.1
|
Splunk 192.168.50.10
```

At that point, pfSense could enforce a rule such as:

```text
Block 192.168.60.100 → 192.168.50.10 TCP 8000
```

---

## Rule Testing Methodology

Each firewall rule change will be tested using a consistent process:

1. record baseline connectivity before the rule is applied
2. create or update the pfSense firewall rule
3. test allowed traffic
4. test blocked traffic
5. confirm Splunk ingestion still works
6. document the result with screenshots and notes

---

## Validation Queries

Splunk will be used to confirm that required identity telemetry still reaches the SIEM after firewall rules are applied.

```spl
index=identity host=ADDC01 OR host=TARGET-PC earliest=-30m
| stats count by host sourcetype
```

```spl
index=identity sourcetype="WinEventLog:SecurityAll" earliest=-30m
| rex "<EventID>(?<EventCode>\\d+)</EventID>"
| stats count by host EventCode
| sort host EventCode
```

---

## Testing Notes

### Baseline Testing Notes

- The pfSense LAN interface currently uses the default broad IPv4 allow rule from `LAN subnets` to any destination.
- Some Windows services were not reachable from Kali even before restrictive pfSense rules were added.
- Required domain traffic from TARGET-PC to ADDC01 was successful.
- Required Splunk forwarding traffic from ADDC01 and TARGET-PC to SPLUNK01 was successful.
- Baseline Splunk ingestion was validated before firewall rule changes.

### Firewall Rule Testing Notes

- The first pfSense rule attempted to block Kali from reaching Splunk Web on TCP `8000`.
- The rule was correctly placed above the default LAN allow rule.
- The connection remained open because Kali and Splunk are on the same `192.168.50.0/24` subnet.
- Same-subnet traffic does not traverse pfSense, so pfSense cannot enforce host-to-host restrictions in this topology.
- True attacker-to-infrastructure segmentation requires a separate routed subnet or pfSense interface for Kali.

---

## Security Outcome

This phase demonstrates that the lab network can move from basic routing behind pfSense toward controlled firewall policy enforcement.

The initial firewall rule test showed that placing all systems behind pfSense on one subnet does not provide true host-to-host segmentation. To enforce attacker-to-infrastructure firewall rules, Kali must be placed on a separate routed subnet so traffic traverses pfSense.

The expected outcome of the next phase is a segmented lab where required identity services and Splunk telemetry continue to function, while unnecessary attacker access to infrastructure systems is reduced.

---

## Status

Baseline testing completed. Initial firewall rule testing identified a same-subnet segmentation limitation. The next phase is to move Kali onto a separate routed subnet or pfSense interface before continuing restrictive firewall rule testing.
