# 🧱 pfSense Firewall Rule Testing

## Objective

This document will track the next phase of the Identity Security lab network segmentation work.

After migrating the lab from the original flat `192.168.10.0/24` network to the pfSense-backed `192.168.50.0/24` subnet, the next step is to define and test firewall rules between attacker, endpoint, and infrastructure systems.

The goal is to move beyond basic network migration and validate that pfSense can enforce controlled traffic flows while still allowing required identity telemetry to reach Splunk.

---

## Scope

This testing phase will focus on traffic between the following systems:

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

Before applying restrictive firewall rules, baseline connectivity will be captured to show the starting state of the network.

### Planned Tests

| Source | Destination | Test | Expected Result |
|---|---|---|---|
| Kali | pfSense | ICMP | To be tested |
| Kali | ADDC01 | ICMP / SMB / Kerberos | To be tested |
| Kali | TARGET-PC | ICMP / SMB | To be tested |
| Kali | SPLUNK01 | TCP `8000` / TCP `9997` | To be tested |
| TARGET-PC | ADDC01 | DNS / Kerberos / LDAP / SMB | To be tested |
| ADDC01 | SPLUNK01 | TCP `9997` | To be tested |
| TARGET-PC | SPLUNK01 | TCP `9997` | To be tested |

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

## Evidence

Screenshots and validation outputs will be added as testing progresses.

### Figure Placeholders

- **Figure 1 – Baseline pfSense LAN rule configuration**
- **Figure 2 – Baseline connectivity from Kali**
- **Figure 3 – Allow rule for required Windows client to Domain Controller traffic**
- **Figure 4 – Block rule preventing Kali access to Splunk Web**
- **Figure 5 – Failed connection test from Kali to blocked service**
- **Figure 6 – Post-rule Splunk ingestion validation from ADDC01 and TARGET-PC**

---

## Testing Notes

Testing notes will be added during implementation.

---

## Security Outcome

This phase will demonstrate that the lab network can move from basic routing behind pfSense to controlled firewall policy enforcement.

The expected outcome is a segmented lab where required identity services and Splunk telemetry continue to function, while unnecessary attacker access to infrastructure systems is reduced.

---

## Status

Planned. Firewall rule testing has not yet started.
