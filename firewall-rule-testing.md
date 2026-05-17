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
| pfSense | Firewall / Gateway | `192.168.50.1` / `192.168.60.1` |
| ADDC01 | Domain Controller / DNS | `192.168.50.20` |
| TARGET-PC | Windows Client | `192.168.50.110` |
| SPLUNK01 | SIEM | `192.168.50.10` |
| Kali | Attack Host | Baseline: `192.168.50.100` / Segmented: `192.168.60.100` |

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

## Routed Attacker Subnet Implementation

To resolve the same-subnet limitation, Kali was moved onto a dedicated attacker subnet using a new pfSense OPT interface.

### ATTACK_NET Interface Design

| Component | Value |
|---|---|
| pfSense interface | `ATTACK_NET` / `em2` |
| pfSense interface IP | `192.168.60.1/24` |
| Attacker subnet | `192.168.60.0/24` |
| Kali IP | `192.168.60.100/24` |
| Kali gateway | `192.168.60.1` |
| Main lab subnet | `192.168.50.0/24` |

### pfSense OPT Interface Assignment

A third adapter was added to the pfSense VM in VirtualBox and assigned as `OPT1` in pfSense. This interface was then renamed to `ATTACK_NET`.

<img width="958" height="303" alt="pfSense OPT interface created for Kali subnet" src="https://github.com/user-attachments/assets/2eb470ee-2aba-4222-b74c-ce98b18b31b4" />

**Figure 9 – pfSense OPT interface created for Kali subnet**

### ATTACK_NET Interface Configuration

The `ATTACK_NET` interface was configured with a static IPv4 address of `192.168.60.1/24`.

<img width="949" height="934" alt="pfSense ATTACK_NET interface configured" src="https://github.com/user-attachments/assets/e2c4ebdd-5617-4082-bd23-34b7d8358afa" />

**Figure 10 – pfSense ATTACK_NET interface configured**

### ATTACK_NET DHCP Scope

DHCP was enabled on the `ATTACK_NET` interface so Kali could receive an address automatically.

| Setting | Value |
|---|---|
| Subnet | `192.168.60.0/24` |
| DHCP range start | `192.168.60.100` |
| DHCP range end | `192.168.60.199` |

<img width="954" height="977" alt="DHCP scope configured for the ATTACK_NET subnet" src="https://github.com/user-attachments/assets/5fb5e271-14be-4d78-a4a5-00ef16bbcdd8" />

**Figure 11 – DHCP scope configured for the ATTACK_NET subnet**

### Kali Migration to ATTACK_NET

Kali was moved from the main `LAB_LAN` network to the new `ATTACK_NET` VirtualBox internal network.

After the change, Kali received the following configuration:

| Item | Result |
|---|---|
| Interface | `eth0` |
| IP address | `192.168.60.100/24` |
| Default gateway | `192.168.60.1` |
| Route | `192.168.60.0/24` via `eth0` |

<img width="798" height="309" alt="Kali moved to the dedicated attacker subnet" src="https://github.com/user-attachments/assets/b9225e26-0725-44f8-a4fb-c14a7f0968cb" />

**Figure 12 – Kali moved to the dedicated attacker subnet**

### Temporary ATTACK_NET Validation Rule

A temporary allow rule was added on the `ATTACK_NET` interface to validate routing before creating restrictive firewall rules.

| Field | Value |
|---|---|
| Action | Pass |
| Interface | ATTACK_NET |
| Protocol | IPv4 any |
| Source | ATTACK_NET subnets |
| Destination | Any |
| Description | Temporary allow ATTACK_NET to any for validation |

<img width="947" height="264" alt="Temporary allow rule for ATTACK_NET validation" src="https://github.com/user-attachments/assets/ca59640c-e708-4a14-807e-65ea8d8b21f6" />

**Figure 13 – Temporary allow rule for ATTACK_NET validation**

### Kali Gateway Validation

After adding the temporary allow rule, Kali successfully reached the pfSense `ATTACK_NET` gateway at `192.168.60.1`.

<img width="502" height="180" alt="Kali reaching the pfSense ATTACK_NET gateway" src="https://github.com/user-attachments/assets/37a19e7c-28ae-46e7-9559-e6c1abdec262" />

**Figure 14 – Kali reaching the pfSense ATTACK_NET gateway**

### Routed Access to Main Lab Subnet

Kali was then tested against Splunk on the main lab subnet.

```bash
ping -c 4 192.168.50.10
```

The test succeeded, confirming that Kali could route from `192.168.60.0/24` to `192.168.50.0/24` through pfSense.

<img width="500" height="182" alt="Kali routing from ATTACK_NET to the main lab subnet" src="https://github.com/user-attachments/assets/ca7dcdd6-d32a-42ea-b7b2-85be940bfcce" />

**Figure 15 – Kali routing from ATTACK_NET to the main lab subnet**

---

## Routed Firewall Rule Test

### Test 2 – Block ATTACK_NET Access to Splunk Web

Before adding the block rule, Kali was tested against Splunk Web across the routed subnets.

```bash
nc -vz 192.168.50.10 8000
```

The port was open, confirming that the temporary validation rule allowed routed access from `ATTACK_NET` to Splunk Web.

<img width="443" height="69" alt="Kali baseline access to Splunk Web across routed subnets" src="https://github.com/user-attachments/assets/6f1db23d-4c5c-4bda-a1de-6af58789bb66" />

**Figure 16 – Kali baseline access to Splunk Web across routed subnets**

A new block rule was then added on the `ATTACK_NET` interface above the temporary allow rule.

| Field | Value |
|---|---|
| Action | Block |
| Interface | ATTACK_NET |
| Protocol | IPv4 TCP |
| Source | ATTACK_NET subnets |
| Destination | `192.168.50.10` |
| Destination Port | `8000` |
| Description | Block ATTACK_NET access to Splunk Web |

<img width="953" height="339" alt="pfSense rule blocking ATTACK_NET access to Splunk Web" src="https://github.com/user-attachments/assets/728fdf64-acef-4f2f-8aaf-f3e151494ae4" />

**Figure 17 – pfSense rule blocking ATTACK_NET access to Splunk Web**

After applying the rule, Kali was no longer able to connect to Splunk Web on TCP `8000`.

```bash
nc -vz 192.168.50.10 8000
```

The connection timed out, confirming that pfSense was now enforcing the block because the traffic traversed routed subnets.

<img width="458" height="68" alt="Kali blocked from accessing Splunk Web across routed subnets" src="https://github.com/user-attachments/assets/5b108256-b8cc-4984-a800-8e588c0050ed" />

**Figure 18 – Kali blocked from accessing Splunk Web across routed subnets**

### Scoped Rule Validation

Additional testing confirmed that the block rule only affected Splunk Web access and did not break general routing or the Splunk receiving port.

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | ICMP ping | Successful |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `9997` | Open |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `8000` | Blocked |

<img width="499" height="261" alt="Kali routing and Splunk receiving port remain available after Splunk Web block" src="https://github.com/user-attachments/assets/1ebc70e2-c6c7-458a-9d52-355eb2aff734" />

**Figure 19 – Kali routing and Splunk receiving port remain available after Splunk Web block**

### Splunk Ingestion Validation After Firewall Rule

Splunk ingestion was validated after blocking attacker subnet access to Splunk Web.

```spl
index=identity host=ADDC01 OR host=TARGET-PC earliest=-30m
| stats count by host sourcetype
```

Fresh events were still visible from both Windows hosts.

| Host | Sourcetype | Result |
|---|---|---|
| ADDC01 | `WinEventLog` | Events received |
| ADDC01 | `WinEventLog:SecurityAll` | Events received |
| TARGET-PC | `WinEventLog` | Events received |

This confirmed that blocking attacker subnet access to Splunk Web did not affect Windows log forwarding to Splunk.

<img width="1047" height="350" alt="Splunk ingestion validated after blocking attacker subnet access to Splunk Web" src="https://github.com/user-attachments/assets/4a3f6062-576a-44db-96cf-bd3adb878340" />

**Figure 20 – Splunk ingestion validated after blocking attacker subnet access to Splunk Web**

### Test 3 – Block ATTACK_NET Access to Splunk Receiving Port

After confirming that Splunk Web access could be blocked across routed subnets, the next restriction focused on the Splunk receiving port, TCP `9997`.

This port is required for trusted Splunk Universal Forwarders on `ADDC01` and `TARGET-PC`, but it is not required from the attacker subnet. Blocking this path reduces unnecessary attacker access to SIEM infrastructure while preserving required log ingestion from trusted systems.

Before adding the new block rule, Kali was tested against the Splunk receiving port across the routed subnets.

```bash
nc -vz 192.168.50.10 9997
ping -c 4 192.168.50.10
```

The TCP `9997` test succeeded and ICMP ping also succeeded, confirming that Kali could still reach the Splunk receiving port before the restriction was applied.

<img width="502" height="261" alt="Kali baseline splunk receiving port" src="https://github.com/user-attachments/assets/280afb70-c133-4ff5-8b07-1445e798a094" />

**Figure 21 – Kali baseline access to the Splunk receiving port before ATTACK_NET restriction**

A new block rule was then added on the `ATTACK_NET` interface above the temporary allow rule.

| Field | Value |
|---|---|
| Action | Block |
| Interface | ATTACK_NET |
| Protocol | IPv4 TCP |
| Source | ATTACK_NET subnets |
| Destination | `192.168.50.10` |
| Destination Port | `9997` |
| Description | Block ATTACK_NET access to Splunk receiving port |

<img width="952" height="391" alt="pfSense block ATTACK_NET Splunk receiving port" src="https://github.com/user-attachments/assets/1251f4d4-cd69-461c-a03f-1730e02ef60c" />

**Figure 22 – pfSense rule blocking ATTACK_NET access to the Splunk receiving port**

After applying the rule and resetting pfSense states, Kali was tested again against Splunk TCP `9997`, Splunk TCP `8000`, and ICMP.

```bash
nc -vz 192.168.50.10 9997
ping -c 4 192.168.50.10
nc -vz 192.168.50.10 8000
```

The tests confirmed that both Splunk Web and the Splunk receiving port were blocked from `ATTACK_NET`, while ICMP routing to Splunk remained available.

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `9997` | Blocked |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | ICMP ping | Successful |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `8000` | Blocked |

<img width="501" height="278" alt="Kali blocked Splunk web and receiving port" src="https://github.com/user-attachments/assets/9733254f-5bac-40ab-84b3-28430f57071f" />

**Figure 23 – Kali blocked from Splunk Web and the Splunk receiving port while routing remains available**

### Splunk Ingestion Validation After Splunk Receiving Port Block

Splunk ingestion was validated after blocking attacker subnet access to the Splunk receiving port.

```spl
index=identity host=ADDC01 OR host=TARGET-PC earliest=-30m
| stats count by host sourcetype
```

Fresh events were still visible from both Windows hosts.

| Host | Sourcetype | Count |
|---|---|---:|
| ADDC01 | `WinEventLog` | 31 |
| ADDC01 | `WinEventLog:SecurityAll` | 113 |
| TARGET-PC | `WinEventLog` | 73 |

This confirmed that blocking `ATTACK_NET` access to TCP `9997` did not affect trusted Windows log forwarding from the main lab subnet.

<img width="1027" height="363" alt="Splunk ingestion after ATTACK_NET Splunk receiving port block" src="https://github.com/user-attachments/assets/c106d204-1689-492e-b81b-537d01f3462e" />

**Figure 24 – Splunk ingestion validated after blocking ATTACK_NET access to the Splunk receiving port**

### Test 4 – Restrict ATTACK_NET Access to Domain Controller LDAP and SMB

After restricting attacker subnet access to Splunk Web and the Splunk receiving port, the next control focused on direct access from `ATTACK_NET` to Domain Controller services.

The goal of this test was to reduce unnecessary attacker access to high-value Domain Controller services while keeping selected identity testing paths available. DNS TCP `53` and Kerberos TCP `88` were left reachable for controlled identity testing. LDAP TCP `389` and SMB TCP `445` were selected for restriction because they can support enumeration and lateral movement activity.

Before adding the new block rules, Kali was tested against the Domain Controller from the routed attacker subnet.

```bash
ping -c 4 192.168.50.20
nc -vz 192.168.50.20 53
nc -vz 192.168.50.20 88
nc -vz 192.168.50.20 389
nc -vz 192.168.50.20 445
```

The baseline showed that Kali could reach the Domain Controller over ICMP, DNS, Kerberos, LDAP, and SMB.

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | ICMP ping | Successful |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `53` DNS | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `88` Kerberos | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `389` LDAP | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `445` SMB | Open |

<img width="502" height="371" alt="Kali baseline domain controller access from ATTACK_NET" src="https://github.com/user-attachments/assets/93cd18a6-79ce-49b4-b5af-f23ca9c8088b" />

**Figure 25 – Kali baseline access to Domain Controller services from ATTACK_NET**

Two new block rules were then added on the `ATTACK_NET` interface above the temporary allow rule.

| Field | LDAP Rule Value | SMB Rule Value |
|---|---|---|
| Action | Block | Block |
| Interface | ATTACK_NET | ATTACK_NET |
| Protocol | IPv4 TCP | IPv4 TCP |
| Source | ATTACK_NET subnets | ATTACK_NET subnets |
| Destination | `192.168.50.20` | `192.168.50.20` |
| Destination Port | `389` | `445` |
| Description | Block ATTACK_NET access to Domain Controller LDAP | Block ATTACK_NET access to Domain Controller SMB |

<img width="951" height="358" alt="pfSense block ATTACK_NET domain controller ldap and smb" src="https://github.com/user-attachments/assets/28bb140e-031c-4a38-87f1-91fad937aa50" />

**Figure 26 – pfSense rules blocking ATTACK_NET access to Domain Controller LDAP and SMB**

After applying the rules and resetting pfSense states, Kali was tested again against the Domain Controller.

```bash
ping -c 4 192.168.50.20
nc -vz 192.168.50.20 53
nc -vz 192.168.50.20 88
nc -vz 192.168.50.20 389
nc -vz 192.168.50.20 445
```

The tests confirmed that LDAP and SMB were blocked from `ATTACK_NET`, while ICMP, DNS, and Kerberos remained available.

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | ICMP ping | Successful |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `53` DNS | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `88` Kerberos | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `389` LDAP | Blocked |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `445` SMB | Blocked |

<img width="541" height="376" alt="Kali blocked domain-controller ldap and smb" src="https://github.com/user-attachments/assets/f12a59c8-22da-4ce9-b7cd-c46b1a71bd64" />

**Figure 27 – Kali blocked from Domain Controller LDAP and SMB while DNS and Kerberos remain available**

### Splunk Ingestion Validation After Domain Controller LDAP and SMB Block

Splunk ingestion was validated after blocking attacker subnet access to Domain Controller LDAP and SMB.

```spl
index=identity host=ADDC01 OR host=TARGET-PC earliest=-30m
| stats count by host sourcetype
```

Fresh events were still visible from both Windows hosts.

| Host | Sourcetype | Count |
|---|---|---:|
| ADDC01 | `WinEventLog` | 171 |
| ADDC01 | `WinEventLog:SecurityAll` | 209 |
| TARGET-PC | `WinEventLog` | 255 |

This confirmed that blocking `ATTACK_NET` access to Domain Controller LDAP and SMB did not affect trusted Windows log forwarding from the main lab subnet.

<img width="1046" height="358" alt="Splunk ingestion after domain controller ldap and smb block" src="https://github.com/user-attachments/assets/0e2b4642-cebc-44cd-b726-fba57aacfe24" />

**Figure 28 – Splunk ingestion validated after blocking ATTACK_NET access to Domain Controller LDAP and SMB**

### Test 5 – Validate Blocked Enumeration Paths from ATTACK_NET

After blocking direct `ATTACK_NET` access to Splunk and initial Domain Controller services, Kali tooling was used to validate the controls from an attacker-subnet perspective.

The purpose of this test was to confirm that common enumeration paths were blocked, while selected identity testing paths remained available.

#### Nmap Service Validation

Kali first ran an `nmap` scan against the Domain Controller for DNS, Kerberos, LDAP, and SMB.

```bash
nmap -Pn -p 53,88,389,445 192.168.50.20
```

The results confirmed that DNS and Kerberos remained open, while LDAP and SMB were filtered.

| Source | Destination | Port | Result |
|---|---|---:|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `53` | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `88` | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `389` | Filtered |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `445` | Filtered |

<img width="PLACEHOLDER" height="PLACEHOLDER" alt="Nmap validation of allowed and blocked Domain Controller services from ATTACK_NET" src="PLACEHOLDER" />

**Figure 29 – Nmap validation of allowed and blocked Domain Controller services from ATTACK_NET**

#### LDAP Query Validation

Kali then attempted a basic unauthenticated LDAP query against the Domain Controller.

```bash
ldapsearch -x -H ldap://192.168.50.20 -o nettimeout=5 -s base
```

The query failed with the following result:

```text
ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)
ldapsearch exit code: 255
```

This confirmed that LDAP queries from `ATTACK_NET` could not reach the Domain Controller over TCP `389`.

<img width="PLACEHOLDER" height="PLACEHOLDER" alt="ldapsearch blocked from querying Domain Controller LDAP from ATTACK_NET" src="PLACEHOLDER" />

**Figure 30 – ldapsearch blocked from querying Domain Controller LDAP from ATTACK_NET**

#### enum4linux-ng Enumeration Validation

Kali then used `enum4linux-ng` to perform a broader enumeration check against the Domain Controller.

The condensed output showed that LDAP TCP `389` and SMB TCP `445` were blocked, but it also identified two additional exposed services:

| Service | Port | Result |
|---|---:|---|
| LDAP | TCP `389` | Timed out |
| LDAPS | TCP `636` | Accessible |
| SMB | TCP `445` | Timed out |
| SMB over NetBIOS | TCP `139` | Accessible |
| SMB sessions | N/A | Failed |

This was a useful finding because the first Domain Controller restrictions only blocked LDAP TCP `389` and SMB TCP `445`. The enumeration test showed that LDAPS and NetBIOS also needed to be considered.

<img width="PLACEHOLDER" height="PLACEHOLDER" alt="enum4linux-ng validation showing blocked LDAP and SMB with additional exposed LDAPS and NetBIOS paths" src="PLACEHOLDER" />

**Figure 31 – enum4linux-ng validation showing blocked LDAP and SMB with additional exposed LDAPS and NetBIOS paths**

#### Additional Service Exposure Validation

A focused `nmap` scan confirmed the additional exposed services.

```bash
nmap -Pn -p 139,636 192.168.50.20
```

| Source | Destination | Port | Result |
|---|---|---:|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `139` | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `636` | Open |

<img width="PLACEHOLDER" height="PLACEHOLDER" alt="Nmap validation of additional Domain Controller services exposed to ATTACK_NET" src="PLACEHOLDER" />

**Figure 32 – Nmap validation of additional Domain Controller services exposed to ATTACK_NET**

#### Additional pfSense Block Rules

Two new block rules were added to the `ATTACK_NET` interface above the temporary allow rule.

| Field | LDAPS Rule Value | NetBIOS Rule Value |
|---|---|---|
| Action | Block | Block |
| Interface | ATTACK_NET | ATTACK_NET |
| Protocol | IPv4 TCP | IPv4 TCP |
| Source | ATTACK_NET subnets | ATTACK_NET subnets |
| Destination | `192.168.50.20` | `192.168.50.20` |
| Destination Port | `636` | `139` |
| Description | Block ATTACK_NET access to Domain Controller LDAPS | Block ATTACK_NET access to Domain Controller NetBIOS |

<img width="PLACEHOLDER" height="PLACEHOLDER" alt="pfSense rules blocking ATTACK_NET access to Domain Controller LDAPS and NetBIOS" src="PLACEHOLDER" />

**Figure 33 – pfSense rules blocking ATTACK_NET access to Domain Controller LDAPS and NetBIOS**

#### Post-Rule Enumeration Service Validation

After applying the LDAPS and NetBIOS restrictions and resetting pfSense states, Kali repeated the `nmap` scan against Domain Controller enumeration services.

```bash
nmap -Pn -p 139,389,445,636 192.168.50.20
```

The scan confirmed that NetBIOS, LDAP, SMB, and LDAPS were now filtered from `ATTACK_NET`.

| Source | Destination | Port | Result |
|---|---|---:|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `139` | Filtered |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `389` | Filtered |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `445` | Filtered |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `636` | Filtered |

<img width="PLACEHOLDER" height="PLACEHOLDER" alt="Nmap validation showing Domain Controller LDAP LDAPS SMB and NetBIOS filtered from ATTACK_NET" src="PLACEHOLDER" />

**Figure 34 – Nmap validation showing Domain Controller LDAP, LDAPS, SMB, and NetBIOS filtered from ATTACK_NET**

A follow-up `enum4linux-ng` validation was attempted after the additional block rules were applied. The tool could not complete useful enumeration because the relevant services were filtered and the process was terminated after repeated timeouts.

<img width="PLACEHOLDER" height="PLACEHOLDER" alt="enum4linux-ng blocked from completing Domain Controller enumeration after additional ATTACK_NET restrictions" src="PLACEHOLDER" />

**Figure 35 – enum4linux-ng blocked from completing Domain Controller enumeration after additional ATTACK_NET restrictions**

#### Allowed Identity Testing Paths

After blocking additional enumeration paths, DNS and Kerberos were tested again from Kali.

```bash
nmap -Pn -p 53,88 192.168.50.20
```

The scan confirmed that DNS and Kerberos remained open from `ATTACK_NET`.

| Source | Destination | Port | Result |
|---|---|---:|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `53` | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `88` | Open |

<img width="PLACEHOLDER" height="PLACEHOLDER" alt="Nmap validation showing DNS and Kerberos remain available from ATTACK_NET" src="PLACEHOLDER" />

**Figure 36 – Nmap validation showing DNS and Kerberos remain available from ATTACK_NET**

### Splunk Ingestion Validation After Additional Domain Controller Restrictions

Splunk ingestion was validated after adding the LDAPS and NetBIOS restrictions.

```spl
index=identity host=ADDC01 OR host=TARGET-PC earliest=-30m
| stats count by host sourcetype
```

Fresh events were still visible from both Windows hosts.

| Host | Sourcetype | Count |
|---|---|---:|
| ADDC01 | `WinEventLog` | 32 |
| ADDC01 | `WinEventLog:SecurityAll` | 166 |
| TARGET-PC | `WinEventLog` | 235 |

This confirmed that blocking additional Domain Controller enumeration services from `ATTACK_NET` did not affect trusted Windows log forwarding from the main lab subnet.

<img width="PLACEHOLDER" height="PLACEHOLDER" alt="Splunk ingestion validated after blocking additional Domain Controller enumeration services from ATTACK_NET" src="PLACEHOLDER" />

**Figure 37 – Splunk ingestion validated after blocking additional Domain Controller enumeration services from ATTACK_NET**

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
- The connection remained open because Kali and Splunk were on the same `192.168.50.0/24` subnet.
- Same-subnet traffic did not traverse pfSense, so pfSense could not enforce host-to-host restrictions in that topology.
- Kali was moved to a separate `192.168.60.0/24` attacker subnet using the pfSense `ATTACK_NET` interface.
- After moving Kali to a routed subnet, pfSense successfully blocked Kali from accessing Splunk Web on TCP `8000`.
- A second ATTACK_NET block rule was added for Splunk TCP `9997`.
- After applying the TCP `9997` block, Kali could no longer reach Splunk Web or the Splunk receiving port, while ICMP routing to Splunk remained available.
- Baseline testing from `ATTACK_NET` showed that Kali could reach ADDC01 over DNS, Kerberos, LDAP, and SMB.
- Two additional ATTACK_NET block rules were added for Domain Controller LDAP TCP `389` and SMB TCP `445`.
- After applying the Domain Controller restrictions, Kali could still reach ADDC01 over ICMP, DNS TCP `53`, and Kerberos TCP `88`, but LDAP and SMB were blocked.
- Kali enumeration tooling later identified that LDAPS TCP `636` and NetBIOS TCP `139` were still exposed from `ATTACK_NET`.
- Additional ATTACK_NET block rules were added for Domain Controller LDAPS TCP `636` and NetBIOS TCP `139`.
- Follow-up `nmap` testing confirmed that TCP `139`, `389`, `445`, and `636` were filtered from `ATTACK_NET`.
- DNS TCP `53` and Kerberos TCP `88` remained available for controlled identity testing after the additional restrictions.
- Splunk ingestion from ADDC01 and TARGET-PC remained functional after both Splunk and Domain Controller ATTACK_NET restrictions were applied.

---

## Security Outcome

This phase demonstrates that the lab network can move from basic routing behind pfSense toward controlled firewall policy enforcement.

The initial firewall rule test showed that placing all systems behind pfSense on one subnet does not provide true host-to-host segmentation. To enforce attacker-to-infrastructure firewall rules, Kali had to be placed on a separate routed subnet so traffic traversed pfSense.

After moving Kali to the `ATTACK_NET` subnet, pfSense successfully blocked attacker access to Splunk Web while allowing required routing and Splunk log ingestion to continue. The follow-up TCP `9997` restriction further reduced unnecessary attacker access to SIEM infrastructure while preserving trusted Windows event forwarding from the main lab subnet.

Domain Controller testing then showed that Kali could reach DNS, Kerberos, LDAP, and SMB from the attacker subnet. LDAP and SMB were blocked from `ATTACK_NET` to reduce direct attacker access to high-value Domain Controller services, while DNS and Kerberos remained available for controlled identity testing.

Kali enumeration tooling then identified additional exposed Domain Controller services over LDAPS TCP `636` and NetBIOS TCP `139`. These paths were also blocked, and follow-up validation confirmed that LDAP, LDAPS, SMB, and NetBIOS were filtered from `ATTACK_NET` while DNS and Kerberos remained available.

This created a stronger foundation for future least-privilege segmentation between attacker, endpoint, and infrastructure systems.

---

## Status

Baseline testing completed. Same-subnet firewall rule limitation identified. Kali moved to a separate `ATTACK_NET` subnet. Routed firewall testing successfully blocked attacker subnet access to Splunk Web, the Splunk receiving port, Domain Controller LDAP, Domain Controller SMB, Domain Controller LDAPS, and Domain Controller NetBIOS while preserving required Splunk ingestion and controlled DNS/Kerberos testing paths.
