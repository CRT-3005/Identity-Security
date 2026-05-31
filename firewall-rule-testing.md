# 🧱 pfSense Firewall Rule Testing

## Objective

This document tracks the firewall rule testing phase of the Identity Security lab.

After migrating the original flat Active Directory lab to a pfSense-backed network, the goal was to validate that pfSense could enforce controlled traffic flows between the attacker subnet, identity infrastructure, and SIEM infrastructure while preserving required Splunk ingestion.

---

## Scope

| Host | Role | IP Address |
|---|---|---:|
| pfSense | Firewall / Gateway | `192.168.50.1` / `192.168.60.1` |
| ADDC01 | Domain Controller / DNS | `192.168.50.20` |
| TARGET-PC | Windows Client | `192.168.50.110` |
| SPLUNK01 | SIEM | `192.168.50.10` |
| Kali | Attack Host | Baseline: `192.168.50.100` / Segmented: `192.168.60.100` |

---

## Planned Rule Testing Areas

The firewall rule testing phase documents:

- baseline LAN behaviour before restrictive rules were added
- required Active Directory and DNS traffic
- Splunk forwarding traffic on TCP `9997`
- Splunk Web access on TCP `8000`
- Kali access to infrastructure systems
- blocked traffic validation
- Kali enumeration tooling validation
- ATTACK_NET least-privilege hardening
- impact of firewall rules on detection engineering and event ingestion

---

## Baseline Connectivity

Before applying restrictive firewall rules, baseline connectivity was captured to show the starting state of the network.

### Baseline pfSense LAN Rule State

The pfSense LAN interface initially included the default permissive LAN rule:

```text
IPv4 * | Source: LAN subnets | Destination: * | Port: * | Default allow LAN to any rule
```

This meant hosts on the `192.168.50.0/24` LAN subnet could communicate broadly unless blocked by host firewalls or service-level controls.

<img width="951" height="374" alt="Baseline pfSense LAN rule configuration" src="https://github.com/user-attachments/assets/96389670-d95c-4a89-8f40-4dab3eb7734c" />

**Figure 1 – Baseline pfSense LAN rule configuration**

### Kali Network Baseline

Kali initially received an address from pfSense DHCP and used pfSense as its default gateway.

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

<img width="450" height="118" alt="Kali baseline access to Splunk Web and Splunk receiving port" src="https://github.com/user-attachments/assets/0840d936-6acb-4161-ad5a-b922d5eb4860" />

**Figure 3 – Kali baseline access to Splunk Web and Splunk receiving port**

### Windows Client to Domain Controller Baseline

The Windows client was tested against the Domain Controller to confirm required domain traffic before firewall rules were tightened.

| Source | Destination | Test | Result |
|---|---|---|---|
| TARGET-PC `192.168.50.110` | ADDC01 `192.168.50.20` | TCP `53` | Successful |
| TARGET-PC `192.168.50.110` | ADDC01 `192.168.50.20` | TCP `88` | Successful |
| TARGET-PC `192.168.50.110` | ADDC01 `192.168.50.20` | TCP `389` | Successful |
| TARGET-PC `192.168.50.110` | ADDC01 `192.168.50.20` | TCP `445` | Successful |

<img width="708" height="214" alt="Windows client baseline access to required Domain Controller services" src="https://github.com/user-attachments/assets/2cd6e893-5530-4290-be0e-2d7adab08f4a" />

**Figure 4 – Windows client baseline access to required Domain Controller services**

### Splunk Ingestion Baseline

Splunk searches confirmed that fresh events were arriving from both Windows hosts before applying restrictive firewall rules.

```spl
index=identity host=ADDC01 OR host=TARGET-PC earliest=-30m
| stats count by host sourcetype
```

<img width="1027" height="355" alt="Baseline Splunk ingestion before firewall rule changes" src="https://github.com/user-attachments/assets/73e37ac4-bb51-4d86-a74e-7033e9e6ad5f" />

**Figure 5 – Baseline Splunk ingestion before firewall rule changes**

A second validation query confirmed fresh Windows event telemetry from `TARGET-PC`:

```spl
index=identity host=TARGET-PC earliest=-15m
| rex "<EventID>(?<EventCode>\\d+)</EventID>"
| stats count by sourcetype EventCode
| sort sourcetype EventCode
```

<img width="1033" height="392" alt="TARGET-PC event code validation before firewall rule changes" src="https://github.com/user-attachments/assets/e84e2db6-80f2-4d89-b89b-67f7584dc72f" />

**Figure 6 – TARGET-PC event code validation before firewall rule changes**

---

## Test 1 – Block Kali Access to Splunk Web on the Same Subnet

The first firewall rule test attempted to block Kali from accessing Splunk Web on TCP `8000` while Kali and Splunk were still on the same `192.168.50.0/24` subnet.

| Field | Value |
|---|---|
| Action | Block |
| Interface | LAN |
| Protocol | IPv4 TCP |
| Source | `192.168.50.100` |
| Destination | `192.168.50.10` |
| Destination Port | `8000` |
| Description | Block Kali access to Splunk Web |

<img width="920" height="48" alt="pfSense rule blocking Kali access to Splunk Web" src="https://github.com/user-attachments/assets/685453bc-882a-4971-834e-539ecb2eff71" />

**Figure 7 – pfSense rule blocking Kali access to Splunk Web**

After applying the rule and resetting pfSense states, Kali was still able to connect to Splunk Web on TCP `8000`.

```bash
nc -vz 192.168.50.10 8000
```

<img width="450" height="74" alt="Same-subnet Kali to Splunk traffic bypassing pfSense LAN rule" src="https://github.com/user-attachments/assets/eb9c811e-00c3-486f-83c1-7db73fffafeb" />

**Figure 8 – Same-subnet Kali to Splunk traffic bypassing pfSense LAN rule**

### Test Result

The firewall rule did not block the traffic because Kali and Splunk were on the same subnet:

```text
Kali:   192.168.50.100/24
Splunk: 192.168.50.10/24
Subnet: 192.168.50.0/24
```

Since both systems were on the same Layer 2 network, Kali communicated directly with Splunk through the VirtualBox internal network. That traffic did not route through pfSense, so the firewall rule could not enforce the block.

### Key Finding

```text
A firewall can only enforce traffic that traverses it.
```

To enforce Kali-to-Splunk restrictions through pfSense, Kali needed to move onto a separate routed subnet.

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

<img width="958" height="303" alt="pfSense OPT interface created for Kali subnet" src="https://github.com/user-attachments/assets/2eb470ee-2aba-4222-b74c-ce98b18b31b4" />

**Figure 9 – pfSense OPT interface created for Kali subnet**

<img width="949" height="934" alt="pfSense ATTACK_NET interface configured" src="https://github.com/user-attachments/assets/e2c4ebdd-5617-4082-bd23-34b7d8358afa" />

**Figure 10 – pfSense ATTACK_NET interface configured**

DHCP was enabled on the `ATTACK_NET` interface.

| Setting | Value |
|---|---|
| Subnet | `192.168.60.0/24` |
| DHCP range start | `192.168.60.100` |
| DHCP range end | `192.168.60.199` |

<img width="954" height="977" alt="DHCP scope configured for the ATTACK_NET subnet" src="https://github.com/user-attachments/assets/5fb5e271-14be-4d78-a4a5-00ef16bbcdd8" />

**Figure 11 – DHCP scope configured for the ATTACK_NET subnet**

Kali was moved from the main `LAB_LAN` network to the new `ATTACK_NET` VirtualBox internal network.

<img width="798" height="309" alt="Kali moved to the dedicated attacker subnet" src="https://github.com/user-attachments/assets/b9225e26-0725-44f8-a4fb-c14a7f0968cb" />

**Figure 12 – Kali moved to the dedicated attacker subnet**

A temporary allow rule was added on the `ATTACK_NET` interface to validate routing before restrictive firewall rules were created.

<img width="947" height="264" alt="Temporary allow rule for ATTACK_NET validation" src="https://github.com/user-attachments/assets/ca59640c-e708-4a14-807e-65ea8d8b21f6" />

**Figure 13 – Temporary allow rule for ATTACK_NET validation**

Kali successfully reached the pfSense `ATTACK_NET` gateway at `192.168.60.1`.

<img width="502" height="180" alt="Kali reaching the pfSense ATTACK_NET gateway" src="https://github.com/user-attachments/assets/37a19e7c-28ae-46e7-9559-e6c1abdec262" />

**Figure 14 – Kali reaching the pfSense ATTACK_NET gateway**

Kali was then tested against Splunk on the main lab subnet.

```bash
ping -c 4 192.168.50.10
```

<img width="500" height="182" alt="Kali routing from ATTACK_NET to the main lab subnet" src="https://github.com/user-attachments/assets/ca7dcdd6-d32a-42ea-b7b2-85be940bfcce" />

**Figure 15 – Kali routing from ATTACK_NET to the main lab subnet**

---

## Test 2 – Block ATTACK_NET Access to Splunk Web

Before adding the block rule, Kali was tested against Splunk Web across the routed subnets.

```bash
nc -vz 192.168.50.10 8000
```

<img width="443" height="69" alt="Kali baseline access to Splunk Web across routed subnets" src="https://github.com/user-attachments/assets/6f1db23d-4c5c-4bda-a1de-6af58789bb66" />

**Figure 16 – Kali baseline access to Splunk Web across routed subnets**

A new block rule was added on the `ATTACK_NET` interface above the temporary allow rule.

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

<img width="458" height="68" alt="Kali blocked from accessing Splunk Web across routed subnets" src="https://github.com/user-attachments/assets/5b108256-b8cc-4984-a800-8e588c0050ed" />

**Figure 18 – Kali blocked from accessing Splunk Web across routed subnets**

Additional testing confirmed the block only affected Splunk Web access and did not break routing or the Splunk receiving port.

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | ICMP ping | Successful |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `9997` | Open |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `8000` | Blocked |

<img width="499" height="261" alt="Kali routing and Splunk receiving port remain available after Splunk Web block" src="https://github.com/user-attachments/assets/1ebc70e2-c6c7-458a-9d52-355eb2aff734" />

**Figure 19 – Kali routing and Splunk receiving port remain available after Splunk Web block**

Splunk ingestion was validated after blocking attacker subnet access to Splunk Web.

<img width="1047" height="350" alt="Splunk ingestion validated after blocking attacker subnet access to Splunk Web" src="https://github.com/user-attachments/assets/4a3f6062-576a-44db-96cf-bd3adb878340" />

**Figure 20 – Splunk ingestion validated after blocking attacker subnet access to Splunk Web**

---

## Test 3 – Block ATTACK_NET Access to Splunk Receiving Port

After confirming that Splunk Web access could be blocked across routed subnets, the next restriction focused on the Splunk receiving port, TCP `9997`.

```bash
nc -vz 192.168.50.10 9997
ping -c 4 192.168.50.10
```

<img width="502" height="261" alt="Kali baseline splunk receiving port" src="https://github.com/user-attachments/assets/280afb70-c133-4ff5-8b07-1445e798a094" />

**Figure 21 – Kali baseline access to the Splunk receiving port before ATTACK_NET restriction**

A new block rule was added on the `ATTACK_NET` interface above the temporary allow rule.

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

After applying the rule and resetting pfSense states, Kali was tested against Splunk TCP `9997`, Splunk TCP `8000`, and ICMP.

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `9997` | Blocked |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | ICMP ping | Successful |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `8000` | Blocked |

<img width="501" height="278" alt="Kali blocked Splunk web and receiving port" src="https://github.com/user-attachments/assets/9733254f-5bac-40ab-84b3-28430f57071f" />

**Figure 23 – Kali blocked from Splunk Web and the Splunk receiving port while routing remains available**

Splunk ingestion was validated after blocking attacker subnet access to the Splunk receiving port.

| Host | Sourcetype | Count |
|---|---|---:|
| ADDC01 | `WinEventLog` | 31 |
| ADDC01 | `WinEventLog:SecurityAll` | 113 |
| TARGET-PC | `WinEventLog` | 73 |

<img width="1027" height="363" alt="Splunk ingestion after ATTACK_NET Splunk receiving port block" src="https://github.com/user-attachments/assets/c106d204-1689-492e-b81b-537d01f3462e" />

**Figure 24 – Splunk ingestion validated after blocking ATTACK_NET access to the Splunk receiving port**

---

## Test 4 – Restrict ATTACK_NET Access to Domain Controller LDAP and SMB

The next control focused on direct access from `ATTACK_NET` to Domain Controller services.

DNS TCP `53` and Kerberos TCP `88` were left reachable for controlled identity testing. LDAP TCP `389` and SMB TCP `445` were selected for restriction because they can support enumeration and lateral movement activity.

Before adding the new block rules, Kali was tested against the Domain Controller from the routed attacker subnet.

```bash
ping -c 4 192.168.50.20
nc -vz 192.168.50.20 53
nc -vz 192.168.50.20 88
nc -vz 192.168.50.20 389
nc -vz 192.168.50.20 445
```

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

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | ICMP ping | Successful |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `53` DNS | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `88` Kerberos | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `389` LDAP | Blocked |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `445` SMB | Blocked |

<img width="541" height="376" alt="Kali blocked domain-controller ldap and smb" src="https://github.com/user-attachments/assets/f12a59c8-22da-4ce9-b7cd-c46b1a71bd64" />

**Figure 27 – Kali blocked from Domain Controller LDAP and SMB while DNS and Kerberos remain available**

Splunk ingestion was validated after blocking attacker subnet access to Domain Controller LDAP and SMB.

| Host | Sourcetype | Count |
|---|---|---:|
| ADDC01 | `WinEventLog` | 171 |
| ADDC01 | `WinEventLog:SecurityAll` | 209 |
| TARGET-PC | `WinEventLog` | 255 |

<img width="1046" height="358" alt="Splunk ingestion after domain controller ldap and smb block" src="https://github.com/user-attachments/assets/0e2b4642-cebc-44cd-b726-fba57aacfe24" />

**Figure 28 – Splunk ingestion validated after blocking ATTACK_NET access to Domain Controller LDAP and SMB**

---

## Test 5 – Validate Blocked Enumeration Paths from ATTACK_NET

After blocking direct `ATTACK_NET` access to Splunk and initial Domain Controller services, Kali tooling was used to validate the controls from an attacker-subnet perspective.

The purpose of this test was to confirm that common enumeration paths were blocked, while selected identity testing paths remained available.

### Nmap Service Validation

Kali first ran an `nmap` scan against the Domain Controller for DNS, Kerberos, LDAP, and SMB.

```bash
nmap -Pn -p 53,88,389,445 192.168.50.20
```

| Source | Destination | Port | Result |
|---|---|---:|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `53` | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `88` | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `389` | Filtered |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `445` | Filtered |

<img width="528" height="217" alt="nmap domain controller filtered services from ATTACK_NET" src="https://github.com/user-attachments/assets/55f2e722-13bf-4178-bff5-c8f0b2d71e2f" />

**Figure 29 – Nmap validation of allowed and blocked Domain Controller services from ATTACK_NET**

### LDAP Query Validation

Kali attempted a basic unauthenticated LDAP query against the Domain Controller.

```bash
ldapsearch -x -H ldap://192.168.50.20 -o nettimeout=5 -s base
```

The query failed with the following result:

```text
ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)
ldapsearch exit code: 255
```

<img width="524" height="87" alt="ldapsearch blocked domain controller ldap from ATTACK_NET" src="https://github.com/user-attachments/assets/36a694d0-00e9-4ec9-b961-cd9cbf236360" />

**Figure 30 – ldapsearch blocked from querying Domain Controller LDAP from ATTACK_NET**

### enum4linux-ng Enumeration Validation

Kali then used `enum4linux-ng` to perform a broader enumeration check against the Domain Controller.

The condensed output showed that LDAP TCP `389` and SMB TCP `445` were blocked, but it also identified two additional exposed services.

| Service | Port | Result |
|---|---:|---|
| LDAP | TCP `389` | Timed out |
| LDAPS | TCP `636` | Accessible |
| SMB | TCP `445` | Timed out |
| SMB over NetBIOS | TCP `139` | Accessible |
| SMB sessions | N/A | Failed |

<img width="1044" height="234" alt="enum4linux ng identifies blocked and exposed domain controller services" src="https://github.com/user-attachments/assets/42418a54-d6aa-485e-950a-61fd7571b112" />

**Figure 31 – enum4linux-ng validation showing blocked LDAP and SMB with additional exposed LDAPS and NetBIOS paths**

### Additional Service Exposure Validation

A focused `nmap` scan confirmed the additional exposed services.

```bash
nmap -Pn -p 139,636 192.168.50.20
```

| Source | Destination | Port | Result |
|---|---|---:|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `139` | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `636` | Open |

<img width="526" height="186" alt="nmap validation of additional domain controller services from ATTACK_NET" src="https://github.com/user-attachments/assets/670b448a-ee51-49cb-ae38-ff5f6b428072" />

**Figure 32 – Nmap validation of additional Domain Controller services exposed to ATTACK_NET**

### Additional pfSense Block Rules

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

<img width="953" height="353" alt="pfSense block ATTACK_NET access to domain controller via ldaps and netbios" src="https://github.com/user-attachments/assets/f5680886-33a4-4829-b9a5-be2a1b36a129" />

**Figure 33 – pfSense rules blocking ATTACK_NET access to Domain Controller LDAPS and NetBIOS**

### Post-Rule Enumeration Service Validation

After applying the LDAPS and NetBIOS restrictions and resetting pfSense states, Kali repeated the `nmap` scan against Domain Controller enumeration services.

```bash
nmap -Pn -p 139,389,445,636 192.168.50.20
```

| Source | Destination | Port | Result |
|---|---|---:|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `139` | Filtered |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `389` | Filtered |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `445` | Filtered |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `636` | Filtered |

<img width="527" height="216" alt="nmap validation domain controller enumeration services filtered" src="https://github.com/user-attachments/assets/b6ed8aa9-df2a-4cff-a28f-1e63eccdb597" />

**Figure 34 – Nmap validation showing Domain Controller LDAP, LDAPS, SMB, and NetBIOS filtered from ATTACK_NET**

### Allowed Identity Testing Paths

After blocking additional enumeration paths, DNS and Kerberos were tested again from Kali.

```bash
nmap -Pn -p 53,88 192.168.50.20
```

| Source | Destination | Port | Result |
|---|---|---:|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `53` | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `88` | Open |

<img width="524" height="182" alt="nmap validation dns and kerberos remain available from ATTACK_NET" src="https://github.com/user-attachments/assets/cc498b8b-863e-4919-a0de-870b2afadd53" />

**Figure 35 – Nmap validation showing DNS and Kerberos remain available from ATTACK_NET**

### Splunk Ingestion Validation After Additional Domain Controller Restrictions

Splunk ingestion was validated after adding the LDAPS and NetBIOS restrictions.

```spl
index=identity host=ADDC01 OR host=TARGET-PC earliest=-30m
| stats count by host sourcetype
```

| Host | Sourcetype | Count |
|---|---|---:|
| ADDC01 | `WinEventLog` | 32 |
| ADDC01 | `WinEventLog:SecurityAll` | 166 |
| TARGET-PC | `WinEventLog` | 235 |

<img width="1043" height="355" alt="Splunk ingestion after additional domain controller enumeration blocks" src="https://github.com/user-attachments/assets/76cdefe3-212b-4277-9682-e091b85b9c12" />

**Figure 36 – Splunk ingestion validated after blocking additional Domain Controller enumeration services from ATTACK_NET**

---

## Test 6 – Convert ATTACK_NET to Least-Privilege Policy

After validating targeted block rules from `ATTACK_NET`, the next phase was to remove the broad temporary allow rule and replace it with explicit allow rules.

The purpose of this test was to move from a testing-mode policy to a least-privilege policy:

```text
Allow only approved ATTACK_NET traffic.
Block everything else by default.
```

### Current ATTACK_NET Rule State Before Hardening

Before changing the rules, the current `ATTACK_NET` policy was captured. The rule set still contained the broad temporary allow rule below the explicit block rules.

<img width="960" height="704" alt="Current ATTACK_NET rules before least privilege hardening" src="https://github.com/user-attachments/assets/b11035b3-73e7-4b0a-a64b-381073f284c3" />

**Figure 37 – Current ATTACK_NET firewall rules before least-privilege hardening**

### Explicit ATTACK_NET Allow Rules

The following explicit allow rules were added above the temporary allow rule and below the existing block rules.

| Rule | Source | Destination | Protocol | Port | Purpose |
|---|---|---|---|---:|---|
| Allow DNS | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP/UDP | `53` | DNS testing and name resolution |
| Allow Kerberos | ATTACK_NET subnets | ADDC01 `192.168.50.20` | TCP/UDP | `88` | Controlled Kerberos testing |
| Allow ICMP to ADDC01 | ATTACK_NET subnets | ADDC01 `192.168.50.20` | ICMP | Any | Routing validation |
| Allow ICMP to Splunk | ATTACK_NET subnets | SPLUNK01 `192.168.50.10` | ICMP | Any | Routing validation |

<img width="959" height="1013" alt="Explicit ATTACK_NET allow rules added before removing the temporary allow rule" src="https://github.com/user-attachments/assets/85c81e37-3297-4431-a5ef-29ffe5b19742" />

**Figure 38 – Explicit ATTACK_NET allow rules added before removing the temporary allow rule**

### Temporary Allow Rule Disabled

After the explicit allow rules were added, the broad temporary validation rule was disabled.

```text
Disabled | Pass | Source: ATTACK_NET subnets | Destination: any | Protocol: IPv4 any
```

<img width="945" height="79" alt="Temporary ATTACK_NET allow rule disabled after explicit allow rules were added" src="https://github.com/user-attachments/assets/d8593abb-edf1-428c-a19a-d76ee3900c29" />

**Figure 39 – Temporary ATTACK_NET allow rule disabled after explicit allow rules were added**

### Allowed Path Validation

After resetting pfSense states, Kali was used to validate that the approved paths still worked.

```bash
ping -c 4 192.168.50.20
ping -c 4 192.168.50.10
nmap -Pn -p 53,88 192.168.50.20
```

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | ICMP ping | Successful |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | ICMP ping | Successful |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `53` DNS | Open |
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `88` Kerberos | Open |

<img width="525" height="500" alt="ATTACK_NET allowed paths after temporary allow rule is disabled" src="https://github.com/user-attachments/assets/4697ea51-a8f0-4281-8e06-bf573a1ebc66" />

**Figure 40 – ATTACK_NET allowed DNS, Kerberos, and ICMP paths after disabling the temporary allow rule**

### Blocked Path Validation

Kali was then used to confirm that previously blocked Splunk and Domain Controller paths stayed filtered after the temporary allow rule was disabled.

```bash
nmap -Pn -p 139,389,445,636 192.168.50.20
nmap -Pn -p 8000,9997 192.168.50.10
```

| Source | Destination | Ports | Result |
|---|---|---:|---|
| Kali `192.168.60.100` | ADDC01 `192.168.50.20` | TCP `139`, `389`, `445`, `636` | Filtered |
| Kali `192.168.60.100` | SPLUNK01 `192.168.50.10` | TCP `8000`, `9997` | Filtered |

<img width="525" height="370" alt="ATTACK_NET blocked paths after temporary allow rule is disabled" src="https://github.com/user-attachments/assets/be4c9b7b-1515-4866-bd62-74efaca7769a" />

**Figure 41 – ATTACK_NET blocked paths remain filtered after disabling the temporary allow rule**

### Splunk Ingestion Validation After Least-Privilege Hardening

Splunk ingestion was validated after disabling the temporary allow rule.

```spl
index=identity host=ADDC01 OR host=TARGET-PC earliest=-30m
| stats count by host sourcetype
```

| Host | Sourcetype | Count |
|---|---|---:|
| ADDC01 | `WinEventLog` | 168 |
| TARGET-PC | `WinEventLog` | 234 |

<img width="960" height="352" alt="Splunk ingestion after ATTACK_NET least privilege hardening" src="https://github.com/user-attachments/assets/fb6f2488-5fd8-416d-9e1b-0aaf90dae968" />

**Figure 42 – Splunk ingestion validated after ATTACK_NET least-privilege hardening**

### Default Deny Validation

Kali was then used to prove that unmatched traffic no longer passed from `ATTACK_NET`.

```bash
ping -c 4 8.8.8.8
curl -I https://github.com --max-time 10
nmap -Pn -p 445,3389 192.168.50.110
```

| Source | Destination | Test | Result |
|---|---|---|---|
| Kali `192.168.60.100` | `8.8.8.8` | ICMP ping | Blocked |
| Kali `192.168.60.100` | `github.com` | HTTPS curl | Failed / timed out |
| Kali `192.168.60.100` | TARGET-PC `192.168.50.110` | TCP `445` SMB | Filtered |
| Kali `192.168.60.100` | TARGET-PC `192.168.50.110` | TCP `3389` RDP | Filtered |

<img width="524" height="309" alt="Default deny validation after ATTACK_NET least privilege hardening" src="https://github.com/user-attachments/assets/f728c808-605b-428c-b5ee-f7d5b104e212" />

**Figure 43 – Default deny validation for unmatched ATTACK_NET traffic after least-privilege hardening**

### DNS Resolution Validation

A final DNS test confirmed that the explicit DNS allow rule still allowed Kali to resolve the Active Directory domain through the Domain Controller.

```bash
nslookup adproject.local 192.168.50.20
```

| Query | DNS Server | Result |
|---|---|---|
| `adproject.local` | ADDC01 `192.168.50.20` | Resolved to `192.168.50.20` |

<img width="340" height="116" alt="DNS resolution validation after ATTACK_NET least privilege hardening" src="https://github.com/user-attachments/assets/5d85033f-afbc-42aa-bc92-9aa68b64b350" />

**Figure 44 – DNS resolution to the Domain Controller validated after ATTACK_NET least-privilege hardening**

### Test Result

The least-privilege test was successful.

The temporary broad allow rule was disabled, explicit allow rules preserved DNS, Kerberos, and ICMP validation paths, and unmatched traffic from `ATTACK_NET` was denied by default. Splunk ingestion from the main lab subnet remained functional after the policy change.

---

## Rule Testing Methodology

Each firewall rule change follows a consistent process:

1. Record baseline connectivity before the rule is applied.
2. Create or update the pfSense firewall rule.
3. Test allowed traffic.
4. Test blocked traffic.
5. Confirm Splunk ingestion still works.
6. Document the result with screenshots and notes.

---

## Validation Queries

Splunk was used to confirm that required identity telemetry still reached the SIEM after firewall rules were applied.

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

- The first pfSense rule attempted to block Kali from reaching Splunk Web on TCP `8000`.
- The connection remained open because Kali and Splunk were on the same `192.168.50.0/24` subnet.
- Same-subnet traffic did not traverse pfSense, so pfSense could not enforce host-to-host restrictions in that topology.
- Kali was moved to a separate `192.168.60.0/24` attacker subnet using the pfSense `ATTACK_NET` interface.
- After moving Kali to a routed subnet, pfSense successfully blocked Kali from accessing Splunk Web on TCP `8000`.
- A second ATTACK_NET block rule was added for Splunk TCP `9997`.
- After applying the TCP `9997` block, Kali could no longer reach Splunk Web or the Splunk receiving port, while ICMP routing to Splunk remained available.
- Baseline testing from `ATTACK_NET` showed that Kali could reach ADDC01 over DNS, Kerberos, LDAP, and SMB.
- Block rules were added for Domain Controller LDAP TCP `389` and SMB TCP `445`.
- Kali enumeration tooling later identified that LDAPS TCP `636` and NetBIOS TCP `139` were still exposed from `ATTACK_NET`.
- Additional block rules were added for Domain Controller LDAPS TCP `636` and NetBIOS TCP `139`.
- Follow-up `nmap` testing confirmed that TCP `139`, `389`, `445`, and `636` were filtered from `ATTACK_NET`.
- DNS TCP `53` and Kerberos TCP `88` remained available for controlled identity testing after the additional restrictions.
- Explicit allow rules were added for ATTACK_NET DNS, Kerberos, and selected ICMP validation traffic.
- The broad temporary ATTACK_NET allow rule was disabled after the explicit allow rules were confirmed.
- Default deny behaviour was validated by testing unmatched internet and TARGET-PC traffic from Kali.
- Splunk ingestion from ADDC01 and TARGET-PC remained functional after all ATTACK_NET restrictions and least-privilege changes were applied.

---

## Security Outcome

This phase demonstrates that the lab network can move from basic routing behind pfSense toward controlled firewall policy enforcement and least-privilege segmentation.

The initial firewall rule test showed that placing all systems behind pfSense on one subnet does not provide true host-to-host segmentation. To enforce attacker-to-infrastructure firewall rules, Kali had to be placed on a separate routed subnet so traffic traversed pfSense.

After moving Kali to the `ATTACK_NET` subnet, pfSense successfully blocked attacker access to Splunk Web while allowing required routing and Splunk log ingestion to continue. The follow-up TCP `9997` restriction further reduced unnecessary attacker access to SIEM infrastructure while preserving trusted Windows event forwarding from the main lab subnet.

Domain Controller testing then showed that Kali could reach DNS, Kerberos, LDAP, and SMB from the attacker subnet. LDAP and SMB were blocked from `ATTACK_NET` to reduce direct attacker access to high-value Domain Controller services, while DNS and Kerberos remained available for controlled identity testing.

Kali enumeration tooling then identified additional exposed Domain Controller services over LDAPS TCP `636` and NetBIOS TCP `139`. These paths were also blocked, and follow-up validation confirmed that LDAP, LDAPS, SMB, and NetBIOS were filtered from `ATTACK_NET` while DNS and Kerberos remained available.

The final hardening phase replaced the temporary broad ATTACK_NET allow rule with explicit allow rules for DNS, Kerberos, and selected ICMP validation traffic. Unmatched traffic was denied by default, and Splunk ingestion remained operational.

This created a stronger foundation for least-privilege segmentation between attacker, endpoint, and infrastructure systems.

---

## Status

Baseline testing completed. Same-subnet firewall rule limitation identified. Kali moved to a separate `ATTACK_NET` subnet. Routed firewall testing successfully blocked attacker subnet access to Splunk Web, the Splunk receiving port, Domain Controller LDAP, Domain Controller SMB, Domain Controller LDAPS, and Domain Controller NetBIOS.

The temporary ATTACK_NET allow rule has now been disabled. Explicit allow rules preserve DNS, Kerberos, and selected ICMP validation paths. Default deny behaviour has been validated, and Splunk ingestion remains functional from the main lab subnet.
