# SNMP Enumeration Playbook

> SNMP often leaks system details, network maps, software versions, and credentials.
> This workflow covers SNMPv1/v2c/v3 testing in authorized environments.

---

## 1. Discovery and Version Detection

```bash
# Find UDP/161 exposure
nmap -sU -p 161 --open <target>
nmap -sU -p 161 --script snmp-info <target>

# Broad subnet check
nmap -sU -p 161 --open 10.10.10.0/24 -oA snmp_hosts
```

What to record:
- Hostname and device type
- SNMP version support (v1/v2c/v3)
- Whether public/private community strings are accepted

---

## 2. Community String Testing (v1/v2c)

```bash
# Quick checks
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c private <target> 1.3.6.1.2.1.1

# Brute force common communities
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>

# Nmap script-assisted probing
nmap -sU -p 161 --script snmp-brute <target>
```

Critical finding:
- Read-write community string found (`private`, `manager`, etc.) can allow configuration tampering.

---

## 3. High-Value OID Enumeration

```bash
# System info
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.1

# Interfaces and routing
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.2
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.4

# ARP table
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.4.22

# Running processes and software
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.25.6.3.1.2

# TCP listeners
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.6.13.1.3
```

Findings to surface:
- Hidden interfaces or management VLANs
- Internal IP ranges and neighboring hosts
- Services not visible externally but exposed internally

---

## 4. SNMPv3 Validation

```bash
# Check if v3 works with known creds
snmpwalk -v3 -l authNoPriv -u <user> -a SHA -A <authpass> <target> 1.3.6.1.2.1.1
snmpwalk -v3 -l authPriv -u <user> -a SHA -A <authpass> -x AES -X <privpass> <target> 1.3.6.1.2.1.1

# Nmap discovery scripts
nmap -sU -p 161 --script snmp-info,snmp-netstat,snmp-processes <target>
```

Security posture checks:
- SNMPv3 enforced or legacy v2c still enabled
- Weak auth/privacy algorithms
- Shared credentials across multiple network devices

---

## 5. Tool-Call Strategy (For Model-Oriented Workflows)

Recommended tool calls:
- `snmp_surface_mapper`: Enumerate SNMP-enabled hosts and fingerprint versions/community posture
- `oid_high_value_extractor`: Pull and normalize interfaces/routes/arp/process OIDs into structured graph
- `snmp_credential_audit`: Classify weak/default communities and reused SNMPv3 identities
- `network_exposure_correlator`: Link SNMP-derived topology with open-port scan results

Decision sequence:
1. Confirm UDP/161 exposure
2. Test safe read-only communities first
3. Enumerate high-value OIDs and internal topology
4. Correlate with network scan and service inventory
5. Prioritize hardening (SNMPv3-only, ACLs, credential rotation)

---

## 6. Detection and Mitigation Guidance

Detection ideas:
- Alert on repeated community-string failures from single source
- Monitor unusual bulk SNMP walks outside NMS systems
- Detect write operations to sensitive OIDs

Mitigation actions:
- Disable SNMPv1/v2c where possible; enforce SNMPv3 authPriv
- Restrict SNMP access by ACL to dedicated monitoring hosts
- Rotate community strings and SNMPv3 credentials periodically
- Disable write permissions unless explicitly required

