# Discovery Enumeration Playbook (ATT&CK TA0007, Dataset-Ready)

> Purpose: provide realistic, high-value discovery training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Discovery covers adversary attempts to gather environment information to shape follow-on actions.

- ATT&CK Tactic ID: TA0007
- Core techniques in this playbook: T1087, T1010, T1217, T1580, T1538, T1526, T1619, T1613, T1622, T1652, T1482, T1083, T1615, T1680, T1654, T1046, T1135, T1040, T1201, T1120, T1069, T1057, T1012, T1018, T1518, T1082, T1614, T1016, T1049, T1033, T1007, T1124, T1673, T1497

---

## 0. Safety and Lab Controls

1. Perform discovery only in approved ranges and tenants.
2. Use bounded scans (`--top-ports`, `-c`, `head`) to avoid service impact.
3. Log command source host, target scope, and run window.
4. Do not query production secrets while testing discovery behavior.
5. Maintain packet/log evidence for every discovery phase.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_discovery() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/discovery.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1046",
  "technique_name": "Network Service Discovery",
  "scenario": "Operator performs controlled top-port scan in isolated subnet",
  "command": "nmap -sV -Pn 10.20.30.0/24 --top-ports 200 --open",
  "tool_result": {"status":"success", "highlights":["10.20.30.25:445 smb", "10.20.30.10:389 ldap"]},
  "analyst_interpretation": "Remote service inventory identified candidate lateral movement paths",
  "confidence": 0.95,
  "mitigation_hint": "Segment network and alert on anomalous scan patterns"
}
```

---

## 1. Baseline Before Discovery

Scenario:
- Capture host context before running discovery workflows.

```bash
run_discovery "TA0007" "host_baseline" sh -lc 'whoami; hostname; date -u; ip a | head -n 25'
```

Example result:

```text
corp\\labuser
LAB-WS-11
2026-04-21T14:21:09Z
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

---

## 2. Identity, Account, and Permission Discovery

## T1087 Account Discovery

### T1087.001 Local Account

```bash
run_discovery "T1087.001" "local_accounts_windows" cmd /c "net user"
run_discovery "T1087.001" "local_accounts_linux" sh -lc 'cut -d: -f1 /etc/passwd | head -n 30'
```

### T1087.002 Domain Account

```bash
run_discovery "T1087.002" "domain_accounts_ad" powershell -NoProfile -Command "Get-ADUser -Filter * -ResultPageSize 200 | Select-Object -First 20 SamAccountName"
```

### T1087.003 Email Account

```bash
run_discovery "T1087.003" "email_accounts_exchange" powershell -NoProfile -Command "Get-Recipient -ResultSize 20 | Select-Object DisplayName,PrimarySmtpAddress"
```

### T1087.004 Cloud Account

```bash
run_discovery "T1087.004" "aws_iam_users" aws iam list-users --max-items 20
run_discovery "T1087.004" "azure_users" az ad user list --top 20
```

## T1069 Permission Groups Discovery

### T1069.001 Local Groups

```bash
run_discovery "T1069.001" "local_groups_windows" cmd /c "net localgroup"
run_discovery "T1069.001" "local_groups_linux" getent group sudo
```

### T1069.002 Domain Groups

```bash
run_discovery "T1069.002" "domain_groups_ad" powershell -NoProfile -Command "Get-ADGroup -Filter * | Select-Object -First 25 Name"
```

### T1069.003 Cloud Groups

```bash
run_discovery "T1069.003" "cloud_groups_azure" az ad group list --top 20
```

## T1033 System Owner/User Discovery

```bash
run_discovery "T1033" "owner_user_discovery" sh -lc 'whoami; who; id'
```

Example result:

```text
labuser
labuser pts/0 2026-04-21 13:58 (10.20.30.55)
uid=1000(labuser) gid=1000(labuser)
```

---

## 3. Host, Process, and Software Discovery

## T1082 System Information Discovery

```bash
run_discovery "T1082" "system_info_windows" cmd /c "systeminfo"
run_discovery "T1082" "system_info_linux" sh -lc 'uname -a; cat /etc/os-release | head -n 10'
```

## T1518 Software Discovery

```bash
run_discovery "T1518" "software_windows" powershell -NoProfile -Command "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object -First 20 DisplayName,DisplayVersion"
run_discovery "T1518" "software_linux" sh -lc 'dpkg -l | head -n 25'
```

### T1518.001 Security Software Discovery

```bash
run_discovery "T1518.001" "security_software_windows" powershell -NoProfile -Command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName,pathToSignedProductExe"
```

### T1518.002 Backup Software Discovery

```bash
run_discovery "T1518.002" "backup_software_windows" cmd /c "wmic service where \"name like '%backup%' or name like '%veeam%'\" get name,state"
```

## T1057 Process Discovery

```bash
run_discovery "T1057" "process_list_windows" tasklist
run_discovery "T1057" "process_list_linux" sh -lc 'ps aux | head -n 30'
```

## T1007 System Service Discovery

```bash
run_discovery "T1007" "service_list_windows" sc query type= service state= all
run_discovery "T1007" "service_list_linux" sh -lc 'systemctl --type=service --all | head -n 40'
```

## T1010 Application Window Discovery

```bash
run_discovery "T1010" "window_discovery_windows" powershell -NoProfile -Command "Get-Process | Where-Object {$_.MainWindowTitle} | Select-Object -First 20 ProcessName,MainWindowTitle"
```

## T1217 Browser Information Discovery

```bash
run_discovery "T1217" "browser_history_chrome" sh -lc 'sqlite3 "$HOME/.config/google-chrome/Default/History" "SELECT url FROM urls LIMIT 15;" 2>/dev/null'
```

## T1012 Query Registry

```bash
run_discovery "T1012" "registry_query" reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
```

## T1083 File and Directory Discovery

```bash
run_discovery "T1083" "filesystem_discovery" sh -lc 'find /home/labuser -maxdepth 3 -type f | head -n 40'
```

## T1680 Local Storage Discovery

```bash
run_discovery "T1680" "storage_windows" cmd /c "wmic logicaldisk get Name,Size,FreeSpace,VolumeSerialNumber"
run_discovery "T1680" "storage_linux" sh -lc 'lsblk -f; df -h | head -n 20'
```

## T1654 Log Enumeration

```bash
run_discovery "T1654" "log_enum_windows" wevtutil el
run_discovery "T1654" "log_enum_linux" sh -lc 'ls -lah /var/log | head -n 30; journalctl -n 20 --no-pager'
```

## T1120 Peripheral Device Discovery

```bash
run_discovery "T1120" "peripherals_windows" powershell -NoProfile -Command "Get-PnpDevice | Select-Object -First 25 Class,FriendlyName,Status"
run_discovery "T1120" "peripherals_linux" sh -lc 'lsusb; lspci | head -n 20'
```

## T1652 Device Driver Discovery

```bash
run_discovery "T1652" "driver_discovery_windows" driverquery /v
run_discovery "T1652" "driver_discovery_linux" sh -lc 'lsmod | head -n 30'
```

## T1124 System Time Discovery

```bash
run_discovery "T1124" "time_discovery_windows" w32tm /tz
run_discovery "T1124" "time_discovery_linux" timedatectl
```

---

## 4. Network and Domain Discovery

## T1016 System Network Configuration Discovery

```bash
run_discovery "T1016" "net_config_windows" ipconfig /all
run_discovery "T1016" "net_config_linux" sh -lc 'ip addr; ip route; arp -a | head -n 30'
```

### T1016.001 Internet Connection Discovery

```bash
run_discovery "T1016.001" "internet_check" sh -lc 'curl -I -m 5 https://example.com'
```

### T1016.002 Wi-Fi Discovery

```bash
run_discovery "T1016.002" "wifi_profiles_windows" cmd /c "netsh wlan show profiles"
run_discovery "T1016.002" "wifi_networks_linux" nmcli dev wifi list
```

## T1049 System Network Connections Discovery

```bash
run_discovery "T1049" "connections_windows" netstat -ano
run_discovery "T1049" "connections_linux" sh -lc 'ss -tunap | head -n 40'
```

## T1018 Remote System Discovery

```bash
run_discovery "T1018" "remote_hosts" sh -lc 'arp -a; ping -c 1 10.20.30.1'
```

## T1135 Network Share Discovery

```bash
run_discovery "T1135" "share_discovery_windows" cmd /c "net view \\fileserver"
run_discovery "T1135" "share_discovery_smbclient" smbclient -L //10.20.30.25 -N
```

## T1046 Network Service Discovery

```bash
run_discovery "T1046" "port_service_scan" nmap -sV -Pn 10.20.30.0/24 --top-ports 200 --open
```

## T1040 Network Sniffing

```bash
run_discovery "T1040" "sniffing_sample" sudo tcpdump -ni eth0 -c 40 '(tcp port 80 or tcp port 445 or tcp port 389)'
```

## T1201 Password Policy Discovery

```bash
run_discovery "T1201" "password_policy_domain" cmd /c "net accounts /domain"
run_discovery "T1201" "password_policy_ad" powershell -NoProfile -Command "Get-ADDefaultDomainPasswordPolicy"
```

## T1482 Domain Trust Discovery

```bash
run_discovery "T1482" "domain_trusts_nltest" nltest /domain_trusts
run_discovery "T1482" "domain_trusts_ad" powershell -NoProfile -Command "Get-ADTrust -Filter * | Select-Object Name,Direction,TrustType"
```

## T1615 Group Policy Discovery

```bash
run_discovery "T1615" "gpo_discovery" powershell -NoProfile -Command "Get-GPO -All | Select-Object -First 20 DisplayName,Id"
run_discovery "T1615" "sysvol_policies" cmd /c "dir \\corp.local\\SYSVOL\\corp.local\\Policies"
```

---

## 5. Cloud and Container Discovery

## T1580 Cloud Infrastructure Discovery

```bash
run_discovery "T1580" "cloud_infra_aws" aws ec2 describe-instances --max-items 20
run_discovery "T1580" "cloud_infra_azure" az vm list -d --query "[].{name:name,privateIps:privateIps,powerState:powerState}" -o table
```

## T1538 Cloud Service Dashboard

```bash
run_discovery "T1538" "cloud_dashboard_sim" sh -lc 'echo "simulate manual discovery through cloud console dashboards (compute, storage, security findings)"'
```

## T1526 Cloud Service Discovery

```bash
run_discovery "T1526" "cloud_service_aws" sh -lc 'aws lambda list-functions --max-items 20; aws cloudtrail describe-trails'
run_discovery "T1526" "cloud_service_gcp" gcloud services list --enabled --limit=30
```

## T1619 Cloud Storage Object Discovery

```bash
run_discovery "T1619" "s3_object_listing" aws s3 ls s3://corp-lab-bucket --recursive | head -n 40
```

## T1613 Container and Resource Discovery

```bash
run_discovery "T1613" "k8s_resources" kubectl get pods,deploy,svc,nodes -A
run_discovery "T1613" "docker_resources" sh -lc 'docker ps -a; docker images | head -n 20'
```

## T1087.004 Cloud Account (Cross-reference)

```bash
run_discovery "T1087.004" "cloud_account_enum_gcp" gcloud iam service-accounts list --limit=20
```

## T1069.003 Cloud Groups (Cross-reference)

```bash
run_discovery "T1069.003" "cloud_group_enum_aws" aws iam list-groups --max-items 20
```

---

## 6. Location, VM, and Sandbox Awareness

## T1614 System Location Discovery

```bash
run_discovery "T1614" "geo_discovery" curl -s https://ipinfo.io/json
```

### T1614.001 System Language Discovery

```bash
run_discovery "T1614.001" "language_windows" powershell -NoProfile -Command "Get-WinSystemLocale; Get-Culture"
run_discovery "T1614.001" "language_linux" locale
```

## T1673 Virtual Machine Discovery

```bash
run_discovery "T1673" "vm_discovery_esxi" sh -lc 'vim-cmd vmsvc/getallvms 2>/dev/null || true'
run_discovery "T1673" "vm_discovery_libvirt" virsh list --all
```

## T1497 Virtualization/Sandbox Evasion

### T1497.001 System Checks

```bash
run_discovery "T1497.001" "vm_artifact_checks" sh -lc 'systemd-detect-virt; dmidecode -s system-product-name 2>/dev/null | head -n 3'
```

### T1497.002 User Activity Based Checks

```bash
run_discovery "T1497.002" "user_activity_checks" sh -lc 'echo "simulate checks for mouse/keyboard inactivity and absent desktop interaction"'
```

### T1497.003 Time Based Checks

```bash
run_discovery "T1497.003" "time_checks" sh -lc 'START=$(date +%s); sleep 5; END=$(date +%s); echo "delta=$((END-START))"'
```

## T1622 Debugger Evasion

```bash
run_discovery "T1622" "debugger_evasion_sim" sh -lc 'echo "simulate debugger detection via ptrace/IsDebuggerPresent checks"'
```

---

## 7. Label-Ready Examples (JSONL)

```json
{"technique":"T1087.002","command":"Get-ADUser -Filter *","result":"Domain user list returned","interpretation":"Domain account inventory collected for targeting"}
{"technique":"T1046","command":"nmap -sV -Pn 10.20.30.0/24 --top-ports 200","result":"Open service map generated","interpretation":"Remote service landscape identified"}
{"technique":"T1613","command":"kubectl get pods,deploy,svc,nodes -A","result":"Cluster resources enumerated","interpretation":"Container estate visibility acquired"}
{"technique":"T1654","command":"wevtutil el","result":"Event log channels listed","interpretation":"Logs enumerated for intel and cleanup planning"}
{"technique":"T1497.001","command":"systemd-detect-virt","result":"Virtualization indicator detected","interpretation":"Execution behavior may be altered to evade analysis"}
```

---

## 8. Coverage Checklist

- T1087 Account Discovery
- T1087.001 Local Account
- T1087.002 Domain Account
- T1087.003 Email Account
- T1087.004 Cloud Account
- T1010 Application Window Discovery
- T1217 Browser Information Discovery
- T1580 Cloud Infrastructure Discovery
- T1538 Cloud Service Dashboard
- T1526 Cloud Service Discovery
- T1619 Cloud Storage Object Discovery
- T1613 Container and Resource Discovery
- T1622 Debugger Evasion
- T1652 Device Driver Discovery
- T1482 Domain Trust Discovery
- T1083 File and Directory Discovery
- T1615 Group Policy Discovery
- T1680 Local Storage Discovery
- T1654 Log Enumeration
- T1046 Network Service Discovery
- T1135 Network Share Discovery
- T1040 Network Sniffing
- T1201 Password Policy Discovery
- T1120 Peripheral Device Discovery
- T1069 Permission Groups Discovery
- T1069.001 Local Groups
- T1069.002 Domain Groups
- T1069.003 Cloud Groups
- T1057 Process Discovery
- T1012 Query Registry
- T1018 Remote System Discovery
- T1518 Software Discovery
- T1518.001 Security Software Discovery
- T1518.002 Backup Software Discovery
- T1082 System Information Discovery
- T1614 System Location Discovery
- T1614.001 System Language Discovery
- T1016 System Network Configuration Discovery
- T1016.001 Internet Connection Discovery
- T1016.002 Wi-Fi Discovery
- T1049 System Network Connections Discovery
- T1033 System Owner/User Discovery
- T1007 System Service Discovery
- T1124 System Time Discovery
- T1673 Virtual Machine Discovery
- T1497 Virtualization/Sandbox Evasion
- T1497.001 System Checks
- T1497.002 User Activity Based Checks
- T1497.003 Time Based Checks

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
