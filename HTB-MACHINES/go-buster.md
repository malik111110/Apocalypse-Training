# HTB Preignition - Gobuster Enumeration Playbook

Target theme:
- Web reconnaissance
- Site structure discovery
- Default credential validation

Use this in authorized labs only.

---

## 1. Objective

For this machine, the goal is to move from:
1. service discovery,
2. hidden content discovery,
3. login surface discovery,
4. credential hypothesis testing,
5. impact confirmation.

---

## 2. Core Concepts

- Directory brute forcing is commonly called dir busting.
- Nmap `-sV` is used for service version detection.
- Gobuster `dir` mode is used for web path discovery.
- Gobuster `-x` adds file extensions to test (`php`, `txt`, `bak`, etc.).

---

## 3. Initial Enumeration

Check host/service quickly:

```bash
nmap -sC -sV -T4 <TARGET_IP>
```

Expected finding on this box:
- `80/tcp` open
- HTTP service (nginx 1.14.2 on common Preignition runs)

Optional targeted check:

```bash
nmap -p 80 -sV --script http-title,http-server-header <TARGET_IP>
```

---

## 4. Gobuster for Hidden Paths

Baseline dir bust:

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt
```

Better coverage for this lab:

```bash
gobuster dir \
	-u http://<TARGET_IP> \
	-w /usr/share/wordlists/dirb/common.txt \
	-x php,txt,html,bak \
	-t 50 \
	-s 200,204,301,302,307,401,403
```

Flag meaning:
- `dir`: directory brute-force mode
- `-u`: target URL
- `-w`: wordlist path
- `-x`: extensions to append
- `-t`: threads
- `-s`: interesting status codes to keep

Common key result:
- `/admin.php` with status `200`

---

## 5. Authentication Hypothesis Testing

When hidden login page is found, test likely default creds in lab context.

Manual browser test:
- URL: `http://<TARGET_IP>/admin.php`
- Try: `admin:admin`

If successful:
- capture proof screenshot
- record exact credential pair
- extract flag / objective artifact

---

## 6. Task Answers (Preignition)

1. Another name for directory brute forcing:
- `dir busting`

2. Nmap switch for version detection:
- `-sV`

3. Service on `80/tcp`:
- `http`

4. Server and version found in typical run:
- `nginx 1.14.2`

5. Gobuster switch/mode for dir busting:
- `dir`

6. Gobuster switch to test PHP pages:
- `-x php`

7. Page discovered:
- `admin.php`

8. Status code of discovered page:
- `200`

---

## 7. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -T4 10.129.177.9
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2

analyst@kali:~$ gobuster dir -u http://10.129.177.9 -w /usr/share/wordlists/dirb/common.txt -x php -t 50
===============================================================
/index.php            (Status: 200) [Size: 612]
/admin.php            (Status: 200) [Size: 999]
/server-status        (Status: 403) [Size: 162]
===============================================================

analyst@kali:~$ firefox http://10.129.177.9/admin.php
[Manual login attempt]
username=admin password=admin
[Success] Flag page displayed.
```

---

## 8. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "preignition_hidden_admin_default_creds",
	"input_signals": [
		"HTTP service exposed on 80/tcp",
		"Gobuster discovered /admin.php with 200 OK",
		"Admin login accepted default credentials"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Active Scanning",
			"confidence": 0.95,
			"evidence": "Nmap service and version detection"
		},
		{
			"step": 2,
			"tactic": "reconnaissance",
			"technique": "Web Site Structure Discovery",
			"confidence": 0.97,
			"evidence": "Gobuster identified hidden admin endpoint"
		},
		{
			"step": 3,
			"tactic": "initial_access",
			"technique": "Valid Accounts (Default Credentials)",
			"confidence": 0.9,
			"evidence": "admin:admin succeeded on /admin.php"
		}
	],
	"hypotheses": [
		"Other admin endpoints may use same weak/default credential policy",
		"Credential reuse may exist across SMB, SSH, or panel services",
		"If no lockout/rate-limit exists, brute-force risk is elevated"
	],
	"uncertainties": [
		"Privilege level behind admin panel not fully validated",
		"Unknown whether this credential is shared by other accounts",
		"No evidence yet of MFA or account lockout controls"
	],
	"tool_calls": [
		{"name": "web_surface_mapper", "priority": "high"},
		{"name": "auth_policy_tester", "priority": "high"},
		{"name": "credential_reuse_probe", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Remove default credentials and rotate admin password",
			"Restrict direct access to admin endpoints",
			"Enable account lockout/rate limiting"
		],
		"hardening": [
			"Enforce strong password and MFA policy",
			"Hide or segment admin panel from public exposure",
			"Run recurring web content discovery tests in CI"
		],
		"monitoring": [
			"Alert on repeated auth failures and credential stuffing patterns",
			"Track scans targeting common admin paths",
			"Monitor successful admin logins from unusual source IPs"
		]
	}
}
```

---

## 9. Why This Matters for Your Dataset Goal

This format trains the model to:
- reason from observable recon evidence,
- form competing hypotheses,
- plan tool calls,
- and end with mitigation, not only exploitation.

That aligns exactly with your target behavior: offensive capability plus defensive decision support.
