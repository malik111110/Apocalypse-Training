# HTB Ignition - Magento Enumeration and Weak Credential Access

Scope: authorized HTB lab only.
Goal: identify virtual host dependency, discover hidden admin endpoint, and validate weak credential exposure.

---

## 1. Investigation Objective

1. Confirm service on port 80.
2. Capture redirect behavior and identify expected hostname.
3. Enumerate hidden web paths.
4. Validate authentication weakness on Magento admin panel.

---

## 2. Service Identification

```bash
nmap -sV -p 80 <TARGET_IP>
```

Expected evidence:
- `80/tcp open http nginx 1.14.2`

Task answer:
- service version on port 80: `nginx 1.14.2`

---

## 3. HTTP Behavior and Virtual Host Discovery

```bash
curl -v http://<TARGET_IP>
```

Key signal:
- server returns `HTTP/1.1 302 Found`
- redirect indicates hostname-based routing requirement

Identified host:
- `ignition.htb`

Add local mapping:

```bash
echo "<TARGET_IP> ignition.htb" | sudo tee -a /etc/hosts
```

---

## 4. Directory Enumeration

```bash
gobuster dir -u http://ignition.htb -w /usr/share/wordlists/dirb/common.txt
```

Critical discovery:
- `/admin` endpoint present and accessible

This endpoint leads to a Magento admin login interface.

---

## 5. Authentication Hypothesis and Validation

Observed context:
- Magento admin panel exposed publicly.
- Weak/default credentials are plausible in beginner-lab deployment.

Validated pair:
- username: `admin`
- password: `qwerty123`

Result:
- successful admin authentication.

---

## 6. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sV -p 80 10.129.XX.XX
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2

analyst@kali:~$ curl -v http://10.129.XX.XX
> GET / HTTP/1.1
< HTTP/1.1 302 Found
< Location: http://ignition.htb/

analyst@kali:~$ echo "10.129.XX.XX ignition.htb" | sudo tee -a /etc/hosts
10.129.XX.XX ignition.htb

analyst@kali:~$ gobuster dir -u http://ignition.htb -w /usr/share/wordlists/dirb/common.txt
===============================================================
/admin                (Status: 200) [Size: 7094]
===============================================================

Browser: http://ignition.htb/admin
Login success with admin:qwerty123
```

---

## 7. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "ignition_magento_weak_admin_creds",
	"input_signals": [
		"nginx 1.14.2 exposed on port 80",
		"HTTP 302 redirect reveals required virtual host ignition.htb",
		"Gobuster discovered /admin endpoint",
		"Magento admin accepted weak credential pair"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Service and Web Discovery",
			"confidence": 0.96,
			"evidence": "nmap + curl identified stack and redirect behavior"
		},
		{
			"step": 2,
			"tactic": "reconnaissance",
			"technique": "Web Site Structure Discovery",
			"confidence": 0.93,
			"evidence": "gobuster found admin endpoint"
		},
		{
			"step": 3,
			"tactic": "initial_access",
			"technique": "Valid Accounts (Weak Credentials)",
			"confidence": 0.9,
			"evidence": "admin panel login successful with weak password"
		}
	],
	"hypotheses": [
		"Credential reuse may exist across additional administrative services",
		"Magento admin endpoint lacks brute-force protections",
		"Further post-auth config weaknesses may allow deeper compromise"
	],
	"uncertainties": [
		"Unknown if MFA or IP restrictions are configured elsewhere",
		"Privilege scope within Magento backend not fully validated",
		"No direct evidence yet of audit controls for admin login anomalies"
	],
	"tool_calls": [
		{"name": "vhost_redirect_analyzer", "priority": "high"},
		{"name": "web_admin_surface_mapper", "priority": "high"},
		{"name": "auth_control_assessor", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Rotate admin credentials and remove weak/default passwords",
			"Restrict /admin access by source IP or VPN",
			"Enable account lockout and rate limiting"
		],
		"hardening": [
			"Enforce strong password policy and MFA for admin accounts",
			"Hide or relocate administrative endpoints where feasible",
			"Continuously scan for exposed management routes"
		],
		"monitoring": [
			"Alert on repeated failed admin logins",
			"Track access to /admin from new geolocations or IP ranges",
			"Monitor redirect and vhost anomalies"
		]
	}
}
```
