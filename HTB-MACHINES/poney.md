# HTB Pennyworth - Jenkins Default Credential to Script Console RCE

Scope: authorized HTB lab only.
Focus: Jenkins exposure on HTTP/8080, weak/default authentication, and command execution through script console.

---

## 1. Investigation Objective

1. Discover externally exposed management services.
2. Validate Jenkins authentication posture.
3. Confirm command execution through script console.
4. Assess impact and sensitive artifact exposure.

---

## 2. Recon and Service Fingerprinting

```bash
nmap -sC -sV -Pn -p 8080 <TARGET_IP>
```

Key finding:
- Jenkins service exposed on 8080/tcp.

Portal URL:

```text
http://<TARGET_IP>:8080
```

---

## 3. Authentication Weakness Validation

In this challenge path, weak/default credential testing against Jenkins login yields administrative access.

Example candidate list:
- `admin:admin`
- `admin:password`
- `jenkins:jenkins`

Confirmed credential pair grants dashboard access.

---

## 4. Script Console Execution

Jenkins script console endpoint:

```text
http://<TARGET_IP>:8080/script
```

From authenticated admin session, Groovy execution can run OS commands in host context.

Listener setup (lab):

```bash
nc -lvnp <PORT>
```

Execution result:
- reverse shell/session callback established.

---

## 5. Post-Exploitation Validation

Inside shell:

```bash
whoami
pwd
ls
cat flag.txt
```

---

## 6. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn -p 8080 10.10.10.XX
PORT     STATE SERVICE VERSION
8080/tcp open  http    Jetty/Jenkins

Browser evidence:
http://10.10.10.XX:8080 -> Jenkins login

Credential test:
username: <default/admin candidate>
password: <matched weak credential>
Result: dashboard access granted

Script console:
http://10.10.10.XX:8080/script

analyst@kali:~$ nc -lvnp 4444
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.XX]
$ whoami
jenkins
$ cat flag.txt
HTB{...flag...}
```

---

## 7. Analyst Reasoning Chain (Dataset-Style)

```json
{
    "scenario": "pennyworth_jenkins_default_credential_script_console_exec",
    "input_signals": [
        "Jenkins service exposed on 8080/tcp",
        "Weak/default credential accepted",
        "Authenticated access to /script console",
        "OS-level command execution and shell callback achieved"
    ],
    "attack_chain": [
        {
            "step": 1,
            "tactic": "reconnaissance",
            "technique": "Management Service Discovery",
            "confidence": 0.95,
            "evidence": "nmap and browser identified Jenkins endpoint"
        },
        {
            "step": 2,
            "tactic": "initial_access",
            "technique": "Valid Accounts (Default/Weak Credentials)",
            "confidence": 0.9,
            "evidence": "dashboard login succeeded with weak credential"
        },
        {
            "step": 3,
            "tactic": "execution",
            "technique": "Command and Scripting Interpreter (Groovy)",
            "confidence": 0.94,
            "evidence": "script console executed OS commands and produced shell"
        }
    ],
    "hypotheses": [
        "Additional Jenkins jobs or credentials may expose broader infrastructure",
        "Build agents may allow lateral movement to adjacent hosts",
        "Same weak credential policy may affect other internal admin panels"
    ],
    "uncertainties": [
        "Unknown if Jenkins runs with elevated host privileges",
        "No full inventory of stored Jenkins secrets was performed",
        "Audit logging and alerting coverage for script console is not validated"
    ],
    "tool_calls": [
        {"name": "jenkins_auth_policy_auditor", "priority": "high"},
        {"name": "jenkins_script_console_guardrail_check", "priority": "high"},
        {"name": "ci_secret_exposure_mapper", "priority": "medium"}
    ],
    "mitigation": {
        "immediate": [
            "Disable weak/default credentials and rotate all Jenkins secrets",
            "Restrict Jenkins access to trusted admin network paths",
            "Disable script console for non-breakglass workflows"
        ],
        "hardening": [
            "Enforce MFA/SSO for Jenkins administrators",
            "Run Jenkins under least-privilege service account",
            "Harden plugin set and keep Jenkins version patched"
        ],
        "monitoring": [
            "Alert on script console usage and new admin logins",
            "Monitor suspicious outbound callbacks from Jenkins host",
            "Track changes to credentials, jobs, and global security settings"
        ]
    }
}
```
