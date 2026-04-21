# DNS Enumeration Playbook

> DNS is the backbone of the internet and leaks enormous intelligence: hostnames, internal naming conventions, mail infrastructure, cloud providers, and sometimes internal IPs. Run this phase against every in-scope domain.

---

## 1. Basic DNS Resolution

```bash
# Forward lookup
nslookup <domain>
dig <domain> ANY +noall +answer       # all record types
dig <domain> A +short                  # IPv4 only
dig <domain> AAAA +short               # IPv6
dig <domain> MX +short                 # mail exchangers
dig <domain> NS +short                 # nameservers
dig <domain> TXT +short               # SPF, DMARC, verification tokens
dig <domain> SOA                       # Start of Authority → primary NS, admin email

# Reverse lookup (PTR)
dig -x 10.10.10.5
nslookup 10.10.10.5
```

**Interpret SOA:** `admin.domain.com` in SOA → admin@domain.com. Leaks internal email structure.
**Interpret TXT:** SPF record shows all mail-sending infrastructure. DMARC policy shows enforcement level.

---

## 2. Zone Transfer (AXFR) — Critical Finding

A successful zone transfer dumps the entire DNS zone: all hostnames, IPs, internal names, subdomains.

```bash
# Step 1: Find authoritative nameservers
dig NS <domain> +short

# Step 2: Attempt zone transfer against each NS
dig AXFR <domain> @<nameserver>          # if successful → gold mine
host -l <domain> <nameserver>            # alternative syntax
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=<domain> -p 53 <nameserver>

# Example:
dig AXFR corp.local @10.10.10.1
# Success looks like:
# corp.local.     600  IN  A      10.10.10.5
# dc01.corp.local 600  IN  A      10.10.10.5
# mail.corp.local 600  IN  A      10.10.10.20
# vpn.corp.local  600  IN  A      10.10.10.30
```

**Finding:** Zone transfer allowed → CRITICAL. Report as `DNS Zone Transfer Enabled (CWE-200)`.

---

## 3. Subdomain Enumeration

### 3.1 Brute Force (dictionary-based)
```bash
# gobuster
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -t 100 --wildcard

# ffuf
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u https://FUZZ.<domain>/ -mc 200,301,302,403 -t 100

# dnsrecon
dnsrecon -d <domain> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt

# fierce
fierce --domain <domain> --wordlist /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt

# subfinder (passive)
subfinder -d <domain> -o subs.txt
subfinder -d <domain> -all -recursive -o subs_full.txt

# amass (comprehensive)
amass enum -d <domain> -o amass_subs.txt
amass enum -passive -d <domain>           # passive only (no active DNS queries)
```

### 3.2 Certificate Transparency Logs (passive, no network noise)
```bash
curl -s "https://crt.sh/?q=%.<domain>&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct_subs.txt
```

### 3.3 Common Wildcard Detection
```bash
# Test for wildcard DNS (random subdomain resolves → wildcard exists)
dig RANDOMSTRING12345.<domain> A +short
# If resolves → wildcard DNS. Tools need --wildcard flag to handle this.
```

---

## 4. DNS Record Deep Dive

```bash
# All common record types in one shot
for type in A AAAA MX NS TXT SOA CNAME SRV PTR NAPTR CAA; do
  echo "=== $type ==="
  dig <domain> $type +short
done

# SRV records (reveal services: LDAP, Kerberos, SIP, XMPP)
dig _ldap._tcp.<domain> SRV          # AD domain controllers
dig _kerberos._tcp.<domain> SRV      # Kerberos KDC
dig _kpasswd._tcp.<domain> SRV       # Kerberos password change
dig _msdcs.<domain> SRV              # Microsoft Domain Controller SRV

# DMARC / SPF analysis
dig _dmarc.<domain> TXT              # DMARC policy
dig <domain> TXT | grep -i spf       # SPF → mail sender whitelist

# DKIM
dig default._domainkey.<domain> TXT  # DKIM public key
```

**Findings from TXT records:**
- `v=spf1 include:amazonses.com` → uses AWS SES for mail
- `v=spf1 ip4:10.0.0.0/8` → internal IP range leaked
- `google-site-verification=...` → uses Google Workspace
- `MS=ms...` → Office 365 tenant

---

## 5. Reverse DNS / PTR Enumeration

```bash
# Reverse lookup on a subnet (identify hostnames from IPs)
for ip in $(seq 1 254); do
  result=$(dig -x 10.10.10.$ip +short)
  [ -n "$result" ] && echo "10.10.10.$ip → $result"
done

# dnsrecon reverse sweep
dnsrecon -r 10.10.10.0/24 -t rvl

# nmap with reverse DNS
nmap -sn -R 10.10.10.0/24 --dns-servers <dns_server>
```

---

## 6. DNS Cache Snooping

Check if a nameserver has recently resolved a domain (reveals what a target organization uses):
```bash
# Non-recursive query — if resolved, it's in cache
dig @<nameserver> <domain_to_check> A +norecurse
# Response with answer → target has visited/resolved this domain recently
```

---

## 7. DNSSEC Enumeration

```bash
dig <domain> DNSKEY              # DNSSEC keys
dig <domain> DS                  # delegation signer
dig <domain> NSEC                # next secure → reveals all DNS names in zone (zone walking)
dig <domain> NSEC3PARAM         # NSEC3 parameters

# NSEC zone walking (if not NSEC3):
ldns-walk <domain>               # enumerate all DNS names via NSEC chaining
```

---

## 8. DNS Amplification & Tunneling Detection Markers

```bash
# Check for open resolver (security misconfiguration)
dig @<target_dns> google.com         # if resolves external domains → open resolver

# Check recursion
dig @<target_dns> <domain> +recurse
```

---

## 9. Tool: dnsrecon (comprehensive)

```bash
dnsrecon -d <domain> -t std          # standard (A, AAAA, NS, SOA, MX, SRV, TXT)
dnsrecon -d <domain> -t axfr         # zone transfer attempt
dnsrecon -d <domain> -t bing         # Bing-based subdomain search
dnsrecon -d <domain> -t crt          # cert transparency
dnsrecon -d <domain> -t zonewalk     # NSEC zone walk
dnsrecon -d <domain> -t snoop --db /tmp/dict.txt  # cache snooping
```

---

## 10. Findings → Vulnerability Mapping

| Finding | Severity | CVE / CWE | Mitigation |
|---------|----------|-----------|------------|
| Zone transfer allowed | Critical | CWE-200 | Restrict AXFR to authorized secondaries only |
| Open DNS resolver | High | CWE-400 | Disable recursion for external clients |
| Missing DNSSEC | Medium | — | Implement DNSSEC for zone signing |
| SPF missing / permissive | Medium | — | Implement strict SPF (`-all`) |
| DMARC missing / `p=none` | Medium | — | Enforce DMARC (`p=reject`) |
| Wildcard DNS resolves | Low/Info | — | Review wildcard necessity; can aid phishing |
| Internal IPs in TXT/PTR | Low | CWE-200 | Remove internal IP exposure from public DNS |
