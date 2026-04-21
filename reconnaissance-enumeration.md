# Reconnaissance Enumeration Playbook (ATT&CK Aligned, Dataset-Ready)

> Purpose: produce high-quality reconnaissance traces for model training and analyst runbooks.
> Audience: authorized red team, purple team, detection engineering, and simulation programs.
> Legal boundary: run only with written authorization and approved scope.

---

## 0. Scope, Safety, and Evidence Discipline

### 0.1 Mandatory Engagement Metadata

```bash
cat > scope.txt << 'EOF'
Primary domain: example.com
In-scope CIDR: 203.0.113.0/24
Authorized contacts: secops@example.com
Allowed testing window: 09:00-17:00 UTC
Disallowed actions: destructive exploit, credential stuffing, production phishing, service disruption
Evidence retention path: ./evidence
EOF
```

### 0.2 Evidence Capture Wrapper

Use one consistent wrapper so every command is timestamped and tied to a technique ID.

```bash
mkdir -p evidence

run_recon() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/recon.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}

# Example:
run_recon "T1590.002" "dns_a_record" dig example.com A +short
```

### 0.3 Training Record Minimum Fields

Each technique execution should capture:

1. Technique ID and name.
2. Real-world scenario context.
3. Exact command(s) executed.
4. Raw or condensed tool result.
5. Analyst interpretation and confidence.
6. Immediate mitigation hint.

---

## 1. T1595 Active Scanning

### T1595 Active Scanning (Parent)

Scenario:
- External attack surface mapping before initial access attempt.

Execution baseline:

```bash
run_recon "T1595" "baseline_host_discovery" nmap -sn 203.0.113.0/24
run_recon "T1595" "baseline_top_ports" nmap -sS --top-ports 1000 -T4 203.0.113.0/24
```

Expected result pattern:

```text
Nmap scan report for 203.0.113.21
Host is up (0.021s latency).
Not shown: 996 filtered tcp ports
22/tcp open ssh
80/tcp open http
443/tcp open https
8443/tcp open https-alt
```

### T1595.001 Scanning IP Blocks

Scenario:
- Adversary maps a newly acquired target ASN and wants reachable hosts plus management ports.

Command execution:

```bash
run_recon "T1595.001" "ping_sweep" nmap -sn 203.0.113.0/24 -oA evidence/t1595_001_ping
run_recon "T1595.001" "top1000" nmap -sS --top-ports 1000 -T4 203.0.113.0/24 -oA evidence/t1595_001_top
run_recon "T1595.001" "high_speed_confirm" masscan 203.0.113.0/24 -p22,80,443,3389,8443 --rate 3000
```

Example tool results:

```text
Discovered open port 22/tcp on 203.0.113.21
Discovered open port 443/tcp on 203.0.113.21
Discovered open port 3389/tcp on 203.0.113.44
```

Training signals to keep:
- Host count increase/decrease over time.
- High-risk exposed services: 22, 3389, 445, 8443.

### T1595.002 Vulnerability Scanning

Scenario:
- Adversary validates whether discovered software versions align with known CVEs.

Command execution:

```bash
run_recon "T1595.002" "nmap_vuln" nmap -sV --script vuln 203.0.113.21 -oN evidence/t1595_002_nmap_vuln.txt
run_recon "T1595.002" "nuclei_web" nuclei -u https://portal.example.com -severity low,medium,high,critical -o evidence/t1595_002_nuclei.txt
```

Example tool results:

```text
[http-cve-2021-41773] [http] [high] https://portal.example.com/cgi-bin/
[ssl-weak-cipher-suites] [ssl] [medium] portal.example.com:443
```

Training signals to keep:
- CVE ID, severity, service/version tuple.
- Confirmed vs potential finding distinction.

### T1595.003 Wordlist Scanning

Scenario:
- Adversary brute-enumerates hidden paths and virtual hosts after finding a public web app.

Command execution:

```bash
run_recon "T1595.003" "ffuf_dirs" ffuf -u https://portal.example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -o evidence/t1595_003_ffuf.json
run_recon "T1595.003" "gobuster_vhost" gobuster vhost -u https://portal.example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 40
```

Example tool results:

```text
/admin           [Status: 403, Size: 512]
/backup.zip      [Status: 200, Size: 10485760]
intranet.example.com [Status: 200]
```

Training signals to keep:
- Sensitive artifact patterns: backup, export, config, old.
- Distinguish 403 discovery from 200 exposure.

---

## 2. T1592 Gather Victim Host Information

### T1592 Gather Victim Host Information (Parent)

Scenario:
- Adversary builds host-level targeting profile: OS, software, hardware class, and client traits.

### T1592.001 Hardware

Scenario:
- Identify host device family and likely enterprise role.

Command execution:

```bash
run_recon "T1592.001" "os_fingerprint" nmap -O 203.0.113.21
run_recon "T1592.001" "snmp_sysdescr" snmpwalk -v2c -c public 203.0.113.10 1.3.6.1.2.1.1.1.0
```

Example tool results:

```text
Running: Linux 5.X
Device type: general purpose
SNMPv2-MIB::sysDescr.0 = Cisco Adaptive Security Appliance Version 9.16
```

Training signals to keep:
- Device class: firewall, router, VM host, workstation.

### T1592.002 Software

Scenario:
- Enumerate exposed software/services and versions for exploitability mapping.

Command execution:

```bash
run_recon "T1592.002" "service_versions" nmap -sV -p 22,80,443,445,3389 203.0.113.21
run_recon "T1592.002" "http_headers" curl -skI https://portal.example.com
run_recon "T1592.002" "web_fingerprint" whatweb https://portal.example.com
```

Example tool results:

```text
22/tcp open  ssh     OpenSSH 8.2p1
443/tcp open https   nginx 1.18.0
X-Powered-By: Express
```

Training signals to keep:
- Service and version pairing.
- Security stack clues from headers/plugins.

### T1592.003 Firmware

Scenario:
- Target appears to expose network appliance web panel and firmware metadata.

Command execution:

```bash
run_recon "T1592.003" "firmware_banner" curl -sk https://gateway.example.com/ | grep -Ei "firmware|version|build"
run_recon "T1592.003" "ssl_cert_clues" nmap -p443 --script ssl-cert gateway.example.com
```

Example tool results:

```text
Firmware Version: 11.0.4 Build 223
Subject: commonName=gateway.example.com/organizationName=Example Networks
```

Training signals to keep:
- Firmware version age and vendor line.

### T1592.004 Client Configurations

Scenario:
- Public client assets leak environment configuration and telemetry endpoints.

Command execution:

```bash
run_recon "T1592.004" "robots" curl -s https://portal.example.com/robots.txt
run_recon "T1592.004" "security_txt" curl -s https://portal.example.com/.well-known/security.txt
run_recon "T1592.004" "js_config" curl -s https://portal.example.com/static/app.js | grep -Ei "api|sentry|env|region"
```

Example tool results:

```text
Disallow: /internal-api/
Contact: mailto:security@example.com
window.API_BASE_URL="https://api-prod.example.com"
```

Training signals to keep:
- Endpoint naming and environment tags: prod, stage, internal.

---

## 3. T1589 Gather Victim Identity Information

### T1589 Gather Victim Identity Information (Parent)

Scenario:
- Build identity graph to support targeted lures and account-focused campaigns.

### T1589.001 Credentials

Scenario:
- Authorized intelligence workflow checks historical credential exposure for target domain.

Command execution (authorized data sources only):

```bash
run_recon "T1589.001" "approved_breach_search" jq -r 'select(.domain=="example.com") | [.email,.source,.first_seen] | @tsv' approved_breach_export.jsonl | head
run_recon "T1589.001" "password_pattern_stats" awk -F '\t' '{print $1}' approved_breach_export.tsv | sed 's/.*@//' | sort | uniq -c
```

Example tool results:

```text
alice@example.com  CollectionX  2024-02-14
bob@example.com    CollectionY  2023-11-03
```

Training signals to keep:
- Domain-linked exposure count.
- Age of leak and source confidence.

### T1589.002 Email Addresses

Scenario:
- Enumerate valid target email formats for social engineering preparation.

Command execution:

```bash
run_recon "T1589.002" "theharvester" theHarvester -d example.com -b bing,crtsh,duckduckgo -l 500 -f evidence/t1589_002_theharvester.html
```

Example tool results:

```text
Emails found:
security@example.com
john.doe@example.com
it-support@example.com
```

Training signals to keep:
- Naming patterns: first.last, first initial + last, role aliases.

### T1589.003 Employee Names

Scenario:
- Collect public employee names to map business units and probable privileged roles.

Command execution:

```bash
run_recon "T1589.003" "about_page" curl -s https://example.com/about
run_recon "T1589.003" "leadership_page" curl -s https://example.com/leadership | grep -Eo '>[A-Z][a-z]+ [A-Z][a-z]+'
```

Example tool results:

```text
Chief Information Security Officer: Sarah Malik
Director of Infrastructure: Daniel Ortiz
```

Training signals to keep:
- Role-to-person mapping for likely access tier.

---

## 4. T1590 Gather Victim Network Information

### T1590 Gather Victim Network Information (Parent)

Scenario:
- Build network map for external entry points, dependencies, and defensive architecture.

### T1590.001 Domain Properties

Scenario:
- Enumerate domain ownership, registrar, expiry, nameservers, and abuse contacts.

Command execution:

```bash
run_recon "T1590.001" "whois" whois example.com
run_recon "T1590.001" "rdap" rdap example.com
```

Example tool results:

```text
Registrar: Example Registrar LLC
Name Server: NS1.CLOUDFLARE.COM
Registrar Abuse Contact Email: abuse@registrar.example
```

Training signals to keep:
- Registrar changes, expiry windows, nameserver provider shifts.

### T1590.002 DNS

Scenario:
- Resolve records that reveal mail infrastructure, SaaS usage, and subdomain inventory.

Command execution:

```bash
run_recon "T1590.002" "dns_a" dig example.com A +short
run_recon "T1590.002" "dns_mx" dig example.com MX +short
run_recon "T1590.002" "dns_txt" dig example.com TXT +short
run_recon "T1590.002" "dns_ns" dig example.com NS +short
```

Example tool results:

```text
10 mx1.mailprovider.net.
"v=spf1 include:_spf.google.com include:mailgun.org -all"
```

Training signals to keep:
- Third-party providers from MX/SPF includes.

### T1590.003 Network Trust Dependencies

Scenario:
- Identify trusted third parties that may provide indirect access paths.

Command execution:

```bash
run_recon "T1590.003" "cname_chain" dig app.example.com CNAME +short
run_recon "T1590.003" "http_dependency_headers" curl -skI https://app.example.com | grep -Ei "server|via|x-served-by|x-cache"
run_recon "T1590.003" "spf_dependencies" dig example.com TXT +short | grep -Ei "include:"
```

Example tool results:

```text
app.example.com.cdn.vendor.net.
via: 1.1 varnish
include:_spf.salesforce.com include:spf.protection.outlook.com
```

Training signals to keep:
- CDN/WAF/Email/SSO trust chain.

### T1590.004 Network Topology

Scenario:
- Infer network path, edge filtering, and likely segmentation boundaries.

Command execution:

```bash
run_recon "T1590.004" "traceroute" traceroute -n 203.0.113.21
run_recon "T1590.004" "mtr" mtr -rw -c 50 203.0.113.21
```

Example tool results:

```text
Hop 6: 198.51.100.1 (Transit ISP)
Hop 7: 203.0.113.1 (Target edge firewall)
Hop 8: 203.0.113.21 (Target host)
Packet loss spike at hop 7: 12%
```

Training signals to keep:
- Edge transition hop and recurring latency/loss boundaries.

### T1590.005 IP Addresses

Scenario:
- Expand known domains into active IP inventory and hosting footprint.

Command execution:

```bash
run_recon "T1590.005" "amass_intel" amass intel -d example.com
run_recon "T1590.005" "subfinder" subfinder -d example.com -all -recursive
run_recon "T1590.005" "dnsx_resolve" dnsx -l subdomains.txt -a -resp -silent
```

Example tool results:

```text
vpn.example.com [203.0.113.44]
mail.example.com [203.0.113.20]
api.example.com [198.51.100.77]
```

Training signals to keep:
- Hosting spread across providers and geographies.

### T1590.006 Network Security Appliances

Scenario:
- Identify exposed security controls and their likely vendor/version profile.

Command execution:

```bash
run_recon "T1590.006" "banner_ssl" nmap -sV --script banner,ssl-cert 203.0.113.1
run_recon "T1590.006" "waf_detect" wafw00f https://portal.example.com
```

Example tool results:

```text
443/tcp open https Fortinet FortiGate SSL VPN
The site is behind Cloudflare (Cloudflare Inc.)
```

Training signals to keep:
- Firewall, WAF, proxy, bastion fingerprints.

---

## 5. T1591 Gather Victim Org Information

### T1591 Gather Victim Org Information (Parent)

Scenario:
- Build organization-level profile for targeting timing, roles, and partner dependencies.

### T1591.001 Determine Physical Locations

Scenario:
- Identify offices, datacenters, and legal jurisdictions relevant to operations.

Command execution:

```bash
run_recon "T1591.001" "contact_page" curl -s https://example.com/contact
run_recon "T1591.001" "office_mentions" curl -s https://example.com/about | grep -Ei "office|headquarters|location|region"
```

Example tool results:

```text
Headquarters: Paris, France
Regional office: Montreal, Canada
```

Training signals to keep:
- Country and city mapping to jurisdiction and timezone.

### T1591.002 Business Relationships

Scenario:
- Infer suppliers, MSPs, and strategic partners with potential trust access.

Command execution:

```bash
run_recon "T1591.002" "vendor_mentions" curl -s https://example.com/partners
run_recon "T1591.002" "spf_partner_clues" dig example.com TXT +short | grep -Ei "include:"
```

Example tool results:

```text
Strategic partner: Example MSP Services
SPF include:spf.protection.outlook.com
SPF include:mail.zendesk.com
```

Training signals to keep:
- Third-party names associated with identity/email/network trust.

### T1591.003 Identify Business Tempo

Scenario:
- Model operational cadence to identify peak and low-observability periods.

Command execution:

```bash
run_recon "T1591.003" "status_history" curl -s https://status.example.com/history
run_recon "T1591.003" "release_notes" curl -s https://example.com/changelog | grep -Eo '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -20
```

Example tool results:

```text
Release dates: 2026-01-05, 2026-01-19, 2026-02-02
Planned maintenance window: Sundays 01:00-03:00 UTC
```

Training signals to keep:
- Change windows and support hour patterns.

### T1591.004 Identify Roles

Scenario:
- Identify role categories with access to key systems and business processes.

Command execution:

```bash
run_recon "T1591.004" "careers_roles" curl -s https://example.com/careers | grep -Ei "administrator|engineer|security|finance|helpdesk"
run_recon "T1591.004" "leadership_roles" curl -s https://example.com/leadership | grep -Ei "Chief|Director|Head"
```

Example tool results:

```text
Open role: Identity and Access Management Engineer
Open role: Senior Helpdesk Administrator
Leadership: Chief Financial Officer
```

Training signals to keep:
- Role-to-function mapping for privilege likelihood.

---

## 6. T1598 Phishing for Information (Sanctioned Simulation Only)

### T1598 Phishing for Information (Parent)

Scenario:
- Controlled simulation to measure human process weaknesses and reporting behavior.

Rules:
1. Written approval and legal review are mandatory.
2. Use benign payloads only.
3. Do not collect real credentials unless explicitly approved in writing.

### T1598.001 Spearphishing Service

Scenario:
- Send approved simulation via corporate messaging service to test verification behavior.

Command execution (simulation tooling):

```bash
run_recon "T1598.001" "service_campaign" python3 simulate_campaign.py --channel service --target-file approved_targets.csv --template "MFA policy notice" --collect clicks_only
```

Example tool results:

```text
Targets: 120
Delivered: 118
Clicks: 17
Reports to SOC: 9
```

Training signals to keep:
- Delivery, click, report, escalation timing.

### T1598.002 Spearphishing Attachment

Scenario:
- Benign attachment simulation tests open/report behavior.

Command execution:

```bash
run_recon "T1598.002" "attachment_campaign" python3 simulate_campaign.py --channel email --attachment benign_awareness.pdf --target-file approved_targets.csv --collect open_only
```

Example tool results:

```text
Delivered: 200
Opened attachment: 63
Reported: 21
```

Training signals to keep:
- Department-level open/report deltas.

### T1598.003 Spearphishing Link

Scenario:
- Controlled links to internal awareness landing page with per-user tokenization.

Command execution:

```bash
run_recon "T1598.003" "link_campaign" python3 simulate_campaign.py --channel email --link https://awareness.example.internal/check --target-file approved_targets.csv --collect click_and_report
```

Example tool results:

```text
Unique clicks: 34
Repeat clicks: 7
SOC reports: 18
Median report time: 11m
```

Training signals to keep:
- Time-to-report and repeat-click pattern.

### T1598.004 Spearphishing Voice

Scenario:
- Vishing tabletop simulation to validate callback and identity verification process.

Command execution:

```bash
run_recon "T1598.004" "voice_tabletop" python3 voice_sim_metrics.py --scenario helpdesk_reset --participants approved_voice_targets.csv
```

Example tool results:

```text
Calls simulated: 25
Verification bypass attempts accepted: 3
Verified callback protocol followed: 19
```

Training signals to keep:
- Verification failure points and script adherence.

---

## 7. T1597 Search Closed Sources

### T1597 Search Closed Sources (Parent)

Scenario:
- Pull non-public intelligence from licensed platforms to enrich target profile.

### T1597.001 Threat Intel Vendors

Scenario:
- Query commercial TI portal for sector targeting patterns and actor overlap.

Command execution:

```bash
run_recon "T1597.001" "vendor_search" curl -s -H "Authorization: Bearer $VENDOR_TOKEN" "https://ti.vendor.local/api/v1/search?query=example.com"
```

Example tool results:

```text
Actor overlap: 2 groups targeting finance sector in last 90 days
Observed TTP trend: credential harvesting + VPN targeting
Confidence: medium
```

Training signals to keep:
- Trend frequency, attribution confidence, campaign recency.

### T1597.002 Purchase Technical Data

Scenario:
- Use paid passive DNS/scan feeds to recover historical infrastructure not visible today.

Command execution:

```bash
run_recon "T1597.002" "paid_pdns" curl -s -H "X-API-Key: $PDNS_TOKEN" "https://pdns.vendor.local/history?domain=example.com"
run_recon "T1597.002" "paid_scan_feed" curl -s -H "Authorization: Bearer $SCAN_TOKEN" "https://scanfeed.vendor.local/assets?query=example.com"
```

Example tool results:

```text
Historical host: legacy-vpn.example.com -> 198.51.100.42 (last seen 2025-11)
Open service history: 8443/tcp exposed intermittently over 6 months
```

Training signals to keep:
- Historical vs current exposure differences.

---

## 8. T1596 Search Open Technical Databases

### T1596 Search Open Technical Databases (Parent)

Scenario:
- Mine open internet datasets to enrich DNS, cert, and exposure intelligence.

### T1596.001 DNS/Passive DNS

Scenario:
- Use passive DNS to map historical subdomains and IP pivots.

Command execution:

```bash
run_recon "T1596.001" "passive_dns" curl -s "https://api.example-pdns.local/query?domain=example.com&apikey=$PDNS_TOKEN"
```

Example tool results:

```text
api-old.example.com -> 198.51.100.66 (first seen 2024-03)
vpn.example.com -> 203.0.113.44 (last seen 2026-04)
```

Training signals to keep:
- First seen, last seen, and pivotable infra lineage.

### T1596.002 WHOIS

Scenario:
- Extract registration metadata and related assets from open WHOIS/RDAP.

Command execution:

```bash
run_recon "T1596.002" "whois" whois example.com
run_recon "T1596.002" "rdap" rdap example.com
```

Example tool results:

```text
OrgName: Example Corp
CIDR: 203.0.113.0/24
NameServer: ns1.cloudflare.com
```

Training signals to keep:
- Related netblocks and ownership metadata consistency.

### T1596.003 Digital Certificates

Scenario:
- Use CT logs to discover additional subdomains and deprecated services.

Command execution:

```bash
run_recon "T1596.003" "crtsh" curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

Example tool results:

```text
api.example.com
legacy-api.example.com
vpn.example.com
```

Training signals to keep:
- Cert SAN expansion and stale endpoint discovery.

### T1596.004 CDNs

Scenario:
- Identify CDN fronting and potential origin exposure patterns.

Command execution:

```bash
run_recon "T1596.004" "cname_cdn" dig app.example.com CNAME +short
run_recon "T1596.004" "cdn_headers" curl -skI https://app.example.com | grep -Ei "server|cf-ray|x-cache|x-served-by"
```

Example tool results:

```text
app.example.com.cdn.vendor.net.
cf-ray: 87af3d0f2a4f1234-CDG
x-cache: HIT
```

Training signals to keep:
- CDN provider, cache behavior, and regional edge hints.

### T1596.005 Scan Databases

Scenario:
- Query open scan indexes for exposed ports, banners, and cert pivots.

Command execution:

```bash
run_recon "T1596.005" "shodan_query" shodan search 'hostname:"example.com"'
run_recon "T1596.005" "censys_query" censys search 'services.tls.certificates.leaf_data.subject.common_name: example.com'
```

Example tool results:

```text
203.0.113.21 443 nginx/1.18.0 title:"Example Portal"
203.0.113.44 8443 SSL VPN login page detected
```

Training signals to keep:
- Publicly indexed service drift vs live scan output.

---

## 9. T1593 Search Open Websites/Domains

### T1593 Search Open Websites/Domains (Parent)

Scenario:
- Collect open-source business and technical context to improve targeting realism.

### T1593.001 Social Media

Scenario:
- Extract publicly posted org details, tooling mentions, and campaign context.

Command execution:

```bash
run_recon "T1593.001" "social_query_log" bash -lc 'echo "Manual social search: company announcements, hiring, tool stack mentions"'
```

Example tool results:

```text
Post: "We migrated identity platform this quarter"
Post: "Hiring Senior Okta Administrator"
```

Training signals to keep:
- Platform/tool mentions linked to identity and infrastructure.

### T1593.002 Search Engines

Scenario:
- Use search engine indexing to locate exposed files and forgotten endpoints.

Command execution:

```bash
run_recon "T1593.002" "dork_list" bash -lc 'cat <<EOF
site:example.com filetype:pdf "internal"
site:example.com inurl:admin
site:example.com ext:bak OR ext:old
EOF'
```

Example tool results:

```text
Indexed file: https://example.com/docs/network-migration-internal.pdf
Indexed endpoint: https://portal.example.com/admin-old/
```

Training signals to keep:
- Indexed sensitive document patterns.

### T1593.003 Code Repositories

Scenario:
- Search public code for leaked endpoints, tokens, or internal references.

Command execution:

```bash
run_recon "T1593.003" "github_code_search" gh search code '"example.com" "api"' --limit 50
run_recon "T1593.003" "repo_secret_scan" trufflehog github --org example-org --json
```

Example tool results:

```text
repo:example-org/mobile-app file:config.js API_BASE=https://api-dev.example.com
Potential secret detected: high entropy token in ci.yml
```

Training signals to keep:
- Exposure type: endpoint leak vs secret leak.

---

## 10. T1681 Search Threat Vendor Data

### T1681 Search Threat Vendor Data

Scenario:
- Adversary studies threat reports (own campaigns and peers) to adapt future operations.

Command execution:

```bash
run_recon "T1681" "vendor_report_search" curl -s -H "Authorization: Bearer $TI_TOKEN" "https://reports.vendor.local/api/v1/reports?query=finance+vpn+credential+harvest"
run_recon "T1681" "ioc_lookup" curl -s -H "Authorization: Bearer $TI_TOKEN" "https://reports.vendor.local/api/v1/iocs?domain=example.com"
```

Example tool results:

```text
Report count: 14
Common initial vector: external remote services
Most observed technique cluster: T1078, T1110, T1595
```

Training signals to keep:
- Technique frequency trends and campaign adaptation indicators.

---

## 11. T1594 Search Victim-Owned Websites

### T1594 Search Victim-Owned Websites

Scenario:
- Deep crawl of victim-owned sites to map legacy paths, hidden assets, and exposure history.

Command execution:

```bash
run_recon "T1594" "wayback" waybackurls example.com
run_recon "T1594" "gau" gau example.com
run_recon "T1594" "crawl" hakrawler -url https://example.com -depth 2 -plain
run_recon "T1594" "httpx_triage" bash -lc 'cat evidence/*T1594* | sort -u | httpx -title -status-code -tech-detect -silent'
```

Example tool results:

```text
https://example.com/admin/
https://example.com/backup/config-2024.zip
https://legacy.example.com/login
```

Training signals to keep:
- Legacy endpoint survivorship and archived sensitive artifacts.

---

## 12. End-to-End Recon Sequence (Real-World Execution Order)

Use this order for realistic simulation data:

1. Passive external collection first:
   - T1596, T1593, T1590.001, T1590.002, T1591, T1589.
2. Victim-owned site and wordlist expansion:
   - T1594, T1595.003.
3. Controlled active reconnaissance:
   - T1595.001, T1595.002, T1590.004, T1590.006, T1592.
4. Intelligence enrichment:
   - T1597, T1681.
5. Sanctioned social simulation (if approved):
   - T1598.

---

## 13. Dataset-Oriented Output Contract

Use one record per command execution.

```json
{
  "technique": "T1595.003",
  "technique_name": "Wordlist Scanning",
  "scenario": "External web app path discovery after initial host mapping",
  "target": "portal.example.com",
  "command": "ffuf -u https://portal.example.com/FUZZ -w common.txt -mc 200,301,302,403",
  "tool_result": {
    "status": "success",
    "highlights": [
      "/admin [403]",
      "/backup.zip [200]"
    ]
  },
  "analyst_interpretation": "Backup artifact is likely sensitive and should be triaged immediately.",
  "confidence": 0.91,
  "mitigation_hint": "Remove backup archives from web root and enforce strict access controls."
}
```

### Quality checks before ingesting into training

1. Every record has a valid ATT&CK ID.
2. Command and output are paired and timestamped.
3. Output highlights are factual excerpts, not fabricated claims.
4. Confidence reflects data quality (not analyst bias).
5. Mitigation hints are actionable and scoped.

---

## 14. Coverage Checklist (Requested Techniques)

This playbook includes:

1. T1595, T1595.001, T1595.002, T1595.003.
2. T1592, T1592.001, T1592.002, T1592.003, T1592.004.
3. T1589, T1589.001, T1589.002, T1589.003.
4. T1590, T1590.001, T1590.002, T1590.003, T1590.004, T1590.005, T1590.006.
5. T1591, T1591.001, T1591.002, T1591.003, T1591.004.
6. T1598, T1598.001, T1598.002, T1598.003, T1598.004.
7. T1597, T1597.001, T1597.002.
8. T1596, T1596.001, T1596.002, T1596.003, T1596.004, T1596.005.
9. T1593, T1593.001, T1593.002, T1593.003.
10. T1681.
11. T1594.

This version is designed specifically for model learning: each technique is represented with scenario context, executable command patterns, and realistic tool output examples.