# Network Enumeration Playbook

> Covers: host discovery, port scanning, service fingerprinting, OS detection, network topology mapping.
> All commands assume an authorized engagement scope. Replace `<target>` with in-scope IP / CIDR.

---

## 1. Host Discovery (Which Hosts Are Alive?)

### 1.1 Ping Sweep — fastest, noisiest
```bash
nmap -sn 10.10.10.0/24                          # ICMP ping sweep
nmap -sn -PE -PP -PM 10.10.10.0/24             # ICMP echo + timestamp + netmask
nmap -sn --send-ip 10.10.10.0/24               # skip ARP, useful when you're not on-segment
fping -a -g 10.10.10.0/24 2>/dev/null          # fast parallel ping
```

### 1.2 ARP Scan (on-segment only, extremely reliable)
```bash
arp-scan -l                                      # scan local subnet
arp-scan --interface eth0 10.10.10.0/24
nmap -sn -PR 10.10.10.0/24                      # ARP via nmap
```

### 1.3 TCP/UDP Discovery (when ICMP is blocked)
```bash
nmap -sn -PS22,80,443,3389 10.10.10.0/24       # TCP SYN to common ports
nmap -sn -PA80,443 10.10.10.0/24               # TCP ACK (passes stateless firewalls)
nmap -sn -PU53,161 10.10.10.0/24               # UDP ping
```

**Interpret:** Any responding host is a target. Note MAC vendors from ARP scan (OUI identifies device type: Cisco, VMware, Raspberry Pi, etc.).

---

## 2. Port Scanning

### 2.1 Quick Top-1000 Scan
```bash
nmap -sV -sC -oA scan_quick <target>            # version + default scripts
nmap -T4 -F <target>                            # fast top-100 ports
```

### 2.2 Full TCP Port Scan
```bash
nmap -p- --min-rate 5000 -T4 <target>           # all 65535 TCP ports, fast
nmap -p- -sV -sC --open -oA scan_full <target>  # full + service + scripts, open only
```

### 2.3 Stealth / IDS Evasion Scanning
```bash
nmap -sS -p- -T2 --randomize-hosts <target>     # SYN scan, slow, randomized order
nmap -sS --data-length 25 -D RND:5 <target>     # decoy IPs + random data length
nmap -sS --source-port 53 <target>              # source port 53 (DNS) to pass ACLs
nmap -f <target>                                 # fragment packets
```

### 2.4 UDP Scan (slow, do targeted)
```bash
nmap -sU -p 53,69,111,123,137,161,500,514,1434 <target>   # common UDP services
nmap -sU --version-intensity 0 -p U:161 <target>           # SNMP check, no intensity
```

### 2.5 Masscan (internet-speed scanning)
```bash
masscan -p1-65535 <target> --rate=10000 -oL masscan.txt    # full TCP, 10k pps
masscan -p80,443,8080,8443 10.10.10.0/24 --rate=5000       # web ports only
# Feed masscan results to nmap for service detection
awk '/open/ {print $4}' masscan.txt | cut -d/ -f1 | sort -u > live_ports.txt
nmap -sV -sC -p $(cat live_ports.txt | tr '\n' ',') <target>
```

---

## 3. Service & Version Fingerprinting

```bash
nmap -sV --version-intensity 9 <target>         # max version detection effort
nmap -A <target>                                 # OS + version + scripts + traceroute
banner_grabber(){
  echo | nc -w2 "$1" "$2" 2>/dev/null | head -5  # raw banner grab
}
banner_grabber <target> 22
banner_grabber <target> 25
banner_grabber <target> 110
```

**Key services to identify and what they imply:**

| Port | Service | Offensive implication |
|------|---------|----------------------|
| 21 | FTP | Anonymous login? Writable shares? Clear-text creds |
| 22 | SSH | Version → CVEs; key auth vs password |
| 23 | Telnet | Clear-text; almost always a finding |
| 25 | SMTP | User enumeration (VRFY/EXPN); open relay |
| 53 | DNS | Zone transfer; subdomain brute force |
| 79 | Finger | User enumeration |
| 80/443 | HTTP/S | Full web enumeration phase |
| 110/995 | POP3 | Credential capture target |
| 111 | RPCBind | Show NFS exports, RPC services |
| 135 | MSRPC | Windows RPC; WMI attack surface |
| 139/445 | SMB | Share enum, relay, Eternal Blue, NTLM capture |
| 161/162 | SNMP | Community string → full device config |
| 389/636 | LDAP | AD enum without authentication |
| 443 | HTTPS | TLS cert → hostnames, org info |
| 445 | SMB | See 139 |
| 512/513/514 | r-services | rlogin, rsh — trust-based auth bypass |
| 873 | rsync | Unauthenticated file access |
| 1433 | MSSQL | SA account; xp_cmdshell; linked servers |
| 1521 | Oracle | TNS listener; SID enum |
| 2049 | NFS | Mount and browse shares |
| 3306 | MySQL | Weak creds; file read via LOAD DATA |
| 3389 | RDP | BlueKeep? Credential attack target |
| 5432 | PostgreSQL | COPY TO/FROM; pg_read_file |
| 5900 | VNC | No/weak auth; screenshot access |
| 6379 | Redis | No auth → config write → RCE |
| 8080/8443 | Alt-HTTP | Management consoles, Jenkins, Tomcat |
| 27017 | MongoDB | No auth → full DB dump |

---

## 4. OS Detection

```bash
nmap -O --osscan-guess <target>                  # OS fingerprinting
nmap -A <target>                                 # includes OS
# TTL-based rough detection:
#   TTL=64   → Linux/macOS
#   TTL=128  → Windows
#   TTL=255  → Network device (Cisco, BSD)
ping -c3 <target> | grep ttl
```

---

## 5. Network Topology Mapping

```bash
traceroute -n <target>                           # hop-by-hop path
nmap --traceroute <target>                       # integrated traceroute
nmap -sn --traceroute 10.10.10.0/24             # traceroute sweep
# Identify routers, firewalls, load balancers between you and target
```

---

## 6. Firewall / WAF / IDS Detection

```bash
nmap -sA <target>                                # ACK scan → filtered vs unfiltered
nmap -sW <target>                                # Window scan
nmap --reason <target>                           # show why port state determined
# RST response → unfiltered (port closed, stateless firewall)
# No response  → filtered (stateful FW dropping)
# ICMP unreachable → filtered
```

---

## 7. Vulnerability Scanning

```bash
nmap --script vuln <target>                      # run all vuln-category scripts
nmap --script=smb-vuln-* <target>               # SMB-specific CVE checks
nmap --script=http-vuln-* <target>              # HTTP CVE checks
nmap --script ssl-heartbleed <target> -p 443    # Heartbleed
nmap --script ssl-poodle <target> -p 443        # POODLE
nmap --script ftp-anon <target> -p 21           # FTP anonymous

# Nessus / OpenVAS / Nuclei for comprehensive vuln scan
nuclei -t network/ -target <target>             # nuclei network templates
nuclei -t cves/ -target <target>                # nuclei CVE templates
```

---

## 8. Interpreting Results → Attack Decision Tree

```
Open port found
├── 21 (FTP)         → try anonymous: ftp <target> [user: anonymous, pass: anything]
├── 22 (SSH)         → check version CVE → hydra/medusa if creds known
├── 80/443           → web enumeration phase
├── 139/445 (SMB)    → SMB enumeration phase
├── 161 (SNMP)       → SNMP enumeration phase
├── 389 (LDAP)       → AD enumeration phase
├── 2049 (NFS)       → showmount -e <target>
├── 6379 (Redis)     → redis-cli -h <target> INFO → try CONFIG SET
└── 27017 (Mongo)    → mongo <target> → show dbs → db.getUsers()
```

---

## 9. Output Formats & Reporting

```bash
nmap -oA <basename> <target>    # .nmap (text), .xml, .gnmap (grep-friendly)
nmap -oX scan.xml <target>      # XML for import into Metasploit / Faraday
# Parse gnmap for open ports:
grep " open " scan_full.gnmap | awk '{print $2, $5}'
# Convert xml to HTML:
xsltproc scan.xml -o scan.html
```
