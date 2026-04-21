# Resource Development Playbook (ATT&CK TA0042, Dataset-Ready)

> ATT&CK tactic: TA0042 Resource Development
> Objective: create realistic, high-quality training traces for how adversaries establish resources for later operations.
> Safety: all procedures below are for authorized simulation, purple-team labs, or defensive validation only.

Metadata:
- ID: TA0042
- Created: 2020-09-30
- Last Modified: 2025-04-25

---

## 0. Safety, Scope, and Evidence Model

### 0.1 Scope and Authorization File

```bash
cat > resource_scope.txt << 'EOF'
Engagement: Authorized Resource Development Emulation
Org: Example Corp
Approval ticket: RT-2026-041
Window: 09:00-17:00 UTC
Allowed: lab-only provisioning, benign payload staging, account simulation
Disallowed: real-world credential theft, production disruption, unauthorized access
Evidence path: ./evidence/ta0042
EOF
```

### 0.2 Command and Output Capture Wrapper

```bash
mkdir -p evidence/ta0042

run_rd() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/ta0042/resource_development.log
  "$@" 2>&1 | tee "evidence/ta0042/${ts}_${technique}_${label}.txt"
}

# Example:
run_rd "T1583.001" "dns_check" dig example-lab-domain.com NS +short
```

### 0.3 Training Record Minimum Fields

1. Technique ID and name.
2. Real-world scenario.
3. Executed command or simulation procedure.
4. Tool output (raw or condensed).
5. Analyst interpretation.
6. Confidence score and mitigation note.

---

## 1. T1650 Acquire Access

### T1650 Acquire Access

Scenario:
- Threat actor seeks pre-compromised entry points from an initial access broker ecosystem.

Command execution (authorized intelligence workflow):

```bash
run_rd "T1650" "parse_iab_feed" jq -r '.offer_id, .access_type, .region, .price_usd, .proof' iab_offers.jsonl | head -40
run_rd "T1650" "validate_claimed_service" nmap -sV -p 22,3389,443 203.0.113.44
run_rd "T1650" "score_access_quality" python3 scripts/resource_dev/score_iab_offers.py --input iab_offers.jsonl
```

Example tool results:

```text
offer_id=IAB-2026-0091 access_type=RDP region=EU price_usd=350
3389/tcp open ms-wbt-server Microsoft Terminal Services
quality_score=0.81 confidence=medium-high
```

Training signals to keep:
- Access type (VPN, RDP, SSH, OWA).
- Claimed proof vs observed exposure match.

---

## 2. T1583 Acquire Infrastructure

### T1583 Acquire Infrastructure (Parent)

Scenario:
- Adversary provisions fresh infrastructure for phishing, C2, staging, and redirect chains.

Command execution baseline:

```bash
run_rd "T1583" "infra_inventory_init" python3 scripts/resource_dev/init_infra_inventory.py --out infra_inventory.json
```

### T1583.001 Domains

Scenario:
- Register lookalike or campaign-specific domains to support payload hosting or phishing.

Command execution:

```bash
run_rd "T1583.001" "register_domain_lab" curl -s -X POST "https://registrar-api.example.local/v1/domains" -d 'name=example-support-lab.com&period=1y'
run_rd "T1583.001" "whois_check" whois example-support-lab.com
run_rd "T1583.001" "ns_validation" dig example-support-lab.com NS +short
```

Example tool results:

```text
status: registered
Registrar: Example Registrar LLC
NS: ns1.lab-dns.net
NS: ns2.lab-dns.net
```

### T1583.002 DNS Server

Scenario:
- Stand up authoritative DNS to control resolution for staged domains.

Command execution:

```bash
run_rd "T1583.002" "deploy_coredns" docker run -d --name rdns -p 1053:53/udp -v "$PWD/labdns:/labdns" coredns/coredns -conf /labdns/Corefile
run_rd "T1583.002" "query_authoritative" dig @127.0.0.1 -p 1053 campaign-lab.example A +short
```

Example tool results:

```text
campaign-lab.example. 60 IN A 198.51.100.77
```

### T1583.003 Virtual Private Server

Scenario:
- Provision disposable VPS nodes for redirectors and payload distribution.

Command execution:

```bash
run_rd "T1583.003" "terraform_init" terraform -chdir=infra/vps init
run_rd "T1583.003" "terraform_apply" terraform -chdir=infra/vps apply -auto-approve
run_rd "T1583.003" "vps_healthcheck" ssh -o StrictHostKeyChecking=no ubuntu@198.51.100.77 'uname -a && hostname'
```

Example tool results:

```text
Apply complete! Resources: 1 added.
instance_ip = 198.51.100.77
hostname: rd-vps-01
```

### T1583.004 Server

Scenario:
- Acquire dedicated server capacity for sustained campaigns or high-throughput staging.

Command execution:

```bash
run_rd "T1583.004" "inventory_baremetal" ansible -i inventory/servers.ini baremetal -m ping
run_rd "T1583.004" "baseline_hardening" ansible-playbook -i inventory/servers.ini playbooks/bootstrap_server.yml
```

Example tool results:

```text
baremetal-01 | SUCCESS => pong
PLAY RECAP: changed=12 failed=0
```

### T1583.005 Botnet

Scenario:
- In emulation environments, represent rented distributed infrastructure with benign worker nodes.

Command execution (lab simulation):

```bash
run_rd "T1583.005" "start_worker_pool" docker compose -f lab/botnet-sim/docker-compose.yml up -d
run_rd "T1583.005" "list_workers" docker compose -f lab/botnet-sim/docker-compose.yml ps
```

Example tool results:

```text
Name                      State   Ports
botnet-sim-worker-01      Up      0.0.0.0:5001->5000/tcp
botnet-sim-worker-12      Up      0.0.0.0:5012->5000/tcp
```

### T1583.006 Web Services

Scenario:
- Register common SaaS/web platforms to blend activity into normal internet traffic.

Command execution:

```bash
run_rd "T1583.006" "service_account_inventory" python3 scripts/resource_dev/create_service_accounts.py --platforms github,gitlab,dropbox,gdrive --mode lab
run_rd "T1583.006" "github_auth_status" gh auth status
```

Example tool results:

```text
created_accounts: 4
github: authenticated as rd-lab-operator
```

### T1583.007 Serverless

Scenario:
- Use serverless functions for low-footprint redirectors, token handlers, or beacon relays.

Command execution:

```bash
run_rd "T1583.007" "deploy_lambda" aws lambda create-function --function-name rd-lab-relay --runtime python3.12 --zip-file fileb://lambda.zip --handler app.handler --role arn:aws:iam::111122223333:role/lambda-exec
run_rd "T1583.007" "invoke_lambda" aws lambda invoke --function-name rd-lab-relay /tmp/lambda_out.json
```

Example tool results:

```text
FunctionArn: arn:aws:lambda:us-east-1:111122223333:function:rd-lab-relay
StatusCode: 200
```

### T1583.008 Malvertising

Scenario:
- In controlled simulation, purchase ad placements that redirect to benign awareness/test landing pages.

Command execution:

```bash
run_rd "T1583.008" "ad_campaign_sim" python3 scripts/resource_dev/simulate_ad_campaign.py --campaign-id RD-AD-001 --landing https://awareness.example.internal
run_rd "T1583.008" "ad_metrics" jq '.impressions, .clicks, .ctr' evidence/ta0042/ad_campaign_metrics.json
```

Example tool results:

```text
impressions: 18420
clicks: 311
ctr: 0.0169
```

---

## 3. T1586 Compromise Accounts

### T1586 Compromise Accounts (Parent)

Scenario:
- Existing trusted accounts are hijacked and reused for targeting and resource actions.

### T1586.001 Social Media Accounts

Scenario:
- Compromised social account used to amplify lure credibility.

Command execution (audit-oriented simulation):

```bash
run_rd "T1586.001" "social_audit_impossible_travel" python3 scripts/resource_dev/detect_impossible_travel.py --input social_audit_log.jsonl
run_rd "T1586.001" "token_reset_events" jq -r 'select(.event=="oauth_token_reset")' social_audit_log.jsonl | head
```

Example tool results:

```text
account=@example_exec risk=high reason=login_paris_then_singapore_14min
oauth_token_reset count=2 in 24h
```

### T1586.002 Email Accounts

Scenario:
- Compromised mailbox leveraged for phishing and infrastructure ownership resets.

Command execution:

```bash
run_rd "T1586.002" "mailbox_forwarding_rules" jq -r 'select(.operation=="Set-Mailbox" and .details|test("ForwardingSmtpAddress"))' m365_audit.jsonl
run_rd "T1586.002" "suspicious_imap_login" jq -r 'select(.protocol=="IMAP" and .mfa==false)' mail_auth_events.jsonl | head
```

Example tool results:

```text
user=finance.ops@example.com forwarding_smtp=externalrelay@proton.example
imap_login user=finance.ops@example.com geo=RU mfa=false
```

### T1586.003 Cloud Accounts

Scenario:
- Cloud identity is compromised and reused for staging infrastructure/services.

Command execution:

```bash
run_rd "T1586.003" "cloudtrail_iam_events" aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey --max-results 20
run_rd "T1586.003" "new_api_tokens" jq -r 'select(.event_name=="CreateAccessKey" or .event_name=="CreateToken")' cloud_identity_events.jsonl
```

Example tool results:

```text
CreateAccessKey user=svc-automation actor=unusual-ip 198.51.100.200
New token created outside approved maintenance window
```

---

## 4. T1584 Compromise Infrastructure

### T1584 Compromise Infrastructure (Parent)

Scenario:
- Third-party infrastructure is hijacked and repurposed as operational assets.

### T1584.001 Domains

Scenario:
- Domain or subdomain control shifts through registrar abuse or DNS provider compromise.

Command execution:

```bash
run_rd "T1584.001" "registrar_diff" python3 scripts/resource_dev/diff_registrar_state.py --old snapshots/domain_state_old.json --new snapshots/domain_state_new.json
run_rd "T1584.001" "ns_change_check" dig compromised-example.com NS +short
```

Example tool results:

```text
ALERT: nameserver change detected old=ns1.legit-dns.net new=ns1.evil-dns.net
```

### T1584.002 DNS Server

Scenario:
- DNS infrastructure compromised to alter resolution paths.

Command execution:

```bash
run_rd "T1584.002" "zone_change_audit" grep -E "zone|serial|update" /var/log/named/audit.log | tail -40
run_rd "T1584.002" "record_integrity" python3 scripts/resource_dev/verify_dns_integrity.py --zone example.com
```

Example tool results:

```text
unauthorized update: A record vpn.example.com -> 198.51.100.250
integrity_check: failed on 3 critical records
```

### T1584.003 Virtual Private Server

Scenario:
- Compromised third-party VPS reused for redirectors, phishing kits, or payload hosting.

Command execution:

```bash
run_rd "T1584.003" "ssh_key_injection_check" jq -r 'select(.event_name=="AuthorizeSecurityGroupIngress" or .event_name=="ImportKeyPair")' cloud_audit.jsonl
run_rd "T1584.003" "webroot_artifacts" ssh ubuntu@198.51.100.90 'find /var/www -type f | head -50'
```

Example tool results:

```text
ImportKeyPair actor=unknown-user key_name=temp-admin
found /var/www/html/update-login/index.php
```

### T1584.004 Server

Scenario:
- Compromised internet-facing server repurposed as C2 or staging host.

Command execution:

```bash
run_rd "T1584.004" "new_service_units" ssh ops@203.0.113.60 'systemctl list-unit-files --type=service | grep -Ei "relay|agent|proxy"'
run_rd "T1584.004" "suspicious_binaries" ssh ops@203.0.113.60 'find /tmp /var/tmp -type f -executable 2>/dev/null'
```

Example tool results:

```text
rd-relay.service enabled
/var/tmp/.cache/updaterd (executable)
```

### T1584.005 Botnet

Scenario:
- Third-party hosts are aggregated to create controllable distributed infrastructure.

Command execution (sinkhole/simulation):

```bash
run_rd "T1584.005" "bot_enrollment_rate" python3 scripts/resource_dev/compute_bot_enrollment.py --input sinkhole_events.jsonl
run_rd "T1584.005" "c2_repointing" jq -r 'select(.event=="c2_repoint")' botnet_control_events.jsonl
```

Example tool results:

```text
new_bots_last_24h=146
c2_repoint old=cnc.old.example new=cnc.new.example nodes=1120
```

### T1584.006 Web Services

Scenario:
- Legitimate web service access is hijacked and abused as hidden infrastructure.

Command execution:

```bash
run_rd "T1584.006" "oauth_app_abuse" jq -r 'select(.event=="oauth_app_authorized" and .publisher_risk=="unknown")' web_service_audit.jsonl
run_rd "T1584.006" "repo_token_abuse" jq -r 'select(.event=="token_created" and .scope|test("repo|gist|workflow"))' github_audit.jsonl
```

Example tool results:

```text
oauth_app_authorized app=DocSyncPro publisher_risk=unknown
token_created actor=build-bot scope=repo,workflow geo=unusual
```

### T1584.007 Serverless

Scenario:
- Existing serverless functions are modified and reused as hidden operational logic.

Command execution:

```bash
run_rd "T1584.007" "lambda_code_change" aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode --max-results 20
run_rd "T1584.007" "function_diff" python3 scripts/resource_dev/diff_lambda_artifacts.py --baseline baseline_hashes.json --current current_hashes.json
```

Example tool results:

```text
UpdateFunctionCode actor=compromised-ci-user function=invoice-processor
hash_diff detected on 2 of 9 functions
```

### T1584.008 Network Devices

Scenario:
- SOHO/edge routers are compromised and reused as relay/proxy infrastructure.

Command execution:

```bash
run_rd "T1584.008" "router_config_diff" python3 scripts/resource_dev/diff_router_config.py --before snapshots/router_before.cfg --after snapshots/router_after.cfg
run_rd "T1584.008" "new_port_forward" grep -Ei "port-forward|nat|upnp" snapshots/router_after.cfg
```

Example tool results:

```text
new rule: tcp/8443 -> 192.168.1.23:443
upnp enabled=true (previously false)
```

---

## 5. T1587 Develop Capabilities

### T1587 Develop Capabilities (Parent)

Scenario:
- Capabilities are built internally to reduce dependence on public tooling and signatures.

### T1587.001 Malware

Scenario:
- Build benign malware-simulation components to emulate payload and C2 behavior for detection training.

Command execution (safe simulation):

```bash
run_rd "T1587.001" "build_beacon_sim" go build -o build/beacon-sim ./cmd/beacon_sim
run_rd "T1587.001" "run_local_test" ./build/beacon-sim --server http://127.0.0.1:8080 --mode dry-run
```

Example tool results:

```text
build: success
dry-run beacon events emitted: 5
```

### T1587.002 Code Signing Certificates

Scenario:
- Generate self-signed code signing material for lab validation of trust chains.

Command execution:

```bash
run_rd "T1587.002" "gen_codesign_key" openssl genrsa -out certs/codesign.key 3072
run_rd "T1587.002" "gen_codesign_cert" openssl req -new -x509 -key certs/codesign.key -out certs/codesign.crt -days 365 -subj '/CN=Lab Code Signing'
```

Example tool results:

```text
generated cert: certs/codesign.crt
subject=CN = Lab Code Signing
```

### T1587.003 Digital Certificates

Scenario:
- Create TLS certificates for staged infrastructure and encrypted channels in lab.

Command execution:

```bash
run_rd "T1587.003" "gen_tls_key" openssl genrsa -out certs/tls.key 2048
run_rd "T1587.003" "gen_tls_cert" openssl req -new -x509 -key certs/tls.key -out certs/tls.crt -days 180 -subj '/CN=staging-lab.example'
run_rd "T1587.003" "inspect_tls_cert" openssl x509 -in certs/tls.crt -noout -text | head -40
```

Example tool results:

```text
Issuer: CN = staging-lab.example
Not After : Oct 17 12:00:00 2026 GMT
```

### T1587.004 Exploits

Scenario:
- Develop exploit logic using vulnerability research workflows (fuzzing and patch diff).

Command execution (defensive lab):

```bash
run_rd "T1587.004" "fuzz_harness" python3 scripts/resource_dev/run_fuzzing.py --target ./build/parser --minutes 20
run_rd "T1587.004" "crash_triage" python3 scripts/resource_dev/triage_crashes.py --input crashes/
```

Example tool results:

```text
crash_count=3 unique=1
root_cause=heap-buffer-overflow in parse_header()
```

---

## 6. T1585 Establish Accounts

### T1585 Establish Accounts (Parent)

Scenario:
- Build and age personas/accounts to support future social engineering and infrastructure actions.

### T1585.001 Social Media Accounts

Scenario:
- Create and cultivate social accounts with believable activity history.

Command execution (simulation metadata pipeline):

```bash
run_rd "T1585.001" "persona_seed" python3 scripts/resource_dev/create_persona_profiles.py --platform social --count 5 --mode lab
run_rd "T1585.001" "persona_activity" python3 scripts/resource_dev/simulate_persona_activity.py --input personas/social_accounts.json --days 30
```

Example tool results:

```text
profiles_created=5
avg_posts_per_profile=12
```

### T1585.002 Email Accounts

Scenario:
- Establish campaign-specific mailbox assets used for phishing and registration workflows.

Command execution:

```bash
run_rd "T1585.002" "mailbox_create_lab" python3 scripts/resource_dev/provision_mailboxes.py --domain campaign-lab.example --count 10
run_rd "T1585.002" "smtp_validate" python3 scripts/resource_dev/verify_smtp_delivery.py --mailboxes evidence/ta0042/mailboxes.csv
```

Example tool results:

```text
mailboxes_created=10
smtp_success_rate=0.90
```

### T1585.003 Cloud Accounts

Scenario:
- Create cloud tenant/account resources for storage, compute, and messaging workflows.

Command execution:

```bash
run_rd "T1585.003" "cloud_account_lab" python3 scripts/resource_dev/create_cloud_accounts.py --provider aws --mode sandbox --count 2
run_rd "T1585.003" "api_key_inventory" jq -r '.account_id, .created_at, .api_keys' evidence/ta0042/cloud_accounts.json
```

Example tool results:

```text
accounts_created=2
api_keys_issued=4
```

---

## 7. T1588 Obtain Capabilities

### T1588 Obtain Capabilities (Parent)

Scenario:
- Adversary acquires capabilities externally instead of building everything in-house.

### T1588.001 Malware

Scenario:
- Obtain malware samples from controlled repositories for capability assessment.

Command execution (authorized malware lab):

```bash
run_rd "T1588.001" "pull_sample_manifest" jq -r '.sample_id, .family, .sha256' internal_malware_catalog.jsonl | head
run_rd "T1588.001" "download_sample" python3 scripts/resource_dev/fetch_sample.py --sample-id MAL-2026-0041 --out samples/
```

Example tool results:

```text
sample_id=MAL-2026-0041 family=stealer sha256=ab12...ff09
download_status=success
```

### T1588.002 Tool

Scenario:
- Acquire offensive or dual-use tools (commercial or open source).

Command execution:

```bash
run_rd "T1588.002" "search_tool_catalog" python3 scripts/resource_dev/search_tool_catalog.py --keyword lateral-movement
run_rd "T1588.002" "install_tool_lab" sudo apt-get install -y nmap
run_rd "T1588.002" "tool_version" nmap --version | head -3
```

Example tool results:

```text
catalog_matches=7
Nmap version 7.94
```

### T1588.003 Code Signing Certificates

Scenario:
- Acquire stolen or purchased code-signing cert data from intelligence sources.

Command execution:

```bash
run_rd "T1588.003" "cert_feed_ingest" python3 scripts/resource_dev/ingest_cert_intel.py --feed stolen_codesign_feed.json
run_rd "T1588.003" "cert_risk_score" python3 scripts/resource_dev/score_cert_abuse.py --input stolen_codesign_feed.json
```

Example tool results:

```text
new_cert_records=14
high_risk_certificates=3
```

### T1588.004 Digital Certificates

Scenario:
- Obtain SSL/TLS certificates for infrastructure trust appearance.

Command execution:

```bash
run_rd "T1588.004" "acme_request" certbot certonly --standalone -d staging-lab.example --non-interactive --agree-tos -m admin@staging-lab.example
run_rd "T1588.004" "cert_list" ls -l /etc/letsencrypt/live/staging-lab.example/
```

Example tool results:

```text
Successfully received certificate.
fullchain.pem and privkey.pem created.
```

### T1588.005 Exploits

Scenario:
- Obtain exploit code from public/commercial sources for adaptation.

Command execution:

```bash
run_rd "T1588.005" "searchsploit_query" searchsploit 'Apache 2.4'
run_rd "T1588.005" "exploit_metadata" python3 scripts/resource_dev/normalize_exploit_metadata.py --input exploits_raw.txt
```

Example tool results:

```text
Apache 2.4.x - Path Traversal | exploits/linux/webapps/50383.py
normalized_entries=22
```

### T1588.006 Vulnerabilities

Scenario:
- Obtain vulnerability intelligence to prioritize exploit or targeting workflows.

Command execution:

```bash
run_rd "T1588.006" "nvd_query" python3 scripts/resource_dev/query_nvd.py --product nginx --since 2025-01-01
run_rd "T1588.006" "cve_prioritize" python3 scripts/resource_dev/prioritize_cves.py --input evidence/ta0042/nginx_cves.json
```

Example tool results:

```text
total_cves=19
critical_or_high=6
priority_ranked=6
```

### T1588.007 Artificial Intelligence

Scenario:
- Acquire access to generative AI services to speed scripting, lure writing, and analysis tasks.

Command execution:

```bash
run_rd "T1588.007" "llm_access_check" python3 scripts/resource_dev/check_llm_access.py --providers openai,anthropic,local-llm
run_rd "T1588.007" "prompt_pipeline_test" python3 scripts/resource_dev/test_ai_workflow.py --task summarize-vuln-report --input sample_report.txt
```

Example tool results:

```text
providers_available=2
workflow_test=pass latency_ms=1240
```

---

## 8. T1608 Stage Capabilities

### T1608 Stage Capabilities (Parent)

Scenario:
- Move obtained/developed capabilities onto controlled infrastructure for operational readiness.

### T1608.001 Upload Malware

Scenario:
- Upload benign malware-simulation payload to staging host for controlled transfer tests.

Command execution:

```bash
run_rd "T1608.001" "upload_payload" aws s3 cp build/beacon-sim s3://rd-staging-bucket/malware/beacon-sim
run_rd "T1608.001" "verify_payload_url" aws s3 ls s3://rd-staging-bucket/malware/
```

Example tool results:

```text
upload: ./build/beacon-sim to s3://rd-staging-bucket/malware/beacon-sim
2026-04-20 13:10:11  2381824 beacon-sim
```

### T1608.002 Upload Tool

Scenario:
- Upload dual-use tooling to controlled distribution endpoint.

Command execution:

```bash
run_rd "T1608.002" "upload_tool" scp tools/admin-helper.bin ubuntu@198.51.100.77:/var/www/stage/tools/
run_rd "T1608.002" "list_tools" ssh ubuntu@198.51.100.77 'ls -lh /var/www/stage/tools/'
```

Example tool results:

```text
admin-helper.bin uploaded
total 6.1M
```

### T1608.003 Install Digital Certificate

Scenario:
- Install TLS certificate on staging server to enable encrypted service delivery.

Command execution:

```bash
run_rd "T1608.003" "install_cert" sudo cp certs/tls.crt /etc/nginx/certs/stage.crt
run_rd "T1608.003" "install_key" sudo cp certs/tls.key /etc/nginx/certs/stage.key
run_rd "T1608.003" "reload_nginx" sudo systemctl reload nginx
run_rd "T1608.003" "verify_tls" openssl s_client -connect staging-lab.example:443 -servername staging-lab.example < /dev/null | grep -E 'subject=|issuer='
```

Example tool results:

```text
subject=CN = staging-lab.example
issuer=CN = staging-lab.example
```

### T1608.004 Drive-by Target

Scenario:
- Prepare benign drive-by simulation page to test browser telemetry and web controls.

Command execution:

```bash
run_rd "T1608.004" "deploy_landing" rsync -av lab/driveby-site/ ubuntu@198.51.100.77:/var/www/driveby/
run_rd "T1608.004" "healthcheck" curl -s -I https://staging-lab.example/driveby/index.html
```

Example tool results:

```text
HTTP/1.1 200 OK
Content-Type: text/html
```

### T1608.005 Link Target

Scenario:
- Stage link destinations used in phishing simulation campaigns.

Command execution:

```bash
run_rd "T1608.005" "generate_tracking_links" python3 scripts/resource_dev/generate_links.py --base https://staging-lab.example/l --targets approved_targets.csv
run_rd "T1608.005" "validate_links" python3 scripts/resource_dev/validate_links.py --input evidence/ta0042/generated_links.csv
```

Example tool results:

```text
links_generated=240
valid_links=240
invalid_links=0
```

### T1608.006 SEO Poisoning

Scenario:
- In controlled exercise, modify ranking signals in test index to measure user click bias.

Command execution (simulation only):

```bash
run_rd "T1608.006" "seo_metadata_stage" python3 scripts/resource_dev/seo_stage.py --site https://staging-lab.example --keywords "vpn update, payroll portal"
run_rd "T1608.006" "ranking_monitor" python3 scripts/resource_dev/monitor_test_index.py --query "example payroll login"
```

Example tool results:

```text
metadata_updated_pages=8
test_index_rank_change: position 12 -> 3
```

---

## 9. End-to-End Resource Development Sequence

Suggested lifecycle for realistic model traces:

1. Access and infrastructure acquisition:
   - T1650, T1583.
2. Account and infrastructure compromise branches:
   - T1586, T1584.
3. Capability generation/acquisition:
   - T1587, T1588.
4. Account establishment for personas and providers:
   - T1585.
5. Capability staging for follow-on operations:
   - T1608.

---

## 10. Dataset Output Contract (Training Ingestion)

One JSON object per execution event.

```json
{
  "tactic": "TA0042",
  "technique": "T1583.003",
  "technique_name": "Virtual Private Server",
  "scenario": "Provision disposable VPS redirector for campaign",
  "command": "terraform -chdir=infra/vps apply -auto-approve",
  "tool_result": {
    "status": "success",
    "highlights": [
      "Resources: 1 added",
      "instance_ip=198.51.100.77"
    ]
  },
  "analyst_interpretation": "New VPS is ready and externally reachable.",
  "confidence": 0.92,
  "risk_note": "Can be used for phishing/C2 if uncontrolled.",
  "mitigation_hint": "Monitor rapid VPS provisioning and unusual geolocation changes."
}
```

Quality gates:

1. Every record has a valid TA0042 technique ID.
2. Command and output are linked by timestamp.
3. Output highlights are evidence-backed excerpts.
4. Confidence reflects evidence quality.
5. Mitigation hint is clear and actionable.

---

## 11. Coverage Checklist (TA0042 Requested Techniques)

Included IDs:

1. T1650
2. T1583, T1583.001, T1583.002, T1583.003, T1583.004, T1583.005, T1583.006, T1583.007, T1583.008
3. T1586, T1586.001, T1586.002, T1586.003
4. T1584, T1584.001, T1584.002, T1584.003, T1584.004, T1584.005, T1584.006, T1584.007, T1584.008
5. T1587, T1587.001, T1587.002, T1587.003, T1587.004
6. T1585, T1585.001, T1585.002, T1585.003
7. T1588, T1588.001, T1588.002, T1588.003, T1588.004, T1588.005, T1588.006, T1588.007
8. T1608, T1608.001, T1608.002, T1608.003, T1608.004, T1608.005, T1608.006

This playbook is ready to use for model training data generation, red-team emulation planning, and defensive analytics mapping across Resource Development.