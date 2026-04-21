#!/usr/bin/env python3
"""Build offensive reconnaissance training data from enumeration markdown playbooks.

This generator transforms command-centric markdown playbooks into model-ready JSONL data
that trains both offensive reasoning (enumeration + vuln hypothesis) and defensive follow-up
(mitigation + monitoring strategy).

Output schema is compatible with the project's reasoning-style datasets.
"""

from __future__ import annotations

import argparse
import json
import random
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Profile:
    slug: str
    path: str
    environment: str
    objective: str
    tactic_focus: list[str]
    findings: list[str]
    vulnerabilities: list[dict[str, str]]
    tool_calls: list[dict[str, str]]
    mitigations_immediate: list[str]
    mitigations_hardening: list[str]
    mitigations_monitoring: list[str]


PROFILES: list[Profile] = [
    Profile(
        slug="active_directory",
        path="ActiveDirectoryEnumeration.md",
        environment="Windows enterprise Active Directory domain",
        objective="Map identity attack paths and privilege escalation chains in AD",
        tactic_focus=["discovery", "credential_access", "privilege_escalation", "lateral_movement"],
        findings=[
            "LDAP anonymous bind exposed domain naming contexts and user objects",
            "Kerberos pre-auth errors revealed valid usernames",
            "Service Principal Name accounts identified and potentially Kerberoastable",
            "Domain trust relationship indicates potential cross-domain movement path",
        ],
        vulnerabilities=[
            {"name": "AS-REP roastable accounts", "likelihood": "high", "validation": "impacket-GetNPUsers"},
            {"name": "Weak service account passwords (Kerberoast)", "likelihood": "high", "validation": "impacket-GetUserSPNs + hashcat"},
            {"name": "Over-privileged ACL path to Domain Admins", "likelihood": "medium", "validation": "BloodHound shortest path"},
        ],
        tool_calls=[
            {"name": "ad_identity_graph_builder", "purpose": "Build privilege path graph from users/groups/trusts", "priority": "high"},
            {"name": "kerberos_exposure_analyzer", "purpose": "Classify AS-REP/Kerberoast exposure and crackability", "priority": "high"},
            {"name": "domain_acl_risk_mapper", "purpose": "Score risky ACLs and delegation misconfigurations", "priority": "medium"},
        ],
        mitigations_immediate=[
            "Disable or rotate credentials for exposed service accounts",
            "Enforce Kerberos pre-auth for all user accounts",
            "Restrict anonymous LDAP bind on domain controllers",
        ],
        mitigations_hardening=[
            "Adopt tiered administration with privileged access workstations",
            "Reduce domain admin membership and remove stale delegated rights",
            "Implement gMSA for service identities and periodic secret rotation",
        ],
        mitigations_monitoring=[
            "Alert on abnormal TGS requests and Kerberoast patterns",
            "Monitor AD ACL changes and group membership changes",
            "Track privileged logons outside approved admin hosts",
        ],
    ),
    Profile(
        slug="dns",
        path="dns-enumeration.md",
        environment="Enterprise external DNS and hybrid internal naming",
        objective="Discover exposed naming infrastructure and hidden host inventory",
        tactic_focus=["reconnaissance", "discovery"],
        findings=[
            "Authoritative nameservers enumerated and SOA metadata exposed admin contact structure",
            "Subdomain brute force and CT logs expanded host attack surface",
            "TXT records leaked third-party providers and mail security posture",
            "Reverse DNS sweep identified likely internal service naming conventions",
        ],
        vulnerabilities=[
            {"name": "DNS zone transfer exposure", "likelihood": "high", "validation": "dig AXFR"},
            {"name": "Excessive DNS metadata disclosure", "likelihood": "medium", "validation": "dig TXT/SRV/SOA analysis"},
            {"name": "Weak DNS segmentation between external and internal records", "likelihood": "medium", "validation": "compare authoritative responses"},
        ],
        tool_calls=[
            {"name": "dns_surface_mapper", "purpose": "Enumerate record types and authority chain", "priority": "high"},
            {"name": "subdomain_intelligence_correlator", "purpose": "Merge brute-force, CT log, and passive DNS findings", "priority": "high"},
            {"name": "dns_misconfig_validator", "purpose": "Validate zone transfer and recursion misconfigurations", "priority": "medium"},
        ],
        mitigations_immediate=[
            "Disable unauthorized zone transfer on all authoritative nameservers",
            "Restrict recursion and public query scope to required zones only",
            "Remove or sanitize sensitive TXT metadata records",
        ],
        mitigations_hardening=[
            "Separate internal and external DNS views (split-horizon)",
            "Enforce DNSSEC where feasible",
            "Apply strict ACLs for zone transfer and admin operations",
        ],
        mitigations_monitoring=[
            "Alert on repeated AXFR attempts and bulk subdomain queries",
            "Monitor spikes in high-entropy DNS lookups",
            "Track newly observed subdomains and certificate transparency drift",
        ],
    ),
    Profile(
        slug="linux",
        path="linux-enumeration.md",
        environment="Linux server estate (mixed app + infra hosts)",
        objective="Identify local privilege escalation and credential exposure opportunities",
        tactic_focus=["discovery", "privilege_escalation", "credential_access", "persistence"],
        findings=[
            "SUID binaries and writable paths suggest potential escalation vectors",
            "Service inventory reveals root-owned daemons executing mutable scripts",
            "Secret hunt patterns indicate credential artifacts in app configuration",
            "Scheduled tasks may run from user-writable paths",
        ],
        vulnerabilities=[
            {"name": "Dangerous sudo NOPASSWD entries", "likelihood": "high", "validation": "sudo -l review"},
            {"name": "Writable root-executed cron scripts", "likelihood": "high", "validation": "cron ownership check"},
            {"name": "Credential leakage in config files", "likelihood": "medium", "validation": "targeted grep + manual validation"},
        ],
        tool_calls=[
            {"name": "linux_privilege_map", "purpose": "Map sudo/SUID/writable-root escalation graph", "priority": "high"},
            {"name": "service_trust_audit", "purpose": "Correlate service owners with script and binary permissions", "priority": "high"},
            {"name": "secret_leak_scanner", "purpose": "Extract and classify exposed secrets with confidence", "priority": "medium"},
        ],
        mitigations_immediate=[
            "Remove unsafe sudo rules and revoke unnecessary shell access",
            "Fix ownership and permissions on cron and service execution paths",
            "Rotate exposed credentials discovered in filesystem artifacts",
        ],
        mitigations_hardening=[
            "Apply least privilege to service accounts and file ACLs",
            "Minimize SUID/SGID binaries to approved baseline only",
            "Centralize secrets in a vault with short-lived credentials",
        ],
        mitigations_monitoring=[
            "Alert on enumeration command clusters and privilege probe patterns",
            "Monitor writes to root-executed script paths",
            "Track anomalous process launches from temp directories",
        ],
    ),
    Profile(
        slug="macos",
        path="macos-enumeration.md",
        environment="macOS endpoints in enterprise-managed fleet",
        objective="Assess local persistence, hardening posture, and credential artifact risk",
        tactic_focus=["discovery", "persistence", "credential_access", "privilege_escalation"],
        findings=[
            "LaunchAgents/LaunchDaemons include entries requiring trust verification",
            "SIP/Gatekeeper/FileVault posture indicates hardening gaps on some endpoints",
            "Remote access services may be enabled outside policy",
            "Developer tooling artifacts contain potential token and key material",
        ],
        vulnerabilities=[
            {"name": "Unauthorized launchd persistence entries", "likelihood": "medium", "validation": "launchctl + filesystem diff"},
            {"name": "Disabled host hardening controls", "likelihood": "medium", "validation": "csrutil/spctl/fdesetup checks"},
            {"name": "Credential artifacts in user profiles", "likelihood": "high", "validation": "targeted secret scan"},
        ],
        tool_calls=[
            {"name": "macos_persistence_audit", "purpose": "Enumerate and score suspicious launchd entries", "priority": "high"},
            {"name": "macos_control_posture", "purpose": "Assess SIP/Gatekeeper/FileVault/firewall baseline", "priority": "high"},
            {"name": "credential_artifact_scan", "purpose": "Classify exposed tokens/keys and potential abuse path", "priority": "medium"},
        ],
        mitigations_immediate=[
            "Disable unapproved remote access services and suspicious launchd entries",
            "Rotate exposed API keys and local credential artifacts",
            "Remove unauthorized users from local admin groups",
        ],
        mitigations_hardening=[
            "Enforce MDM baseline for SIP, Gatekeeper, FileVault, and firewall",
            "Restrict local admin rights and automate drift remediation",
            "Require signed binaries for persistence-related paths",
        ],
        mitigations_monitoring=[
            "Alert on writes to LaunchAgents/LaunchDaemons",
            "Monitor anomalous osascript and shell execution chains",
            "Track repeated admin-group membership changes",
        ],
    ),
    Profile(
        slug="network",
        path="netwrok-enumeration.md",
        environment="Mixed enterprise network perimeter and internal segments",
        objective="Map live hosts, exposed services, and vuln-prone network surfaces",
        tactic_focus=["reconnaissance", "discovery", "initial_access"],
        findings=[
            "Host discovery identified active endpoints across target subnet",
            "Service fingerprinting revealed high-value exposed management protocols",
            "UDP and TCP scanning uncovered additional attack surface not in CMDB",
            "Firewall behavior suggests selective filtering and potential blind spots",
        ],
        vulnerabilities=[
            {"name": "Exposed legacy/insecure network services", "likelihood": "medium", "validation": "nmap service fingerprinting"},
            {"name": "Weak network segmentation boundaries", "likelihood": "medium", "validation": "traceroute and service reachability"},
            {"name": "Unpatched externally reachable service versions", "likelihood": "high", "validation": "version + CVE correlation"},
        ],
        tool_calls=[
            {"name": "host_surface_mapper", "purpose": "Build alive host inventory and open-port matrix", "priority": "high"},
            {"name": "service_cve_correlator", "purpose": "Map detected versions to known exploitability", "priority": "high"},
            {"name": "network_path_analyzer", "purpose": "Infer segmentation and trust boundaries", "priority": "medium"},
        ],
        mitigations_immediate=[
            "Restrict externally exposed management services and close unnecessary ports",
            "Patch high-risk service versions with known exploitation paths",
            "Apply temporary ACL blocks for internet-origin reconnaissance traffic",
        ],
        mitigations_hardening=[
            "Implement service allowlisting and network micro-segmentation",
            "Adopt continuous external attack-surface monitoring",
            "Enforce secure protocol standards and deprecate legacy services",
        ],
        mitigations_monitoring=[
            "Alert on high-rate scan signatures and sequential host probing",
            "Monitor unexpected new listeners on critical assets",
            "Detect abnormal east-west recon traffic from endpoints",
        ],
    ),
    Profile(
        slug="smb_windows",
        path="smb-windows-enumeration.md",
        environment="Windows SMB estate with domain-joined hosts",
        objective="Identify share abuse paths, credential exposure, and relay opportunities",
        tactic_focus=["discovery", "credential_access", "lateral_movement", "privilege_escalation"],
        findings=[
            "SMB signing posture indicates relay feasibility on selected hosts",
            "Null session and share enumeration exposed sensitive paths",
            "RPC and share metadata reveal user/group and domain structure",
            "Historical GPP artifacts may leak decryptable credentials",
        ],
        vulnerabilities=[
            {"name": "SMB signing not required", "likelihood": "high", "validation": "smb2-security-mode script"},
            {"name": "Sensitive share overexposure", "likelihood": "high", "validation": "smbclient/smbmap recursive review"},
            {"name": "Legacy SMB vulnerability exposure", "likelihood": "medium", "validation": "smb-vuln scripts and patch check"},
        ],
        tool_calls=[
            {"name": "smb_surface_mapper", "purpose": "Enumerate shares, signing mode, and auth posture", "priority": "high"},
            {"name": "ntlm_relay_feasibility_check", "purpose": "Assess relay preconditions across SMB targets", "priority": "high"},
            {"name": "share_secret_hunter", "purpose": "Locate credential-bearing files and risky artifacts", "priority": "medium"},
        ],
        mitigations_immediate=[
            "Enforce SMB signing and disable SMBv1 where still enabled",
            "Restrict anonymous/null session access and lock down share ACLs",
            "Rotate credentials found in scripts, configs, or GPP artifacts",
        ],
        mitigations_hardening=[
            "Adopt least-privilege share model with regular access recertification",
            "Remove legacy protocols and enforce NTLM hardening policy",
            "Separate admin shares from user-accessible segments",
        ],
        mitigations_monitoring=[
            "Alert on bulk share enumeration and unusual ADMIN$ access",
            "Monitor NTLM authentication anomalies and relay indicators",
            "Track creation/execution patterns of PsExec-like service artifacts",
        ],
    ),
    Profile(
        slug="snmp",
        path="snmp-enumeration.md",
        environment="Network infrastructure with SNMP-enabled devices",
        objective="Extract topology intelligence and identify weak SNMP security posture",
        tactic_focus=["reconnaissance", "discovery", "credential_access"],
        findings=[
            "UDP/161 service exposure discovered across in-scope devices",
            "Community string testing indicates potential weak/default credentials",
            "OID traversal reveals interfaces, routing, and process/service metadata",
            "SNMPv3 support and policy consistency vary across devices",
        ],
        vulnerabilities=[
            {"name": "Default/weak SNMP community strings", "likelihood": "high", "validation": "snmpwalk/onesixtyone"},
            {"name": "Legacy SNMPv1/v2c exposure", "likelihood": "medium", "validation": "version fingerprinting"},
            {"name": "Excessive SNMP data disclosure", "likelihood": "medium", "validation": "high-value OID extraction"},
        ],
        tool_calls=[
            {"name": "snmp_surface_mapper", "purpose": "Discover SNMP endpoints and supported versions", "priority": "high"},
            {"name": "oid_high_value_extractor", "purpose": "Extract and normalize sensitive topology OIDs", "priority": "high"},
            {"name": "snmp_credential_audit", "purpose": "Classify weak/default community and v3 identity reuse", "priority": "medium"},
        ],
        mitigations_immediate=[
            "Disable SNMPv1/v2c where feasible and rotate community strings",
            "Restrict SNMP ACLs to dedicated monitoring sources",
            "Disable write access unless explicitly required",
        ],
        mitigations_hardening=[
            "Standardize on SNMPv3 authPriv with unique per-device credentials",
            "Segment management plane from user/data plane traffic",
            "Minimize exposed OID scope to operational necessity",
        ],
        mitigations_monitoring=[
            "Alert on bulk OID walks from non-monitoring hosts",
            "Track repeated community-string failures and spray attempts",
            "Monitor unauthorized SNMP SET operations",
        ],
    ),
    Profile(
        slug="web",
        path="web-enumeration.md",
        environment="Internet-facing web applications and APIs",
        objective="Identify web attack surface, vuln candidates, and auth weaknesses",
        tactic_focus=["reconnaissance", "initial_access", "discovery"],
        findings=[
            "Technology fingerprinting identified framework and server version hints",
            "Directory and vhost fuzzing expanded reachable endpoint inventory",
            "TLS inspection exposed configuration posture and additional hostnames",
            "Parameter and API fuzzing identified candidate input vectors",
        ],
        vulnerabilities=[
            {"name": "Exposed sensitive endpoints and backup artifacts", "likelihood": "high", "validation": "ffuf/gobuster/feroxbuster"},
            {"name": "Outdated framework or server versions", "likelihood": "medium", "validation": "header and CVE correlation"},
            {"name": "Weak auth/session controls", "likelihood": "medium", "validation": "auth flow and token analysis"},
        ],
        tool_calls=[
            {"name": "web_surface_mapper", "purpose": "Correlate tech stack, endpoint discovery, and TLS metadata", "priority": "high"},
            {"name": "api_parameter_fuzzer", "purpose": "Enumerate hidden parameters and input handling paths", "priority": "high"},
            {"name": "web_vuln_triage", "purpose": "Prioritize findings by exploitability and impact", "priority": "medium"},
        ],
        mitigations_immediate=[
            "Remove exposed debug/backup artifacts and block sensitive paths",
            "Patch known vulnerable web components and dependencies",
            "Enforce strict WAF and rate-limiting on fuzz-prone endpoints",
        ],
        mitigations_hardening=[
            "Adopt secure SDLC with dependency and config scanning in CI",
            "Enforce strong authentication and session hardening standards",
            "Segment public-facing services from internal trust zones",
        ],
        mitigations_monitoring=[
            "Alert on high-entropy path fuzzing and auth endpoint abuse",
            "Track anomalous request patterns and error-rate spikes",
            "Continuously monitor cert/SAN drift and newly exposed subdomains",
        ],
    ),
]


HEADING_RE = re.compile(r"^##\s+(.+?)\s*$")


def read_markdown(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def extract_sections_and_commands(content: str) -> tuple[list[str], list[str]]:
    sections: list[str] = []
    commands: list[str] = []
    in_code = False
    code_lang = ""

    for line in content.splitlines():
        m = HEADING_RE.match(line)
        if m:
            sections.append(m.group(1).strip())

        stripped = line.strip()
        if stripped.startswith("```"):
            if not in_code:
                in_code = True
                code_lang = stripped[3:].strip().lower()
            else:
                in_code = False
                code_lang = ""
            continue

        if in_code and (code_lang in {"bash", "powershell", "ps1", ""}):
            if not stripped or stripped.startswith("#"):
                continue
            commands.append(stripped)

    return sections, commands


def pick_commands(commands: list[str], rng: random.Random, n: int) -> list[str]:
    if not commands:
        return []
    return rng.sample(commands, min(n, len(commands)))


def build_reasoning(profile: Profile, command_subset: list[str], rng: random.Random) -> dict:
    findings = rng.sample(profile.findings, k=min(3, len(profile.findings)))
    vulns = rng.sample(profile.vulnerabilities, k=min(2, len(profile.vulnerabilities)))

    vuln_block = []
    for item in vulns:
        vuln_block.append(
            {
                "name": item["name"],
                "likelihood": item["likelihood"],
                "evidence": rng.sample(command_subset, k=min(2, len(command_subset))) if command_subset else [],
                "validation": item["validation"],
            }
        )

    hypotheses = [
        f"Primary hypothesis: {findings[0]} which suggests a viable attack path within {profile.environment.lower()}.",
        f"Alternative hypothesis: observed evidence may represent defensive testing noise rather than active weakness; validate with targeted tool calls.",
        f"Operational hypothesis: chaining discovered weaknesses could enable privilege escalation or data access if left unmitigated.",
    ]

    uncertainties = [
        "Enumeration evidence is point-in-time and may miss transient services or policy changes",
        "Exploitability is inferred and must be validated in a controlled, authorized test step",
        "Some findings may be false positives caused by legacy artifacts or stale configuration",
    ]

    confidence = round(rng.uniform(0.68, 0.9), 2)

    plan = [
        {
            "phase": "enumeration",
            "objective": profile.objective,
            "commands": command_subset[: max(1, len(command_subset) // 2)],
            "expected_artifacts": findings,
        },
        {
            "phase": "validation",
            "objective": "Confirm exploitability and remove false positives",
            "commands": command_subset[max(1, len(command_subset) // 2) :],
            "expected_artifacts": [v["name"] for v in vuln_block],
        },
    ]

    return {
        "tactic_focus": profile.tactic_focus,
        "recon_plan": plan,
        "findings": findings,
        "vulnerability_candidates": vuln_block,
        "hypotheses": hypotheses,
        "uncertainties": uncertainties,
        "confidence": confidence,
        "explanation": (
            "The selected enumeration sequence supports offensive discovery and vulnerability triage, "
            "then transitions to validation and mitigation planning to reduce operational risk."
        ),
    }


def build_sample(profile: Profile, sections: list[str], commands: list[str], idx: int, rng: random.Random) -> dict:
    n_cmd = rng.randint(6, 12)
    cmd_subset = pick_commands(commands, rng, n_cmd)
    n_sections = min(4, len(sections))
    section_subset = rng.sample(sections, k=n_sections) if n_sections else []

    reasoning = build_reasoning(profile, cmd_subset, rng)

    return {
        "id": f"offrecon-{profile.slug}-{idx:04d}",
        "instruction": (
            "Analyze this authorized offensive-enumeration context. Build an attack-oriented recon strategy, "
            "prioritize likely vulnerabilities, define tool-call validation steps, and produce mitigation actions "
            "to remediate discovered weaknesses."
        ),
        "input": {
            "environment": profile.environment,
            "objective": profile.objective,
            "sections_in_scope": section_subset,
            "command_observations": cmd_subset,
        },
        "expected_output": {
            "reasoning": reasoning,
            "tool_calls": profile.tool_calls,
            "mitigation": {
                "immediate_actions": profile.mitigations_immediate,
                "hardening": profile.mitigations_hardening,
                "monitoring": profile.mitigations_monitoring,
            },
        },
        "meta": {
            "source": "enumeration_playbooks",
            "profile": profile.slug,
            "type": "offensive_recon_with_mitigation",
            "authorized_scope_required": True,
            "contains_tool_strategy": True,
        },
    }


def build_dataset(base_dir: Path, n_samples: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    parsed: list[tuple[Profile, list[str], list[str]]] = []

    for profile in PROFILES:
        path = base_dir / profile.path
        if not path.exists():
            continue
        content = read_markdown(path)
        sections, commands = extract_sections_and_commands(content)
        if commands:
            parsed.append((profile, sections, commands))

    if not parsed:
        raise RuntimeError("No playable markdown sources found with command blocks")

    out: list[dict] = []
    idx = 0
    while len(out) < n_samples:
        profile, sections, commands = rng.choice(parsed)
        out.append(build_sample(profile, sections, commands, idx, rng))
        idx += 1
    return out


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build offensive recon dataset from markdown playbooks")
    parser.add_argument("--base-dir", type=Path, default=Path("."), help="Repository root containing markdown playbooks")
    parser.add_argument("--train", type=Path, default=Path("data/training/train.phase2.offensive_recon.v1.jsonl"))
    parser.add_argument("--eval", type=Path, default=Path("data/evaluation/eval.phase2.offensive_recon.v1.jsonl"))
    parser.add_argument("--n-train", type=int, default=260)
    parser.add_argument("--n-eval", type=int, default=40)
    parser.add_argument("--seed", type=int, default=1337)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    train = build_dataset(args.base_dir, args.n_train, args.seed)
    eval_rows = build_dataset(args.base_dir, args.n_eval, args.seed + 1)

    write_jsonl(args.train, train)
    write_jsonl(args.eval, eval_rows)

    print(f"Wrote train: {len(train)} -> {args.train}")
    print(f"Wrote eval:  {len(eval_rows)} -> {args.eval}")


if __name__ == "__main__":
    main()
