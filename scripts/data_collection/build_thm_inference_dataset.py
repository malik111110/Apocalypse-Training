#!/usr/bin/env python3
"""Build inference-focused training JSONL from offensive markdown writeups.

This script is designed to avoid answer memorization by generating records that
emphasize hypothesis branching, evidence collection strategy, and command
selection logic from partial observations.
"""

from __future__ import annotations

import argparse
import json
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HEADING_RE = re.compile(r"^##\s+(.+?)\s*$")
CODE_FENCE_RE = re.compile(r"^```\s*([a-zA-Z0-9_-]*)\s*$")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PERM_STYLE_RE = re.compile(r"^-[-rwxstST]{9}\s+")
WINDOWS_PROMPT_RE = re.compile(r"^[A-Za-z]:\\[^>]*>\s*")

ALLOWED_CODE_LANGS = {
    "",
    "bash",
    "sh",
    "zsh",
    "shell",
    "shell-session",
    "console",
    "text",
    "powershell",
    "ps1",
    "cmd",
}

COMMAND_PREFIX_PATTERNS = [
    re.compile(r"^\$\s+"),
    re.compile(r"^#\s+"),
    re.compile(r"^PS [^>]*>\s*", re.IGNORECASE),
    re.compile(r"^[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[^$#>]*[#$]\s*"),
    re.compile(r"^msf\d*[^>]*>\s*", re.IGNORECASE),
]

COMMAND_STARTERS = {
    "nmap",
    "rustscan",
    "gobuster",
    "ffuf",
    "dirb",
    "nikto",
    "curl",
    "wget",
    "hydra",
    "john",
    "hashcat",
    "smbclient",
    "enum4linux",
    "rpcclient",
    "ftp",
    "ssh",
    "nc",
    "netcat",
    "python",
    "python3",
    "perl",
    "ruby",
    "searchsploit",
    "msfconsole",
    "msfvenom",
    "whoami",
    "id",
    "uname",
    "cat",
    "ls",
    "find",
    "grep",
    "awk",
    "sed",
    "echo",
    "cd",
    "pwd",
    "cp",
    "mv",
    "chmod",
    "chown",
    "tar",
    "zip",
    "unzip",
    "curl.exe",
    "certutil",
    "linpeas",
    "winpeas",
    "sqlmap",
    "wpscan",
    "impacket-GetNPUsers",
    "impacket-GetUserSPNs",
}

NOISE_PREFIXES = (
    "|",
    "_",
    "-",
    "open ",
    "closed ",
    "filtered ",
)

NOISE_SUBSTRINGS = (
    "(status:",
    "http-title",
    "http-enum",
    "starting nmap",
    "nmap scan report",
    "service info",
    "syn-ack",
)

SCRIPT_TOKENS_ALLOWLIST = {
    "./linpeas.sh",
    "linpeas.sh",
    "./linpeas",
    "linpeas",
    "./winpeas.exe",
    "winpeas.exe",
}

KEYWORD_TO_BRANCH = {
    "nmap": "service_exposure",
    "rustscan": "service_exposure",
    "gobuster": "web_surface",
    "ffuf": "web_surface",
    "dirb": "web_surface",
    "nikto": "web_vuln_hypothesis",
    "wpscan": "web_cms_abuse",
    "hydra": "credential_attack",
    "john": "credential_attack",
    "hashcat": "credential_attack",
    "enum4linux": "smb_enum",
    "smbclient": "smb_enum",
    "rpcclient": "smb_enum",
    "ssh": "remote_access",
    "ftp": "file_transfer_abuse",
    "searchsploit": "vulnerability_mapping",
    "msfconsole": "exploit_validation",
    "sqlmap": "injection_path",
}

HIGH_SIGNAL_TOKENS = {
    "nmap",
    "rustscan",
    "gobuster",
    "ffuf",
    "nikto",
    "searchsploit",
    "sqlmap",
    "hydra",
    "john",
    "hashcat",
    "msfconsole",
    "impacket-mssqlclient",
    "impacket-psexec",
    "enum4linux",
    "smbclient",
    "ssh",
    "ftp",
}

TRIVIAL_TOKENS = {
    "ls",
    "cd",
    "pwd",
    "echo",
    "cat",
    "whoami",
    "id",
}

PHASE_FALLBACKS: dict[str, list[str]] = {
    "reconnaissance": [
        "nmap -sC -sV -p- <TARGET_IP>",
        "gobuster dir -u http://<TARGET_IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt",
    ],
    "surface_expansion": [
        "ffuf -u http://<TARGET_IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt",
        "searchsploit <service_or_version>",
    ],
    "access_validation": [
        "sqlmap -u http://<TARGET_IP>/endpoint?id=1 --batch",
        "hydra -L users.txt -P passwords.txt ssh://<TARGET_IP>",
    ],
    "foothold_confirmation": [
        "whoami",
        "uname -a",
    ],
    "privilege_escalation": [
        "sudo -l",
        "find / -perm -4000 -type f 2>/dev/null",
    ],
    "objective_and_collection": [
        "cat /etc/passwd",
        "cat /var/log/auth.log",
    ],
    "cleanup_and_reporting": [
        "history -c",
        "echo \"operation completed with evidence package\"",
    ],
}


@dataclass
class RoomData:
    slug: str
    title: str
    path: Path
    sections: list[str]
    commands: list[str]
    reasoning_chain: dict[str, Any] | None


def sanitize_command(command: str) -> str:
    cmd = command.strip()
    for pattern in COMMAND_PREFIX_PATTERNS:
        cmd = pattern.sub("", cmd)

    # Common Windows prompt format: C:\Users\name>
    cmd = WINDOWS_PROMPT_RE.sub("", cmd)

    cmd = IPV4_RE.sub("<TARGET_IP>", cmd)
    cmd = cmd.replace("MACHINE_IP", "<TARGET_IP>")
    cmd = cmd.replace("TARGET_IP", "<TARGET_IP>")
    cmd = cmd.replace("ATTACKER_IP", "<ATTACKER_IP>")
    cmd = cmd.replace("<<TARGET_IP>>", "<TARGET_IP>")
    cmd = re.sub(r"<+TARGET_IP>+", "<TARGET_IP>", cmd)
    cmd = re.sub(r"<+ATTACKER_IP>+", "<ATTACKER_IP>", cmd)
    return cmd.strip()


def looks_like_command(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False

    candidate = sanitize_command(stripped)
    if not candidate:
        return False

    lowered_candidate = candidate.lower()
    if PERM_STYLE_RE.match(candidate):
        return False
    if all(ch in "-_=:./[](){}<>*+ \\|" for ch in candidate):
        return False
    if lowered_candidate.startswith(NOISE_PREFIXES):
        return False
    if any(noise in lowered_candidate for noise in NOISE_SUBSTRINGS):
        return False

    parts = candidate.split()
    first_raw = parts[0].strip()
    first_token = first_raw.lower().rstrip(":")

    if first_raw.endswith(":"):
        return False

    if first_token == "sudo" and len(parts) > 1:
        second = parts[1].strip().lower().rstrip(":")
        if second in COMMAND_STARTERS:
            return True

    if first_token in SCRIPT_TOKENS_ALLOWLIST:
        return True

    if re.match(r"^\./[a-zA-Z0-9_.-]+$", first_token) and len(parts) > 1:
        return True

    if (first_token.endswith(".sh") or first_token.endswith(".py") or first_token.endswith(".ps1")) and len(parts) > 1:
        return True

    if first_token.endswith(".exe") and len(parts) > 1:
        return True

    if first_token in COMMAND_STARTERS:
        return True

    return False


def parse_markdown(path: Path) -> RoomData:
    content = path.read_text(encoding="utf-8")
    if path.name.lower() == "readme.md":
        slug = path.parent.name
    else:
        slug = path.stem

    title = slug
    sections: list[str] = []
    commands: list[str] = []
    reasoning_chain: dict[str, Any] | None = None

    in_code = False
    current_lang = ""
    current_block: list[str] = []

    lines = content.splitlines()

    for i, line in enumerate(lines):
        if i == 0 and line.startswith("# "):
            title = line[2:].strip()

        heading_match = HEADING_RE.match(line)
        if heading_match:
            sections.append(heading_match.group(1).strip())

        fence_match = CODE_FENCE_RE.match(line.strip())
        if fence_match:
            if not in_code:
                in_code = True
                current_lang = fence_match.group(1).strip().lower()
                current_block = []
            else:
                if current_lang in ALLOWED_CODE_LANGS:
                    for code_line in current_block:
                        if looks_like_command(code_line):
                            commands.append(sanitize_command(code_line))

                if current_lang == "json" and reasoning_chain is None:
                    block_text = "\n".join(current_block).strip()
                    if block_text.startswith("{"):
                        try:
                            parsed = json.loads(block_text)
                            if isinstance(parsed, dict) and "attack_chain" in parsed:
                                reasoning_chain = parsed
                        except json.JSONDecodeError:
                            pass

                in_code = False
                current_lang = ""
                current_block = []
            continue

        if in_code:
            current_block.append(line)

    deduped_commands: list[str] = []
    seen = set()
    for cmd in commands:
        if cmd and cmd not in seen:
            deduped_commands.append(cmd)
            seen.add(cmd)

    return RoomData(
        slug=slug,
        title=title,
        path=path,
        sections=sections,
        commands=deduped_commands,
        reasoning_chain=reasoning_chain,
    )


def build_possibility_branches(commands: list[str], max_branches: int = 5) -> list[dict[str, Any]]:
    branches: list[dict[str, Any]] = []
    added = set()

    for cmd in commands:
        lowered = cmd.lower()
        for keyword, branch in KEYWORD_TO_BRANCH.items():
            if keyword in lowered and branch not in added:
                branches.append(
                    {
                        "branch": branch,
                        "why_possible": f"Observed command pattern includes '{keyword}', suggesting {branch.replace('_', ' ')} path.",
                        "validation_goal": f"Gather stronger evidence to confirm or reject {branch.replace('_', ' ')}.",
                    }
                )
                added.add(branch)

    if not branches:
        branches.append(
            {
                "branch": "general_recon_to_access",
                "why_possible": "Observed commands indicate broad reconnaissance but no explicit exploit path yet.",
                "validation_goal": "Correlate service versions, credential clues, and reachable paths before selecting exploitation steps.",
            }
        )

    # Ensure branch diversity so the model learns branching decisions, not linear replay.
    default_branches = [
        "service_exposure",
        "web_surface",
        "credential_attack",
        "remote_access",
        "vulnerability_mapping",
    ]
    for branch_name in default_branches:
        if len(branches) >= min(max_branches, 3):
            break
        if branch_name in added:
            continue
        branches.append(
            {
                "branch": branch_name,
                "why_possible": f"Operational fallback branch to preserve multi-path analysis for {branch_name.replace('_', ' ')}.",
                "validation_goal": f"Collect decisive evidence to either confirm or reject {branch_name.replace('_', ' ')}.",
            }
        )
        added.add(branch_name)

    return branches[:max_branches]


def build_evidence_plan(commands: list[str]) -> list[dict[str, str]]:
    picks = commands[: min(6, len(commands))]
    if not picks:
        picks = [
            "nmap -sC -sV <TARGET_IP>",
            "gobuster dir -u http://<TARGET_IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt",
        ]

    plan: list[dict[str, str]] = []
    for cmd in picks:
        plan.append(
            {
                "command": cmd,
                "collect": "stdout/stderr, timestamps, and resulting artifacts (files/endpoints/credentials)",
                "reason": "Provides verifiable evidence to update hypotheses instead of guessing.",
            }
        )
    return plan


def build_bug_hunting_paths(commands: list[str], branches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    branch_names = [b["branch"] for b in branches]

    if "web_surface" in branch_names or "web_vuln_hypothesis" in branch_names:
        paths.append(
            {
                "bug_family": "web_misconfiguration_or_injection",
                "signals_to_seek": [
                    "hidden/admin endpoints",
                    "version disclosure",
                    "input reflection or unsanitized parameters",
                ],
                "next_commands": [
                    "ffuf -u http://<TARGET_IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt",
                    "nikto -h http://<TARGET_IP>",
                ],
            }
        )

    if "smb_enum" in branch_names or "service_exposure" in branch_names:
        paths.append(
            {
                "bug_family": "smb_or_service_exposure",
                "signals_to_seek": [
                    "weak share permissions",
                    "legacy protocol/version",
                    "unauthenticated enumeration",
                ],
                "next_commands": [
                    "enum4linux -a <TARGET_IP>",
                    "smbclient -L //<TARGET_IP> -N",
                ],
            }
        )

    if "credential_attack" in branch_names:
        paths.append(
            {
                "bug_family": "credential_weakness",
                "signals_to_seek": [
                    "password policy gaps",
                    "reused/default credentials",
                    "harvested usernames from services/files",
                ],
                "next_commands": [
                    "hydra -L users.txt -P passwords.txt ssh://<TARGET_IP>",
                    "crackmapexec smb <TARGET_IP> -u users.txt -p passwords.txt",
                ],
            }
        )

    if not paths:
        paths.append(
            {
                "bug_family": "multi_vector_validation",
                "signals_to_seek": [
                    "service anomalies",
                    "credential artifacts",
                    "access control misconfigurations",
                ],
                "next_commands": [
                    "nmap -sV -sC <TARGET_IP>",
                    "searchsploit <service_or_version>",
                ],
            }
        )

    return paths[:3]


def build_thinking_steps(room: RoomData, commands: list[str]) -> list[str]:
    steps = [
        "Start with constraints: define authorized scope, target assumptions, and failure-safe boundaries.",
        "Convert raw command outputs into evidence statements before selecting any exploit path.",
        "Generate at least two competing hypotheses and rank them by evidence strength.",
        "Choose the next command only if it can disambiguate hypotheses or gather missing proof.",
        "Re-score confidence after each evidence update and pivot quickly when a path is disproven.",
    ]

    if room.reasoning_chain and room.reasoning_chain.get("uncertainties"):
        steps.append("Explicitly track uncertainty and unresolved questions to avoid overfitting to known lab narratives.")

    if commands:
        steps.append("Preserve full command timeline and artifacts so every claim is reproducible and reviewable.")

    numbered: list[str] = []
    for idx, step in enumerate(steps[:6], start=1):
        numbered.append(f"{idx}. {step}")
    return numbered


def command_token(command: str) -> str:
    if not command.strip():
        return ""
    return command.split()[0].strip().lower().rstrip(":")


def command_score_for_operation(command: str) -> int:
    token = command_token(command)
    score = 1

    if token in HIGH_SIGNAL_TOKENS:
        score += 4
    if token in TRIVIAL_TOKENS:
        score -= 2
    if "--" in command or "&&" in command or "|" in command:
        score += 1
    if len(command.split()) >= 4:
        score += 1

    lowered = command.lower()
    if "<target_ip>" in lowered or "http://" in lowered or "https://" in lowered:
        score += 1

    return score


def pick_operation_commands(commands: list[str], rng: random.Random, min_pick: int = 6, max_pick: int = 12) -> list[str]:
    if not commands:
        return []

    ranked = sorted(commands, key=lambda c: command_score_for_operation(c), reverse=True)
    pick_n = min(max_pick, len(ranked))
    pick_n = max(min_pick if len(ranked) >= min_pick else len(ranked), min(pick_n, len(ranked)))

    top_pool = ranked[: max(pick_n + 3, pick_n)]
    chosen = top_pool[:pick_n]

    # Introduce slight diversity for training variety without sacrificing command quality.
    if len(top_pool) > pick_n:
        replace_idx = rng.randint(0, pick_n - 1)
        chosen[replace_idx] = rng.choice(top_pool[pick_n - 1 :])

    deduped: list[str] = []
    seen: set[str] = set()
    for cmd in chosen:
        if cmd not in seen:
            deduped.append(cmd)
            seen.add(cmd)
    return deduped


def filter_commands(commands: list[str], keywords: list[str], limit: int) -> list[str]:
    out: list[str] = []
    for cmd in commands:
        lowered = cmd.lower()
        if any(k in lowered for k in keywords):
            out.append(cmd)
        if len(out) >= limit:
            break
    return out


def build_operation_steps(
    commands: list[str],
    branches: list[dict[str, Any]],
    bug_paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    branch_names = [b["branch"] for b in branches]

    phase_plan: list[tuple[str, str, list[str], str]] = [
        (
            "reconnaissance",
            "Establish host and service exposure baseline.",
            ["nmap", "rustscan", "gobuster", "ffuf"],
            "Open ports, service versions, and initial web/service surface documented.",
        ),
        (
            "surface_expansion",
            "Expand attack surface from initial findings and map probable weaknesses.",
            ["searchsploit", "nikto", "sqlmap", "smbclient", "enum4linux"],
            "At least two exploit hypotheses linked to observed evidence.",
        ),
        (
            "access_validation",
            "Attempt initial access only on validated high-confidence paths.",
            ["hydra", "sqlmap", "ssh", "ftp", "msfconsole"],
            "One controlled initial-access path validated or disproven with logs.",
        ),
        (
            "foothold_confirmation",
            "Confirm shell/session integrity and context.",
            ["whoami", "id", "uname", "hostname"],
            "Execution context (user, host, privileges) is verified.",
        ),
        (
            "privilege_escalation",
            "Enumerate and test privilege-escalation opportunities.",
            ["sudo", "linpeas", "winpeas", "find", "getcap", "impacket"],
            "Privilege escalation path validated or evidence captured for rejection.",
        ),
        (
            "objective_and_collection",
            "Collect objective artifacts and evidence package.",
            ["cat", "grep", "tar", "zip", "powershell", "type"],
            "Objective artifacts and full command/evidence timeline captured.",
        ),
        (
            "cleanup_and_reporting",
            "Define cleanup boundaries and incident-ready reporting output.",
            ["history", "rm", "echo"],
            "Cleanup actions and report summary prepared with evidence references.",
        ),
    ]

    steps: list[dict[str, Any]] = []
    for idx, (phase, objective, keywords, success_criteria) in enumerate(phase_plan, start=1):
        phase_cmds = filter_commands(commands, keywords, 3)
        if not phase_cmds:
            phase_cmds = PHASE_FALLBACKS[phase][:2]

        if idx == 2 and bug_paths:
            evidence_needed = [
                "Correlate at least one vulnerability family with concrete artifacts",
                bug_paths[0]["bug_family"],
            ]
        elif idx == 3:
            evidence_needed = [
                "Access path selected from top-ranked hypothesis",
                f"Candidate branches: {', '.join(branch_names[:3]) if branch_names else 'general_recon_to_access'}",
            ]
        else:
            evidence_needed = [
                "Command outputs captured with timestamps",
                "Evidence mapped to hypothesis confidence updates",
            ]

        steps.append(
            {
                "step": idx,
                "phase": phase,
                "objective": objective,
                "primary_commands": phase_cmds,
                "fallback_commands": PHASE_FALLBACKS[phase][:2],
                "required_evidence": evidence_needed,
                "decision_gate": f"Proceed only if phase '{phase}' produced verifiable evidence and no scope violation.",
                "success_criteria": success_criteria,
                "failure_action": "Pivot to alternate branch and record rejection reason for current path.",
            }
        )

    return steps


def compute_solidity_assessment(
    commands: list[str],
    branches: list[dict[str, Any]],
    operation_steps: list[dict[str, Any]],
    has_reference_chain: bool,
) -> dict[str, Any]:
    score = 50
    score += min(20, len(commands) * 2)
    score += min(10, len(branches) * 2)
    score += 10 if len(operation_steps) >= 7 else len(operation_steps)
    score += 8 if has_reference_chain else 0

    if len(commands) < 5:
        score -= 10
    if len(branches) < 2:
        score -= 5

    score = max(0, min(100, score))

    strengths: list[str] = []
    risks: list[str] = []

    if len(commands) >= 7:
        strengths.append("Command evidence coverage is broad enough for multi-stage operation training.")
    else:
        risks.append("Limited command diversity may reduce operation realism.")

    if len(branches) >= 3:
        strengths.append("Hypothesis branching supports non-linear decision training.")
    else:
        risks.append("Branching depth is shallow; model may overfit to a single path.")

    if has_reference_chain:
        strengths.append("Embedded reasoning chain improves evidence-to-decision supervision.")
    else:
        risks.append("No reference reasoning chain found; confidence supervision weaker.")

    solid_for_project = score >= 75
    return {
        "score": score,
        "solid_for_project": solid_for_project,
        "strengths": strengths,
        "risks": risks,
        "status": "pass" if solid_for_project else "needs_hardening",
    }


def build_expected_output(room: RoomData, commands: list[str]) -> dict[str, Any]:
    branches = build_possibility_branches(commands)
    evidence_plan = build_evidence_plan(commands)
    bug_paths = build_bug_hunting_paths(commands, branches)
    operation_steps = build_operation_steps(commands, branches, bug_paths)

    reasoning: dict[str, Any] = {
        "mode": "serious_offensive_operation",
        "anti_memorization_rules": [
            "Do not answer with room-specific flags or known walkthrough steps without evidence.",
            "Prefer multiple plausible paths and eliminate them through evidence collection.",
            "Every action must include purpose, expected signal, and failure condition.",
        ],
        "thinking_steps": build_thinking_steps(room, commands),
        "possibility_branches": branches,
        "evidence_collection_plan": evidence_plan,
        "bug_hunting_paths": bug_paths,
        "command_execution_plan": {
            "first_actions": commands[: min(5, len(commands))],
            "fallback_actions": [
                "searchsploit <service_or_version>",
                "nmap -sC -sV -p- <TARGET_IP>",
                "manual validation of each high-risk finding before exploitation",
            ],
        },
        "decision_points": [
            "Escalate only when evidence supports exploitability.",
            "If expected signals are absent, switch to an alternate branch rather than force a known path.",
            "Stop and reassess when commands begin repeating without new evidence.",
        ],
        "confidence_guidance": {
            "high": "Multiple independent artifacts confirm the same hypothesis.",
            "medium": "Some evidence exists but alternate explanations remain viable.",
            "low": "Insufficient or contradictory evidence; gather more telemetry.",
        },
        "operation_requirements": [
            "Use numbered, sequential execution steps with decision gates.",
            "Each step must state objective, evidence needed, and fallback path.",
            "Preserve OPSEC constraints and stop conditions throughout execution.",
        ],
    }

    has_reference_chain = False
    if room.reasoning_chain:
        has_reference_chain = True
        reasoning["reference_chain"] = {
            "scenario": room.reasoning_chain.get("scenario", room.slug),
            "input_signals": room.reasoning_chain.get("input_signals", [])[:4],
            "prior_hypotheses": room.reasoning_chain.get("hypotheses", [])[:4],
            "uncertainties": room.reasoning_chain.get("uncertainties", [])[:4],
        }

    assessment = compute_solidity_assessment(commands, branches, operation_steps, has_reference_chain)

    operation_runbook: dict[str, Any] = {
        "operation_profile": "multi_stage_step_by_step",
        "step_by_step_operation": operation_steps,
        "cross_target_hypotheses": [
            "Technique reuse may apply to adjacent targets with similar software/credential practices.",
            "Recovered artifacts can seed follow-on validation against linked assets in authorized scope.",
        ],
        "opsec_controls": {
            "boundaries": [
                "Operate only within authorized lab scope and approved targets.",
                "Prefer non-destructive validation before invasive actions.",
            ],
            "detection_aware_actions": [
                "Throttle brute-force/fuzzing activity and track request rates.",
                "Capture command timeline and rationale for each high-risk action.",
            ],
            "stop_conditions": [
                "Immediate stop on out-of-scope indicators.",
                "Immediate stop if evidence contradicts operational assumptions.",
            ],
        },
    }

    return {
        "reasoning": reasoning,
        "operation_runbook": operation_runbook,
        "assessment": assessment,
    }


def get_context_labels(source_label: str) -> tuple[str, str]:
    lowered = source_label.lower()
    if "hackthebox" in lowered or lowered.startswith("htb"):
        return "Hack The Box", "machine"
    if "tryhackme" in lowered or lowered.startswith("thm"):
        return "TryHackMe", "room"
    return "lab", "target"


def build_record(
    room: RoomData,
    sample_idx: int,
    rng: random.Random,
    id_prefix: str,
    source_label: str,
) -> dict[str, Any]:
    platform_label, target_label = get_context_labels(source_label)

    chosen_cmds = pick_operation_commands(room.commands, rng)

    section_subset = room.sections[: min(6, len(room.sections))]

    target_obj = {
            "slug": room.slug,
            "title": room.title,
            "source": str(room.path),
            "platform": platform_label,
            "target_type": target_label,
    }

    input_obj = {
        "target": target_obj,
        "room": target_obj,
        "objective": f"Build a serious, step-by-step offensive operation from partial evidence to solve the {target_label} without memorizing walkthrough answers.",
        "sections_in_scope": section_subset,
        "observed_commands": chosen_cmds,
        "operation_mode": "multi_stage_offensive_operation",
        "constraints": {
            "inference_over_memorization": True,
            "require_evidence_for_claims": True,
            "authorized_lab_only": True,
            "must_include_decision_gates": True,
            "must_include_fallback_paths": True,
        },
    }

    expected_output = build_expected_output(room, chosen_cmds)

    instruction = (
        f"You are given partial {platform_label} {target_label} evidence. Build a serious step-by-step offensive operation plan. "
        "Return structured output with: numbered operation phases, decision gates, fallback branches, evidence requirements, "
        "OPSEC boundaries, and a final assessment of operation solidity for training use."
    )

    text = (
        "### Instruction:\n"
        f"{instruction}\n\n"
        "### Input:\n"
        f"{json.dumps(input_obj, ensure_ascii=False)}\n\n"
        "### Expected Output:\n"
        f"{json.dumps(expected_output, ensure_ascii=False)}"
    )

    return {
        "id": f"{id_prefix}-{room.slug}-{sample_idx:03d}",
        "instruction": instruction,
        "input": input_obj,
        "expected_output": expected_output,
        "meta": {
            "source": source_label,
            "room_slug": room.slug,
            "type": "serious_offensive_operation",
            "inference_first": True,
            "anti_memorization": True,
            "operation_steps": len(expected_output["operation_runbook"]["step_by_step_operation"]),
            "solidity_score": expected_output["assessment"]["score"],
        },
        "text": text,
    }


def discover_markdowns(input_root: Path, markdown_glob: str, exclude_globs: list[str] | None = None) -> list[Path]:
    candidates = sorted(input_root.glob(markdown_glob))

    excluded: set[Path] = set()
    for pattern in (exclude_globs or []):
        for path in input_root.glob(pattern):
            if path.is_file():
                excluded.add(path.resolve())

    out: list[Path] = []
    for path in candidates:
        if not path.is_file() or path.suffix.lower() != ".md":
            continue
        if path.resolve() in excluded:
            continue
        if path.name.lower() == "readme.md" and path.parent.name.lower() == "readme":
            continue
        out.append(path)
    return out


def build_dataset(
    input_root: Path,
    markdown_glob: str,
    exclude_globs: list[str],
    samples_per_room: int,
    seed: int,
    id_prefix: str,
    source_label: str,
    require_commands: bool,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rng = random.Random(seed)
    room_paths = discover_markdowns(input_root, markdown_glob, exclude_globs)

    rooms: list[RoomData] = []
    stats = {
        "rooms_total": len(room_paths),
        "rooms_with_commands": 0,
        "rooms_used": 0,
        "records_total": 0,
    }

    for path in room_paths:
        room = parse_markdown(path)
        if room.commands:
            stats["rooms_with_commands"] += 1

        if require_commands and not room.commands:
            continue

        rooms.append(room)

    stats["rooms_used"] = len(rooms)

    records: list[dict[str, Any]] = []
    for room in rooms:
        n = max(1, samples_per_room)
        for i in range(1, n + 1):
            records.append(build_record(room, i, rng, id_prefix, source_label))

    rng.shuffle(records)
    stats["records_total"] = len(records)
    return records, stats


def split_train_eval(records: list[dict[str, Any]], eval_ratio: float, seed: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rng = random.Random(seed)
    rows = list(records)
    rng.shuffle(rows)

    eval_size = int(len(rows) * eval_ratio)
    eval_size = max(1, eval_size) if rows else 0
    eval_rows = rows[:eval_size]
    train_rows = rows[eval_size:]
    return train_rows, eval_rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build inference-first JSONL from markdown writeups")
    parser.add_argument("--input-root", "--thm-root", dest="input_root", type=Path, default=Path("HTB-MACHINES/thm-writeups-main"))
    parser.add_argument("--markdown-glob", type=str, default="*/README.md")
    parser.add_argument("--exclude-glob", action="append", default=[])
    parser.add_argument("--id-prefix", type=str, default="thm-infer")
    parser.add_argument("--source-label", type=str, default="tryhackme_writeups")
    parser.add_argument("--require-commands", action="store_true", default=True)
    parser.add_argument("--allow-empty-commands", action="store_false", dest="require_commands")
    parser.add_argument("--output-raw", type=Path, default=Path("data/raw/thm.rooms.inference.v1.jsonl"))
    parser.add_argument("--output-train", type=Path, default=Path("data/training/train.phase2.thm_inference.v1.jsonl"))
    parser.add_argument("--output-eval", type=Path, default=Path("data/evaluation/eval.phase2.thm_inference.v1.jsonl"))
    parser.add_argument("--report", type=Path, default=Path("data/raw/thm.rooms.inference.v1.report.json"))
    parser.add_argument("--samples-per-room", type=int, default=4)
    parser.add_argument("--eval-ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=2026)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    records, stats = build_dataset(
        args.input_root,
        args.markdown_glob,
        args.exclude_glob,
        args.samples_per_room,
        args.seed,
        args.id_prefix,
        args.source_label,
        args.require_commands,
    )
    train_rows, eval_rows = split_train_eval(records, args.eval_ratio, args.seed + 1)

    write_jsonl(args.output_raw, records)
    write_jsonl(args.output_train, train_rows)
    write_jsonl(args.output_eval, eval_rows)

    report = {
        "input_root": str(args.input_root),
        "thm_root": str(args.input_root),
        "markdown_glob": args.markdown_glob,
        "exclude_globs": args.exclude_glob,
        "id_prefix": args.id_prefix,
        "source_label": args.source_label,
        "require_commands": args.require_commands,
        "output_raw": str(args.output_raw),
        "output_train": str(args.output_train),
        "output_eval": str(args.output_eval),
        "samples_per_room": args.samples_per_room,
        "eval_ratio": args.eval_ratio,
        "seed": args.seed,
        "stats": {
            **stats,
            "train_records": len(train_rows),
            "eval_records": len(eval_rows),
        },
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"Input files parsed:   {stats['rooms_total']}")
    print(f"Files w/ commands:    {stats['rooms_with_commands']}")
    print(f"Files used:           {stats['rooms_used']}")
    print(f"Records generated:    {len(records)}")
    print(f"Train records:        {len(train_rows)} -> {args.output_train}")
    print(f"Eval records:         {len(eval_rows)} -> {args.output_eval}")
    print(f"Raw records:          {len(records)} -> {args.output_raw}")
    print(f"Report:               {args.report}")


if __name__ == "__main__":
    main()
