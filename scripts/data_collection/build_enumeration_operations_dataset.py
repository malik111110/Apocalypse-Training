#!/usr/bin/env python3
"""Build non-MITRE enumeration operation datasets from markdown playbooks.

This builder ingests enumeration markdown files and emits instruction-style JSONL
records focused on:
- information extraction
- practical techniques
- tool calls
- command execution paths
- possible operational branches

The output intentionally avoids MITRE/ATT&CK-specific framing in training fields.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shlex
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_INCLUDE_PATTERNS = ["*enumeration*.md", "ActiveDirectoryEnumeration.md"]

HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$")
SCENARIO_RE = re.compile(r"^\s*Scenario:\s*(.+?)\s*$", re.IGNORECASE)

TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
TACTIC_ID_RE = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)
ATTCK_RE = re.compile(r"ATT&CK|MITRE", re.IGNORECASE)


@dataclass
class ParsedPlaybook:
    path: Path
    title: str
    sections: list[str]
    scenarios: list[str]
    commands: list[str]


def slugify(value: str) -> str:
    text = value.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "playbook"


def clean_label(text: str) -> str:
    value = text.strip()
    value = value.replace("**", "")
    value = ATTCK_RE.sub("", value)
    value = TECHNIQUE_ID_RE.sub("", value)
    value = TACTIC_ID_RE.sub("", value)
    value = re.sub(r"\(\s*\)", "", value)
    value = re.sub(r"\s{2,}", " ", value)
    return value.strip(" -:")


def discover_markdown_files(base_dir: Path, include_patterns: list[str], exclude_patterns: list[str]) -> list[Path]:
    found: dict[str, Path] = {}
    for pattern in include_patterns:
        for path in base_dir.glob(pattern):
            if path.is_file() and path.suffix.lower() == ".md":
                found[str(path)] = path

    results = sorted(found.values(), key=lambda p: p.name.lower())
    if not exclude_patterns:
        return results

    filtered: list[Path] = []
    for path in results:
        rel = path.relative_to(base_dir).as_posix()
        if any(path.match(pat) or rel == pat for pat in exclude_patterns):
            continue
        filtered.append(path)
    return filtered


def collapse_shell_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    buffer = ""
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1].rstrip() + " "
            continue
        merged = (buffer + stripped).strip()
        buffer = ""
        if merged:
            out.append(merged)
    if buffer.strip():
        out.append(buffer.strip())
    return out


def normalize_wrapped_command(command: str) -> str:
    text = command.strip()
    if text.startswith("$"):
        text = text[1:].strip()

    try:
        tokens = shlex.split(text)
    except ValueError:
        return text

    if len(tokens) >= 4 and tokens[0].startswith("run_"):
        core = tokens[3:]
        if len(core) >= 3 and core[0] in {"sh", "bash", "zsh"} and core[1] in {"-c", "-lc"}:
            return core[2].strip()
        return " ".join(core).strip()

    return text


def strip_framework_tokens(text: str) -> str:
    value = ATTCK_RE.sub("", text)
    value = TECHNIQUE_ID_RE.sub("", value)
    value = TACTIC_ID_RE.sub("", value)
    value = re.sub(r"\s{2,}", " ", value)
    return value.strip()


def looks_like_command(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith(("{", "}", "[", "]", '"')):
        return False
    if stripped.startswith(("//", "--", "|")):
        return False
    if stripped.lower().startswith(("match ", "return ", "create ", "select ")) and ";" not in stripped:
        return False
    return True


def extract_commands_from_code_block(code_lines: list[str]) -> list[str]:
    commands: list[str] = []
    for line in collapse_shell_lines(code_lines):
        command = normalize_wrapped_command(line)
        command = strip_framework_tokens(command)
        if command and looks_like_command(command):
            commands.append(command)
    return commands


def parse_markdown(path: Path) -> ParsedPlaybook:
    content = path.read_text(encoding="utf-8")
    sections: list[str] = []
    scenarios: list[str] = []
    commands: list[str] = []

    in_code = False
    code_buffer: list[str] = []

    for line in content.splitlines():
        heading_match = HEADING_RE.match(line)
        if heading_match:
            title = clean_label(heading_match.group(1))
            if title and title not in sections:
                sections.append(title)

        scenario_match = SCENARIO_RE.match(line)
        if scenario_match:
            scenario = clean_label(scenario_match.group(1))
            if scenario:
                scenarios.append(scenario)

        stripped = line.strip()
        if stripped.startswith("```"):
            if in_code:
                commands.extend(extract_commands_from_code_block(code_buffer))
                code_buffer = []
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_buffer.append(line)

    title = clean_label(path.stem.replace("-", " ").replace("_", " ")).title()
    return ParsedPlaybook(
        path=path,
        title=title,
        sections=sections,
        scenarios=scenarios,
        commands=commands,
    )


def command_tool_name(command: str) -> str:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return command.split()[0] if command.split() else "unknown"

    if not tokens:
        return "unknown"

    if tokens[0] == "sudo" and len(tokens) > 1:
        token = tokens[1]
    else:
        token = tokens[0]
    return Path(token).name


def infer_purpose(command: str) -> str:
    checks: list[tuple[str, str]] = [
        (r"nmap|rustscan|masscan|zmap|netdiscover|arp-scan", "discover hosts and services"),
        (r"gobuster|ffuf|feroxbuster|dirsearch|nikto|whatweb", "expand web attack surface"),
        (r"ldapsearch|bloodhound|sharphound|powerview|get-domain|Get-Domain", "enumerate identity and trust relationships"),
        (r"hydra|kerbrute|john|hashcat|GetNPUsers|GetUserSPNs|secretsdump", "validate credential weakness paths"),
        (r"tcpdump|tshark|wireshark|responder|arpspoof|hostapd|dnsmasq", "capture or redirect network traffic"),
        (r"curl|wget|ftp|swaks|mosquitto|dig|nslookup", "test protocol-level communication paths"),
        (r"impacket|psexec|wmiexec|evil-winrm|crackmapexec|ssh", "attempt authenticated remote execution path"),
        (r"tar|7z|zip|Compress-Archive", "package collected artifacts"),
    ]
    for pattern, purpose in checks:
        if re.search(pattern, command, re.IGNORECASE):
            return purpose
    return "collect additional evidence for the next decision"


def infer_expected_signal(command: str) -> str:
    checks: list[tuple[str, str]] = [
        (r"nmap|rustscan|masscan", "ports and service fingerprints"),
        (r"gobuster|ffuf|feroxbuster|dirsearch", "new endpoints or hidden resources"),
        (r"ldapsearch|bloodhound|powerview", "user/group/trust/ACL relationships"),
        (r"hydra|kerbrute|john|hashcat", "credential validation outcomes"),
        (r"tcpdump|tshark|responder|arpspoof|hostapd|dnsmasq", "traffic redirection or capture evidence"),
        (r"secretsdump|GetNPUsers|GetUserSPNs", "credential material with crackability context"),
        (r"curl|wget|dig|nslookup", "service response behavior and metadata"),
    ]
    for pattern, signal in checks:
        if re.search(pattern, command, re.IGNORECASE):
            return signal
    return "output that confirms or rejects a working hypothesis"


def build_tool_calls(commands: list[str], max_tools: int = 10) -> list[dict[str, Any]]:
    counts = Counter(command_tool_name(cmd) for cmd in commands)
    tool_calls: list[dict[str, Any]] = []
    for tool, count in counts.most_common(max_tools):
        representative = next((cmd for cmd in commands if command_tool_name(cmd) == tool), "")
        tool_calls.append(
            {
                "tool": tool,
                "purpose": infer_purpose(representative),
                "observed_usage_count": count,
            }
        )
    return tool_calls


def infer_possibilities(commands: list[str]) -> list[dict[str, Any]]:
    categories: list[tuple[str, str, str, list[str]]] = [
        (
            r"nmap|rustscan|masscan|gobuster|ffuf|dirsearch",
            "surface_expansion",
            "Discovered services or endpoints may expose additional attack paths.",
            ["Run deeper version checks", "Validate exposure against known weak configurations"],
        ),
        (
            r"ldapsearch|bloodhound|powerview|Get-Domain",
            "identity_path",
            "Identity graph may reveal privilege transitions or delegation abuse.",
            ["Trace group nesting and ACL rights", "Prioritize shortest admin path with evidence"],
        ),
        (
            r"hydra|kerbrute|john|hashcat|GetNPUsers|GetUserSPNs|secretsdump",
            "credential_path",
            "Credential exposure may enable authenticated access or escalation.",
            ["Validate credential reuse scope", "Test least-noisy authenticated command path"],
        ),
        (
            r"responder|arpspoof|dnsmasq|hostapd|tcpdump|tshark",
            "traffic_interception",
            "Traffic interception setup may expose authentication or sensitive protocol data.",
            ["Correlate capture timestamps with auth events", "Pivot only on confirmed evidence"],
        ),
        (
            r"tar|7z|zip|Compress-Archive|cp\s|find\s",
            "collection_staging",
            "Collected artifacts may indicate prep for transfer or objective completion.",
            ["Track staging directories", "Verify if transfer channels become active"],
        ),
    ]

    possibilities: list[dict[str, Any]] = []
    for pattern, name, why, next_actions in categories:
        matching = [cmd for cmd in commands if re.search(pattern, cmd, re.IGNORECASE)]
        if matching:
            possibilities.append(
                {
                    "name": name,
                    "why_possible": why,
                    "evidence_clues": matching[:3],
                    "next_actions": next_actions,
                }
            )
    if not possibilities:
        possibilities.append(
            {
                "name": "general_validation",
                "why_possible": "Observed commands indicate an active technical workflow but require targeted validation.",
                "evidence_clues": commands[:3],
                "next_actions": [
                    "Run one high-signal validation command",
                    "Compare results against expected baseline behavior",
                ],
            }
        )
    return possibilities


def build_execution_plan(commands: list[str], rng: random.Random) -> dict[str, Any]:
    if not commands:
        return {"primary_path": [], "alternate_path": [], "validation_path": []}

    sample_size = min(len(commands), rng.randint(8, 16))
    selected = rng.sample(commands, k=sample_size)

    third = max(1, sample_size // 3)
    primary = selected[:third]
    alternate = selected[third : 2 * third]
    validation = selected[2 * third :]

    def to_steps(items: list[str], start_idx: int) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        for offset, command in enumerate(items, start=0):
            steps.append(
                {
                    "step": start_idx + offset,
                    "command": command,
                    "purpose": infer_purpose(command),
                    "expected_signal": infer_expected_signal(command),
                }
            )
        return steps

    return {
        "primary_path": to_steps(primary, 1),
        "alternate_path": to_steps(alternate, 1),
        "validation_path": to_steps(validation, 1),
    }


def build_record(playbook: ParsedPlaybook, sample_index: int, rng: random.Random) -> dict[str, Any]:
    clean_sections = [s for s in (clean_label(x) for x in playbook.sections) if s]
    sections = clean_sections[:]
    rng.shuffle(sections)
    sections = sections[: min(8, len(sections))]

    scenarios = [s for s in (clean_label(x) for x in playbook.scenarios) if s]
    if scenarios:
        rng.shuffle(scenarios)
        scenarios = scenarios[: min(3, len(scenarios))]

    techniques = [
        {
            "name": sec,
            "focus": "practical execution and validation",
        }
        for sec in sections
        if sec.lower() not in {"coverage checklist", "label-ready examples", "safety and lab controls"}
    ][:8]

    commands = playbook.commands[:]
    rng.shuffle(commands)
    observed_commands = commands[: min(18, len(commands))]

    execution_plan = build_execution_plan(observed_commands, rng)
    tool_calls = build_tool_calls(observed_commands)
    possibilities = infer_possibilities(observed_commands)

    input_payload = {
        "source_file": playbook.path.name,
        "playbook_title": playbook.title,
        "sections_in_scope": sections,
        "scenario_context": scenarios,
        "observed_commands": observed_commands,
        "constraints": {
            "authorized_lab_only": True,
            "evidence_required": True,
            "non_destructive_preference": True,
        },
    }

    expected_output = {
        "information": {
            "key_points": [
                "Summarize what is known from observed command outputs before proposing next actions.",
                "Highlight missing evidence that blocks high-confidence conclusions.",
                "Separate confirmed facts from assumptions.",
            ],
            "scenario_notes": scenarios,
        },
        "techniques": techniques,
        "tool_calls": tool_calls,
        "command_execution": execution_plan,
        "possibilities": possibilities,
        "decision_gates": [
            "Proceed only when command output adds new evidence.",
            "Switch path when expected signals are absent.",
            "Stop if activity leaves authorized lab scope.",
        ],
        "operational_boundaries": [
            "Authorized environment only",
            "Prefer low-impact validation before invasive actions",
            "Record command/output timeline for auditability",
        ],
    }

    instruction = (
        "You are given enumeration playbook evidence. Build a practical operation response that focuses on "
        "information extraction, techniques, tool calls, command execution steps, and possible branches. "
        "Do not rely on framework labels."
    )

    text = (
        "### Instruction:\n"
        f"{instruction}\n\n"
        "### Input:\n"
        f"{json.dumps(input_payload, ensure_ascii=True)}\n\n"
        "### Expected Output:\n"
        f"{json.dumps(expected_output, ensure_ascii=True)}"
    )

    file_slug = slugify(playbook.path.stem)
    return {
        "id": f"enumops-{file_slug}-{sample_index:04d}",
        "instruction": instruction,
        "input": input_payload,
        "expected_output": expected_output,
        "meta": {
            "source": "enumeration_markdown_playbooks",
            "file_slug": file_slug,
            "non_mitre_focused": True,
            "record_type": "enumeration_operations",
        },
        "text": text,
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build non-MITRE enumeration operation datasets from markdown files")
    parser.add_argument("--base-dir", type=Path, default=Path("."), help="Repository base directory")
    parser.add_argument(
        "--include-pattern",
        action="append",
        default=[],
        help="Glob pattern for markdown source files (can be repeated)",
    )
    parser.add_argument(
        "--exclude-pattern",
        action="append",
        default=[],
        help="Glob pattern to exclude (can be repeated)",
    )
    parser.add_argument("--samples-per-file", type=int, default=5, help="Number of records to create per source file")
    parser.add_argument("--eval-ratio", type=float, default=0.15, help="Eval split ratio")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument(
        "--output-raw",
        type=Path,
        default=Path("data/raw/enumeration.playbooks.operations.jsonl"),
    )
    parser.add_argument(
        "--output-train",
        type=Path,
        default=Path("data/training/train.enumeration.operations.instructions.jsonl"),
    )
    parser.add_argument(
        "--output-eval",
        type=Path,
        default=Path("data/evaluation/eval.enumeration.operations.instructions.jsonl"),
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("data/raw/enumeration.playbooks.operations.report.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    include_patterns = args.include_pattern or DEFAULT_INCLUDE_PATTERNS
    files = discover_markdown_files(args.base_dir, include_patterns, args.exclude_pattern)

    parsed: list[ParsedPlaybook] = []
    for path in files:
        doc = parse_markdown(path)
        if doc.commands:
            parsed.append(doc)

    if not parsed:
        raise RuntimeError("No markdown playbooks with executable command blocks were found")

    rng = random.Random(args.seed)
    rows: list[dict[str, Any]] = []
    idx = 0
    for playbook in parsed:
        for _ in range(args.samples_per_file):
            rows.append(build_record(playbook, idx, rng))
            idx += 1

    rng.shuffle(rows)

    eval_count = max(1, int(len(rows) * args.eval_ratio))
    eval_rows = rows[:eval_count]
    train_rows = rows[eval_count:]

    write_jsonl(args.output_raw, rows)
    write_jsonl(args.output_train, train_rows)
    write_jsonl(args.output_eval, eval_rows)

    tool_counter = Counter()
    for row in rows:
        for tool in row["expected_output"].get("tool_calls", []):
            tool_counter[tool["tool"]] += 1

    report = {
        "base_dir": str(args.base_dir.resolve()),
        "sources_used": [p.path.name for p in parsed],
        "source_count": len(parsed),
        "samples_per_file": args.samples_per_file,
        "records_total": len(rows),
        "train_records": len(train_rows),
        "eval_records": len(eval_rows),
        "outputs": {
            "raw": str(args.output_raw),
            "train": str(args.output_train),
            "eval": str(args.output_eval),
        },
        "top_tools": tool_counter.most_common(20),
        "non_mitre_focused": True,
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")

    print(f"Sources used: {len(parsed)}")
    print(f"Records total: {len(rows)}")
    print(f"Train records: {len(train_rows)} -> {args.output_train}")
    print(f"Eval records:  {len(eval_rows)} -> {args.output_eval}")
    print(f"Raw records:   {len(rows)} -> {args.output_raw}")
    print(f"Report: {args.report}")


if __name__ == "__main__":
    main()
