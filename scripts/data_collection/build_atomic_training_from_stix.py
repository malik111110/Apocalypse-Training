#!/usr/bin/env python3
"""Build phase-1 atomic training data from ATT&CK STIX attack patterns."""

from __future__ import annotations

import argparse
import json
import random
from collections.abc import Iterable
from pathlib import Path
from typing import Any


MITRE_ATTACK_SOURCE_NAMES = {
    "mitre-attack",
    "mitre-mobile-attack",
    "mitre-ics-attack",
}


def load_bundle(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("STIX payload must be a JSON object")
    if payload.get("type") != "bundle":
        raise ValueError("Input is not a STIX bundle")
    if not isinstance(payload.get("objects"), list):
        raise ValueError("STIX bundle does not contain an objects list")
    return payload


def clean_text(text: str, max_chars: int = 0) -> str:
    compact = " ".join(text.split())
    if max_chars <= 0 or len(compact) <= max_chars:
        return compact
    if max_chars <= 3:
        return compact[:max_chars]
    return compact[: max_chars - 3].rstrip() + "..."


def get_attack_id(external_references: Iterable[dict[str, Any]]) -> str:
    for ref in external_references:
        source_name = str(ref.get("source_name", "")).strip().lower()
        external_id = str(ref.get("external_id", "")).strip()
        if source_name in MITRE_ATTACK_SOURCE_NAMES and external_id:
            return external_id
    return ""


def get_primary_tactic(kill_chain_phases: Iterable[dict[str, Any]]) -> str:
    for phase in kill_chain_phases:
        phase_name = str(phase.get("phase_name", "")).strip().lower()
        if phase_name:
            return phase_name.replace("-", "_")
    return "unknown"


def to_atomic_record(
    attack_pattern: dict[str, Any],
    description_max_chars: int,
) -> dict[str, Any] | None:
    attack_id = get_attack_id(attack_pattern.get("external_references", []))
    if not attack_id:
        return None

    technique_name = str(attack_pattern.get("name", "")).strip() or "Unknown Technique"
    tactic = get_primary_tactic(attack_pattern.get("kill_chain_phases", []))
    description = clean_text(
        str(attack_pattern.get("description", "")),
        max_chars=description_max_chars,
    )
    is_subtechnique = bool(attack_pattern.get("x_mitre_is_subtechnique", False))

    signals = [f"Observed behavior linked to {technique_name} ({attack_id})."]
    if description:
        signals.append(f"Threat intel context: {description}")

    record_id = f"atomic-{attack_id.lower().replace('.', '-').replace('/', '-') }"
    difficulty = "medium" if is_subtechnique else "easy"

    return {
        "id": record_id,
        "input": {
            "signals": signals,
        },
        "output": {
            "tactic": tactic,
            "technique": technique_name,
        },
        "meta": {
            "source": "mitre_attack_stix",
            "difficulty": difficulty,
            "attack_stage": tactic,
            "attack_id": attack_id,
            "stix_attack_pattern_id": attack_pattern.get("id", ""),
            "is_subtechnique": is_subtechnique,
        },
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def attack_id_sort_key(row: dict[str, Any]) -> str:
    return str(row.get("meta", {}).get("attack_id", ""))


def tactic_name(row: dict[str, Any]) -> str:
    tactic = str(row.get("output", {}).get("tactic", "")).strip().lower()
    return tactic or "unknown"


def tactic_distribution(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        tactic = tactic_name(row)
        counts[tactic] = counts.get(tactic, 0) + 1
    return dict(sorted(counts.items()))


def tactic_balanced_sample(
    rows: list[dict[str, Any]],
    per_tactic: int,
    seed: int,
    limit: int,
) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        tactic = tactic_name(row)
        buckets.setdefault(tactic, []).append(row)

    if not buckets:
        return []

    if limit > 0 and limit < len(buckets):
        raise ValueError(
            f"limit={limit} is smaller than number of tactic buckets ({len(buckets)}), "
            "cannot preserve tactic balance"
        )

    for bucket_rows in buckets.values():
        bucket_rows.sort(key=attack_id_sort_key)

    if per_tactic <= 0:
        if limit > 0:
            per_tactic = max(1, limit // len(buckets))
        else:
            per_tactic = min(len(bucket_rows) for bucket_rows in buckets.values())

    rng = random.Random(seed)
    selected_by_tactic: dict[str, list[dict[str, Any]]] = {}
    for tactic, bucket_rows in buckets.items():
        take = min(len(bucket_rows), per_tactic)
        if take == len(bucket_rows):
            selected = list(bucket_rows)
        else:
            sampled_indexes = sorted(rng.sample(range(len(bucket_rows)), k=take))
            selected = [bucket_rows[index] for index in sampled_indexes]
        selected_by_tactic[tactic] = selected

    if limit > 0:
        ordered_tactics = sorted(selected_by_tactic.keys())
        trimmed: list[dict[str, Any]] = []
        while len(trimmed) < limit:
            progressed = False
            for tactic in ordered_tactics:
                tactic_rows = selected_by_tactic[tactic]
                if tactic_rows:
                    trimmed.append(tactic_rows.pop(0))
                    progressed = True
                    if len(trimmed) >= limit:
                        break
            if not progressed:
                break
        final_rows = trimmed
    else:
        final_rows = []
        for tactic in sorted(selected_by_tactic.keys()):
            final_rows.extend(selected_by_tactic[tactic])

    final_rows.sort(key=attack_id_sort_key)
    return final_rows


def probe_mitreattack(stix_input: Path) -> dict[str, Any]:
    """Try loading mitreattack-python to confirm ATT&CK tooling availability."""
    try:
        from mitreattack.stix20 import MitreAttackData
    except Exception as error:  # pragma: no cover - depends on optional environment
        return {
            "mitreattack_python_available": False,
            "error": str(error),
        }

    status: dict[str, Any] = {
        "mitreattack_python_available": True,
        "mitreattack_python_loaded": True,
    }

    try:
        data = MitreAttackData(str(stix_input))
        get_techniques = getattr(data, "get_techniques", None)
        if callable(get_techniques):
            try:
                techniques = get_techniques(remove_revoked_deprecated=True)
            except TypeError:
                techniques = get_techniques()
            if isinstance(techniques, list):
                status["mitreattack_python_techniques"] = len(techniques)
    except Exception as error:  # pragma: no cover - library may differ across versions
        status["mitreattack_python_parse_error"] = str(error)

    return status


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build atomic phase training data from ATT&CK STIX")
    parser.add_argument(
        "--stix-input",
        type=Path,
        default=Path("data/collection/stix/enterprise-attack.json"),
        help="Input STIX bundle JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/atomic/atomic_mitre_attack.jsonl"),
        help="Output atomic training JSONL",
    )
    parser.add_argument("--limit", type=int, default=0, help="Optional maximum number of records")
    parser.add_argument(
        "--include-subtechniques",
        action="store_true",
        help="Include sub-techniques (defaults to false)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Optional output summary report JSON (default: output.report.json)",
    )
    parser.add_argument(
        "--tactic-balanced",
        action="store_true",
        help="Apply tactic-balanced sampling to reduce ATT&CK tactic skew",
    )
    parser.add_argument(
        "--balanced-per-tactic",
        type=int,
        default=0,
        help="Records per tactic when --tactic-balanced is enabled (0 = auto)",
    )
    parser.add_argument(
        "--description-max-chars",
        type=int,
        default=0,
        help="Max chars for ATT&CK description in signals (0 = full text, no truncation)",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic sampling")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    bundle = load_bundle(args.stix_input)
    objects = bundle["objects"]

    records: list[dict[str, Any]] = []
    seen_attack_ids: set[str] = set()
    total_attack_patterns = 0

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        total_attack_patterns += 1

        if bool(obj.get("x_mitre_is_subtechnique", False)) and not args.include_subtechniques:
            continue

        record = to_atomic_record(
            obj,
            description_max_chars=args.description_max_chars,
        )
        if record is None:
            continue

        attack_id = str(record["meta"].get("attack_id", ""))
        if attack_id in seen_attack_ids:
            continue
        seen_attack_ids.add(attack_id)

        records.append(record)

    records.sort(key=attack_id_sort_key)
    pre_balance_distribution = tactic_distribution(records)

    if args.tactic_balanced:
        records = tactic_balanced_sample(
            rows=records,
            per_tactic=args.balanced_per_tactic,
            seed=args.seed,
            limit=args.limit,
        )
    elif args.limit > 0:
        records = records[: args.limit]

    post_balance_distribution = tactic_distribution(records)

    write_jsonl(args.output, records)

    report_path = args.report or args.output.with_suffix(".report.json")
    report = {
        "stix_input": str(args.stix_input),
        "output": str(args.output),
        "total_stix_objects": len(objects),
        "total_attack_patterns_seen": total_attack_patterns,
        "atomic_records": len(records),
        "include_subtechniques": args.include_subtechniques,
        "limit": args.limit,
        "tactic_balanced": args.tactic_balanced,
        "balanced_per_tactic": args.balanced_per_tactic,
        "description_max_chars": args.description_max_chars,
        "seed": args.seed,
        "pre_balance_tactic_distribution": pre_balance_distribution,
        "post_balance_tactic_distribution": post_balance_distribution,
    }
    report.update(probe_mitreattack(args.stix_input))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)
        handle.write("\n")

    print(f"Atomic training records written: {len(records)} -> {args.output}")
    print(f"Report -> {report_path}")


if __name__ == "__main__":
    main()
