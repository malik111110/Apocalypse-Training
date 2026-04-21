#!/usr/bin/env python3
"""Build a reproducible evaluation subset from normalized JSONL cases."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSON on line {line_number}: {error.msg}") from error
            if not isinstance(obj, dict):
                raise ValueError(f"Line {line_number} must contain a JSON object")
            rows.append(obj)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build held-out evaluation dataset from normalized JSONL")
    parser.add_argument("--input", required=True, type=Path, help="Input normalized JSONL file")
    parser.add_argument("--output", required=True, type=Path, help="Output evaluation JSONL file")
    parser.add_argument("--size", type=int, default=200, help="Maximum number of records to sample")
    parser.add_argument(
        "--difficulty",
        nargs="*",
        default=[],
        help="Optional list of difficulties to include (easy medium hard)",
    )
    parser.add_argument(
        "--attack-stage",
        nargs="*",
        default=[],
        help="Optional list of attack_stage values to include",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducible sampling")
    return parser.parse_args()


def matches_filters(row: dict[str, Any], difficulties: set[str], stages: set[str]) -> bool:
    meta = row.get("meta", {})
    if not isinstance(meta, dict):
        return False

    difficulty = str(meta.get("difficulty", "")).strip().lower()
    attack_stage = str(meta.get("attack_stage", "")).strip().lower()

    if difficulties and difficulty not in difficulties:
        return False
    if stages and attack_stage not in stages:
        return False
    return True


def main() -> None:
    args = parse_args()

    difficulties = {item.strip().lower() for item in args.difficulty if item.strip()}
    stages = {item.strip().lower() for item in args.attack_stage if item.strip()}

    rows = load_jsonl(args.input)
    filtered = [row for row in rows if matches_filters(row, difficulties, stages)]

    if not filtered:
        raise SystemExit("No records matched the selected filters")

    sample_size = min(args.size, len(filtered))
    rng = random.Random(args.seed)
    sampled = rng.sample(filtered, sample_size)

    write_jsonl(args.output, sampled)
    print(
        f"Evaluation set created: {len(sampled)} rows "
        f"(from {len(filtered)} filtered rows, {len(rows)} total rows) -> {args.output}"
    )


if __name__ == "__main__":
    main()
