#!/usr/bin/env python3
"""Filter raw records into accepted and rejected sets before normalization."""

from __future__ import annotations

import argparse
import json
from collections import Counter
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
                raise ValueError(f"Invalid JSON in line {line_number}: {error.msg}") from error
            if not isinstance(obj, dict):
                raise ValueError(f"Line {line_number} must be a JSON object")
            rows.append(obj)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def has_minimum_signal_input(case: dict[str, Any]) -> bool:
    if isinstance(case.get("input"), dict):
        input_block = case["input"]
        for key in ("signals", "alerts", "raw_logs"):
            if key in input_block:
                return True

    for key in ("signals", "alerts", "raw_logs"):
        if key in case:
            return True

    return False


def classify(case: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(case, dict):
        return False, "root_not_object"

    if "input" in case and not isinstance(case["input"], dict):
        return False, "input_not_object"

    if "output" in case and not isinstance(case["output"], dict):
        return False, "output_not_object"

    has_signal_content = has_minimum_signal_input(case)
    has_output_hint = isinstance(case.get("output"), dict)

    if not has_signal_content and not has_output_hint:
        return False, "missing_input_signals_and_output"

    return True, "accepted"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare raw cases for cleaning by filtering invalid inputs")
    parser.add_argument("--input", required=True, type=Path, help="Input raw JSONL")
    parser.add_argument("--accepted", required=True, type=Path, help="Output accepted JSONL")
    parser.add_argument("--rejected", required=True, type=Path, help="Output rejected JSONL with reasons")
    parser.add_argument("--report", required=True, type=Path, help="Output JSON report")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = load_jsonl(args.input)

    accepted_rows: list[dict[str, Any]] = []
    rejected_rows: list[dict[str, Any]] = []
    reason_counter: Counter[str] = Counter()

    for row in rows:
        is_valid, reason = classify(row)
        if is_valid:
            accepted_rows.append(row)
        else:
            rejected_rows.append({"reason": reason, "record": row})
            reason_counter[reason] += 1

    write_jsonl(args.accepted, accepted_rows)
    write_jsonl(args.rejected, rejected_rows)

    report = {
        "input": str(args.input),
        "accepted_output": str(args.accepted),
        "rejected_output": str(args.rejected),
        "total": len(rows),
        "accepted": len(accepted_rows),
        "rejected": len(rejected_rows),
        "rejection_reasons": dict(reason_counter),
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)
        handle.write("\n")

    print(f"Accepted {len(accepted_rows)} / {len(rows)} records")
    print(f"Rejected {len(rejected_rows)} / {len(rows)} records")
    print(f"Report -> {args.report}")


if __name__ == "__main__":
    main()
