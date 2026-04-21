#!/usr/bin/env python3
"""Build instruction-format training records from normalized cybersecurity cases."""

from __future__ import annotations

import argparse
import json
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


def build_text_record(instruction: str, input_payload: dict[str, Any], expected_output: dict[str, Any]) -> str:
    return (
        "### Instruction:\n"
        f"{instruction}\n\n"
        "### Input:\n"
        f"{json.dumps(input_payload, ensure_ascii=True)}\n\n"
        "### Expected Output:\n"
        f"{json.dumps(expected_output, ensure_ascii=True)}"
    )


def to_instruction_record(
    case: dict[str, Any],
    instruction: str,
    include_meta: bool,
) -> dict[str, Any]:
    input_payload: dict[str, Any] = {
        "context": case.get("context", {}),
        "input": case.get("input", {}),
    }
    if include_meta:
        input_payload["meta"] = case.get("meta", {})

    expected_output = {
        "reasoning": case.get("reasoning", {}),
        "detection": case.get("detection", {}),
        "mitigation": case.get("mitigation", {}),
        "response": case.get("response", {}),
    }

    return {
        "id": str(case.get("id", "")),
        "instruction": instruction,
        "input": input_payload,
        "expected_output": expected_output,
        "text": build_text_record(instruction, input_payload, expected_output),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build instruction-format training JSONL from normalized cases")
    parser.add_argument("--input", required=True, type=Path, help="Input normalized JSONL")
    parser.add_argument("--output", required=True, type=Path, help="Output instruction JSONL")
    parser.add_argument(
        "--instruction",
        default="Analyze the cybersecurity scenario.",
        help="Instruction prompt used for all records",
    )
    parser.add_argument(
        "--exclude-meta",
        action="store_true",
        help="Exclude the meta block from the training input payload",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    rows = load_jsonl(args.input)
    records = [
        to_instruction_record(
            case=row,
            instruction=args.instruction,
            include_meta=not args.exclude_meta,
        )
        for row in rows
    ]

    write_jsonl(args.output, records)
    print(f"Built {len(records)} instruction records -> {args.output}")


if __name__ == "__main__":
    main()
