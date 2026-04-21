#!/usr/bin/env python3
"""Render phase prompt templates into JSONL training records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PLACEHOLDERS = (
    "{{case_id}}",
    "{{context_json}}",
    "{{input_json}}",
    "{{reasoning_json}}",
    "{{detection_json}}",
    "{{mitigation_json}}",
    "{{response_json}}",
    "{{meta_json}}",
    "{{tool_output_json}}",
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSON in {path} line {line_number}: {error.msg}") from error
            if not isinstance(row, dict):
                raise ValueError(f"Line {line_number} in {path} must be a JSON object")
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def dump_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True)


def render_template(template: str, case: dict[str, Any]) -> str:
    values = {
        "{{case_id}}": str(case.get("id", "")),
        "{{context_json}}": dump_json(case.get("context", {})),
        "{{input_json}}": dump_json(case.get("input", {})),
        "{{reasoning_json}}": dump_json(case.get("reasoning", {})),
        "{{detection_json}}": dump_json(case.get("detection", {})),
        "{{mitigation_json}}": dump_json(case.get("mitigation", {})),
        "{{response_json}}": dump_json(case.get("response", {})),
        "{{meta_json}}": dump_json(case.get("meta", {})),
        "{{tool_output_json}}": dump_json({}),
    }

    rendered = template
    for key in PLACEHOLDERS:
        rendered = rendered.replace(key, values[key])
    return rendered


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build phase prompt dataset from normalized JSONL")
    parser.add_argument("--input", required=True, type=Path, help="Input normalized JSONL")
    parser.add_argument("--template", required=True, type=Path, help="Prompt template file")
    parser.add_argument("--output", required=True, type=Path, help="Output JSONL file")
    parser.add_argument("--phase", required=True, help="Phase label, e.g. phase1_atomic")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    with args.template.open("r", encoding="utf-8") as handle:
        template_text = handle.read()

    rows = load_jsonl(args.input)

    output_rows: list[dict[str, Any]] = []
    for case in rows:
        output_rows.append(
            {
                "id": str(case.get("id", "")),
                "phase": args.phase,
                "template": str(args.template),
                "prompt": render_template(template_text, case),
            }
        )

    write_jsonl(args.output, output_rows)
    print(f"Built {len(output_rows)} phase prompt rows -> {args.output}")


if __name__ == "__main__":
    main()
