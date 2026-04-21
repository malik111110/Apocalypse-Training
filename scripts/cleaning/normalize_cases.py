#!/usr/bin/env python3
"""Normalize cybersecurity training cases into a consistent JSON schema."""

from __future__ import annotations

import argparse
import json
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

DEFAULT_CASE = {
    "id": "",
    "context": {
        "environment": "",
        "industry": "",
        "critical_assets": [],
        "security_stack": [],
    },
    "input": {
        "signals": [],
        "alerts": [],
        "raw_logs": [],
    },
    "reasoning": {
        "tactic": "",
        "techniques": [],
        "hypotheses": [],
        "confidence": "low",
        "explanation": "",
    },
    "detection": {
        "rules": [],
        "ioc": [],
        "behavior_patterns": [],
    },
    "mitigation": {
        "immediate_actions": [],
        "short_term": [],
        "long_term": [],
    },
    "response": {
        "containment": [],
        "investigation": [],
        "recovery": [],
    },
    "meta": {
        "source": "",
        "difficulty": "",
        "attack_stage": "",
    },
}

ALLOWED_CONFIDENCE = {"low", "medium", "high"}
LIST_PATHS = [
    ("context", "critical_assets"),
    ("context", "security_stack"),
    ("input", "signals"),
    ("input", "alerts"),
    ("input", "raw_logs"),
    ("reasoning", "techniques"),
    ("reasoning", "hypotheses"),
    ("detection", "rules"),
    ("detection", "ioc"),
    ("detection", "behavior_patterns"),
    ("mitigation", "immediate_actions"),
    ("mitigation", "short_term"),
    ("mitigation", "long_term"),
    ("response", "containment"),
    ("response", "investigation"),
    ("response", "recovery"),
]


def ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def deep_merge(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    for key, value in incoming.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def adapt_input_shape(raw_case: dict[str, Any]) -> dict[str, Any]:
    adapted = deepcopy(raw_case)

    has_top_level_input_parts = any(key in adapted for key in ("signals", "alerts", "raw_logs"))
    if "input" not in adapted and has_top_level_input_parts:
        adapted["input"] = {
            "signals": ensure_list(adapted.pop("signals", [])),
            "alerts": ensure_list(adapted.pop("alerts", [])),
            "raw_logs": ensure_list(adapted.pop("raw_logs", [])),
        }

    # Support minimal atomic examples that place prediction in "output".
    output = adapted.get("output")
    if isinstance(output, dict) and "reasoning" not in adapted:
        adapted["reasoning"] = {
            "tactic": output.get("tactic", ""),
            "techniques": ensure_list(output.get("technique", [])),
            "hypotheses": [],
            "confidence": "low",
            "explanation": "",
        }

    return adapted


def normalize_case(raw_case: dict[str, Any], index: int) -> dict[str, Any]:
    adapted = adapt_input_shape(raw_case)
    normalized = deep_merge(deepcopy(DEFAULT_CASE), adapted)

    if not normalized.get("id"):
        normalized["id"] = f"case-{index:06d}-{uuid.uuid4().hex[:8]}"

    if normalized["reasoning"].get("confidence") not in ALLOWED_CONFIDENCE:
        normalized["reasoning"]["confidence"] = "low"

    for section, key in LIST_PATHS:
        section_obj = normalized.setdefault(section, {})
        section_obj[key] = ensure_list(section_obj.get(key, []))

    return normalized


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
    parser = argparse.ArgumentParser(description="Normalize cybersecurity cases into the project schema")
    parser.add_argument("--input", required=True, type=Path, help="Input JSONL file")
    parser.add_argument("--output", required=True, type=Path, help="Output normalized JSONL file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = load_jsonl(args.input)
    normalized_rows = [normalize_case(case, index + 1) for index, case in enumerate(rows)]
    write_jsonl(args.output, normalized_rows)
    print(f"Normalized {len(normalized_rows)} cases -> {args.output}")


if __name__ == "__main__":
    main()
