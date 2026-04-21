#!/usr/bin/env python3
"""Validate normalized cybersecurity cases against the expected structure."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ALLOWED_CONFIDENCE = {"low", "medium", "high"}

REQUIRED_TOP_LEVEL = {
    "id": str,
    "context": dict,
    "input": dict,
    "reasoning": dict,
    "detection": dict,
    "mitigation": dict,
    "response": dict,
    "meta": dict,
}

REQUIRED_NESTED = {
    "context": {
        "environment": str,
        "industry": str,
        "critical_assets": list,
        "security_stack": list,
    },
    "input": {
        "signals": list,
        "alerts": list,
        "raw_logs": list,
    },
    "reasoning": {
        "tactic": str,
        "techniques": list,
        "hypotheses": list,
        "confidence": str,
        "explanation": str,
    },
    "detection": {
        "rules": list,
        "ioc": list,
        "behavior_patterns": list,
    },
    "mitigation": {
        "immediate_actions": list,
        "short_term": list,
        "long_term": list,
    },
    "response": {
        "containment": list,
        "investigation": list,
        "recovery": list,
    },
    "meta": {
        "source": str,
        "difficulty": str,
        "attack_stage": str,
    },
}


def type_name(value: Any) -> str:
    return type(value).__name__


def validate_case(case: dict[str, Any], line_number: int) -> list[str]:
    errors: list[str] = []

    for key, expected_type in REQUIRED_TOP_LEVEL.items():
        if key not in case:
            errors.append(f"line {line_number}: missing top-level key '{key}'")
            continue
        if not isinstance(case[key], expected_type):
            errors.append(
                f"line {line_number}: key '{key}' must be {expected_type.__name__}, got {type_name(case[key])}"
            )

    for section, section_rules in REQUIRED_NESTED.items():
        section_obj = case.get(section)
        if not isinstance(section_obj, dict):
            continue
        for key, expected_type in section_rules.items():
            if key not in section_obj:
                errors.append(f"line {line_number}: missing key '{section}.{key}'")
                continue
            if not isinstance(section_obj[key], expected_type):
                errors.append(
                    "line "
                    f"{line_number}: key '{section}.{key}' must be {expected_type.__name__}, "
                    f"got {type_name(section_obj[key])}"
                )

    confidence = case.get("reasoning", {}).get("confidence")
    if isinstance(confidence, str) and confidence not in ALLOWED_CONFIDENCE:
        errors.append(
            f"line {line_number}: reasoning.confidence must be one of {sorted(ALLOWED_CONFIDENCE)}, got '{confidence}'"
        )

    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate normalized cybersecurity JSONL schema")
    parser.add_argument("--input", required=True, type=Path, help="Input JSONL file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    found_errors: list[str] = []
    total = 0

    with args.input.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue

            total += 1
            try:
                case = json.loads(text)
            except json.JSONDecodeError as error:
                found_errors.append(f"line {line_number}: invalid JSON ({error.msg})")
                continue

            if not isinstance(case, dict):
                found_errors.append(f"line {line_number}: root element must be an object")
                continue

            found_errors.extend(validate_case(case, line_number))

    if found_errors:
        print("Schema validation failed:")
        for error in found_errors:
            print(f"- {error}")
        raise SystemExit(1)

    print(f"Schema validation passed for {total} cases")


if __name__ == "__main__":
    main()
