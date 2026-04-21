#!/usr/bin/env python3
"""Assess serious offensive operation instruction datasets.

This script evaluates structural quality and readiness signals for training use.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REQUIRED_TOP_KEYS = {"id", "instruction", "input", "expected_output", "text"}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Invalid JSON at {path}:{idx}: {exc}") from exc
            if not isinstance(obj, dict):
                raise RuntimeError(f"Non-object JSON at {path}:{idx}")
            rows.append(obj)
    return rows


def pct(part: int, whole: int) -> float:
    return round((part / whole) * 100, 2) if whole else 0.0


def mean(values: list[int]) -> float:
    return round(sum(values) / len(values), 2) if values else 0.0


def assess_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)

    missing_required = 0
    records_with_numbered_steps = 0
    records_with_fallback = 0
    records_with_opsec = 0
    records_with_score_ge_75 = 0
    command_lengths: list[int] = []
    step_lengths: list[int] = []

    for row in rows:
        if not REQUIRED_TOP_KEYS.issubset(set(row.keys())):
            missing_required += 1

        input_obj = row.get("input", {})
        commands = input_obj.get("observed_commands", []) if isinstance(input_obj, dict) else []
        if isinstance(commands, list):
            command_lengths.append(len(commands))
        else:
            command_lengths.append(0)

        expected = row.get("expected_output", {}) if isinstance(row.get("expected_output", {}), dict) else {}
        runbook = expected.get("operation_runbook", {}) if isinstance(expected.get("operation_runbook", {}), dict) else {}
        steps = runbook.get("step_by_step_operation", []) if isinstance(runbook.get("step_by_step_operation", []), list) else []

        step_lengths.append(len(steps))

        if steps and all(isinstance(s, dict) and isinstance(s.get("step"), int) for s in steps):
            records_with_numbered_steps += 1

        if steps and all(isinstance(s, dict) and s.get("fallback_commands") for s in steps):
            records_with_fallback += 1

        opsec = runbook.get("opsec_controls", {}) if isinstance(runbook.get("opsec_controls", {}), dict) else {}
        if opsec and opsec.get("boundaries") and opsec.get("stop_conditions"):
            records_with_opsec += 1

        assessment = expected.get("assessment", {}) if isinstance(expected.get("assessment", {}), dict) else {}
        score = assessment.get("score", 0)
        if isinstance(score, int | float) and score >= 75:
            records_with_score_ge_75 += 1

    metrics = {
        "total_records": total,
        "schema_completeness_pct": pct(total - missing_required, total),
        "numbered_steps_pct": pct(records_with_numbered_steps, total),
        "fallback_coverage_pct": pct(records_with_fallback, total),
        "opsec_coverage_pct": pct(records_with_opsec, total),
        "records_score_ge_75_pct": pct(records_with_score_ge_75, total),
        "avg_observed_commands": mean(command_lengths),
        "avg_operation_steps": mean(step_lengths),
        "min_operation_steps": min(step_lengths) if step_lengths else 0,
        "max_operation_steps": max(step_lengths) if step_lengths else 0,
    }

    gates = {
        "schema_completeness_pct": 100.0,
        "numbered_steps_pct": 95.0,
        "fallback_coverage_pct": 95.0,
        "opsec_coverage_pct": 95.0,
        "records_score_ge_75_pct": 70.0,
        "avg_observed_commands": 6.0,
        "avg_operation_steps": 6.0,
    }

    checks = {
        name: metrics.get(name, 0.0) >= threshold
        for name, threshold in gates.items()
    }

    passed = all(checks.values())

    return {
        "metrics": metrics,
        "quality_gates": gates,
        "checks": checks,
        "overall_status": "pass" if passed else "needs_hardening",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assess offensive operation instruction dataset quality")
    parser.add_argument("--input", action="append", required=True, help="Input JSONL path(s)")
    parser.add_argument("--output", type=Path, default=Path("data/raw/offensive.dataset.assessment.json"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    combined: list[dict[str, Any]] = []
    per_file: dict[str, Any] = {}

    for raw_path in args.input:
        path = Path(raw_path)
        rows = load_jsonl(path)
        per_file[str(path)] = assess_rows(rows)
        combined.extend(rows)

    combined_assessment = assess_rows(combined)

    report = {
        "files": per_file,
        "combined": combined_assessment,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"Assessment written: {args.output}")
    print(f"Combined status:    {combined_assessment['overall_status']}")
    print(f"Total records:      {combined_assessment['metrics']['total_records']}")


if __name__ == "__main__":
    main()
