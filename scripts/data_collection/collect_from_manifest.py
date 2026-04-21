#!/usr/bin/env python3
"""Collect and merge raw cybersecurity cases from a manifest of sources."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Manifest root must be a JSON object")
    if "sources" not in data or not isinstance(data["sources"], list):
        raise ValueError("Manifest must define a 'sources' list")
    return data


def iter_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSON in {path} line {line_number}: {error.msg}") from error
            if not isinstance(obj, dict):
                raise ValueError(f"Record in {path} line {line_number} must be a JSON object")
            rows.append(obj)
    return rows


def iter_json(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and isinstance(data.get("records"), list):
        rows = data["records"]
    else:
        raise ValueError(f"Unsupported JSON structure in {path}: expected list or object with 'records'")

    output: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"Record {index} in {path} must be a JSON object")
        output.append(row)
    return output


def read_source_rows(path: Path, source_format: str) -> list[dict[str, Any]]:
    if source_format == "jsonl":
        return iter_jsonl(path)
    if source_format == "json":
        return iter_json(path)
    raise ValueError(f"Unsupported source format: {source_format}")


def merge_meta(case: dict[str, Any], source_name: str, default_meta: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(case)
    meta = merged.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    for key, value in default_meta.items():
        meta.setdefault(key, value)

    meta.setdefault("source", source_name)
    merged["meta"] = meta
    return merged


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect and merge JSON/JSONL sources into raw JSONL")
    parser.add_argument("--manifest", required=True, type=Path, help="Path to source manifest JSON")
    parser.add_argument("--output", type=Path, help="Optional output JSONL path (overrides manifest output_raw)")
    parser.add_argument("--report", type=Path, help="Optional report JSON path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest = load_manifest(args.manifest)

    root_dir = Path.cwd()
    sources = manifest["sources"]

    if args.output is not None:
        output_path = args.output
    else:
        output_raw = manifest.get("output_raw")
        if not isinstance(output_raw, str) or not output_raw.strip():
            raise ValueError("Manifest must define 'output_raw' when --output is not provided")
        output_path = root_dir / output_raw

    merged_rows: list[dict[str, Any]] = []
    source_stats: list[dict[str, Any]] = []

    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("Each source in manifest must be an object")

        source_name = str(source.get("name", "")).strip()
        source_path_raw = str(source.get("path", "")).strip()
        source_format = str(source.get("format", "jsonl")).strip().lower()
        default_meta = source.get("default_meta", {})

        if not source_name:
            raise ValueError("Each source must define a non-empty 'name'")
        if not source_path_raw:
            raise ValueError(f"Source '{source_name}' must define a non-empty 'path'")
        if not isinstance(default_meta, dict):
            raise ValueError(f"Source '{source_name}' default_meta must be an object")

        source_path = root_dir / source_path_raw
        if not source_path.exists():
            raise FileNotFoundError(f"Source path does not exist: {source_path}")

        rows = read_source_rows(source_path, source_format)
        enriched = [merge_meta(case=row, source_name=source_name, default_meta=default_meta) for row in rows]
        merged_rows.extend(enriched)

        source_stats.append(
            {
                "name": source_name,
                "path": str(source_path),
                "format": source_format,
                "records": len(rows),
            }
        )

    write_jsonl(output_path, merged_rows)

    report = {
        "manifest": str(args.manifest),
        "output": str(output_path),
        "sources": source_stats,
        "total_records": len(merged_rows),
    }

    report_path = args.report
    if report_path is None:
        report_path = output_path.with_suffix(".report.json")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)
        handle.write("\n")

    print(f"Collected {len(merged_rows)} records -> {output_path}")
    print(f"Report -> {report_path}")


if __name__ == "__main__":
    main()
