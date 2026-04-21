#!/usr/bin/env python3
"""Fetch MITRE ATT&CK STIX bundle for data collection."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import requests

SUPPORTED_DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
DEFAULT_BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"


def default_url_for_domain(domain: str) -> str:
    return f"{DEFAULT_BASE_URL}/{domain}/{domain}.json"


def validate_bundle(payload: dict[str, Any]) -> int:
    if payload.get("type") != "bundle":
        raise ValueError("Downloaded document is not a STIX bundle")
    objects = payload.get("objects")
    if not isinstance(objects, list):
        raise ValueError("STIX bundle is missing an 'objects' list")
    return len(objects)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch MITRE ATT&CK STIX bundle JSON")
    parser.add_argument(
        "--domain",
        choices=SUPPORTED_DOMAINS,
        default="enterprise-attack",
        help="ATT&CK domain to download",
    )
    parser.add_argument("--url", help="Optional override URL for STIX bundle")
    parser.add_argument(
        "--output",
        type=Path,
        help="Output path for downloaded STIX JSON (default data/collection/stix/<domain>.json)",
    )
    parser.add_argument("--timeout", type=int, default=90, help="HTTP timeout in seconds")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing output file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    url = args.url or default_url_for_domain(args.domain)
    output_path = args.output or Path(f"data/collection/stix/{args.domain}.json")

    if output_path.exists() and not args.overwrite:
        raise SystemExit(f"Output already exists: {output_path} (use --overwrite to replace)")

    response = requests.get(url, timeout=args.timeout)
    response.raise_for_status()

    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Unexpected STIX payload type; expected JSON object")

    object_count = validate_bundle(payload)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True)
        handle.write("\n")

    print(f"Downloaded {args.domain} STIX bundle -> {output_path}")
    print(f"STIX objects: {object_count}")
    print(f"Source URL: {url}")


if __name__ == "__main__":
    main()
