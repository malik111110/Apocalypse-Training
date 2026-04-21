#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

MANIFEST_PATH="${1:-$ROOT_DIR/data/collection/manifests/sources.example.json}"
COLLECTED_RAW="${2:-$ROOT_DIR/data/raw/cases.collected.jsonl}"
CANDIDATES_RAW="${3:-$ROOT_DIR/data/raw/cases.candidates.jsonl}"
REJECTED_JSONL="${4:-$ROOT_DIR/data/collection/rejected/cases.rejected.jsonl}"
REJECT_REPORT="${5:-$ROOT_DIR/data/collection/rejected/cases.rejected.report.json}"
NORMALIZED_JSONL="${6:-$ROOT_DIR/data/normalized/cases.normalized.jsonl}"

"$PYTHON_BIN" "$ROOT_DIR/scripts/data_collection/collect_from_manifest.py" \
  --manifest "$MANIFEST_PATH" \
  --output "$COLLECTED_RAW"

"$PYTHON_BIN" "$ROOT_DIR/scripts/cleaning/prepare_cleaning_candidates.py" \
  --input "$COLLECTED_RAW" \
  --accepted "$CANDIDATES_RAW" \
  --rejected "$REJECTED_JSONL" \
  --report "$REJECT_REPORT"

"$PYTHON_BIN" "$ROOT_DIR/scripts/cleaning/normalize_cases.py" \
  --input "$CANDIDATES_RAW" \
  --output "$NORMALIZED_JSONL"

"$PYTHON_BIN" "$ROOT_DIR/scripts/cleaning/validate_schema.py" \
  --input "$NORMALIZED_JSONL"

echo "Collection preparation pipeline finished"
echo "- Collected raw:   $COLLECTED_RAW"
echo "- Candidate raw:   $CANDIDATES_RAW"
echo "- Rejected rows:   $REJECTED_JSONL"
echo "- Rejected report: $REJECT_REPORT"
echo "- Normalized:      $NORMALIZED_JSONL"
