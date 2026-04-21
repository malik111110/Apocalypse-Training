#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

DOMAIN="${1:-enterprise-attack}"
STIX_OUTPUT="${2:-$ROOT_DIR/data/collection/stix/${DOMAIN}.json}"
ATOMIC_OUTPUT="${3:-$ROOT_DIR/data/raw/atomic/atomic_${DOMAIN}.jsonl}"
ATOMIC_SUBTECH_OUTPUT="${4:-$ROOT_DIR/data/raw/atomic/atomic_${DOMAIN}_with_subtechniques.jsonl}"
ATOMIC_BALANCED_OUTPUT="${5:-$ROOT_DIR/data/raw/atomic/atomic_${DOMAIN}_with_subtechniques_balanced.jsonl}"
BALANCED_PER_TACTIC="${6:-0}"

"$PYTHON_BIN" "$ROOT_DIR/scripts/data_collection/fetch_attack_stix.py" \
  --domain "$DOMAIN" \
  --output "$STIX_OUTPUT" \
  --overwrite

"$PYTHON_BIN" "$ROOT_DIR/scripts/data_collection/build_atomic_training_from_stix.py" \
  --stix-input "$STIX_OUTPUT" \
  --output "$ATOMIC_OUTPUT"

"$PYTHON_BIN" "$ROOT_DIR/scripts/data_collection/build_atomic_training_from_stix.py" \
  --stix-input "$STIX_OUTPUT" \
  --output "$ATOMIC_SUBTECH_OUTPUT" \
  --include-subtechniques

if [[ "$BALANCED_PER_TACTIC" != "0" ]]; then
  "$PYTHON_BIN" "$ROOT_DIR/scripts/data_collection/build_atomic_training_from_stix.py" \
    --stix-input "$STIX_OUTPUT" \
    --output "$ATOMIC_BALANCED_OUTPUT" \
    --include-subtechniques \
    --tactic-balanced \
    --balanced-per-tactic "$BALANCED_PER_TACTIC"
else
  "$PYTHON_BIN" "$ROOT_DIR/scripts/data_collection/build_atomic_training_from_stix.py" \
    --stix-input "$STIX_OUTPUT" \
    --output "$ATOMIC_BALANCED_OUTPUT" \
    --include-subtechniques \
    --tactic-balanced
fi

echo "Atomic collection pipeline finished"
echo "- STIX bundle: $STIX_OUTPUT"
echo "- Atomic data (base): $ATOMIC_OUTPUT"
echo "- Atomic data (with sub-techniques): $ATOMIC_SUBTECH_OUTPUT"
echo "- Atomic data (with sub-techniques + tactic-balanced): $ATOMIC_BALANCED_OUTPUT"
