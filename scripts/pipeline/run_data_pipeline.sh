#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

INPUT_JSONL="${1:-$ROOT_DIR/data/raw/cases.jsonl}"
NORMALIZED_JSONL="${2:-$ROOT_DIR/data/normalized/cases.normalized.jsonl}"
TRAINING_JSONL="${3:-$ROOT_DIR/data/training/train.instructions.jsonl}"
EVAL_JSONL="${4:-$ROOT_DIR/data/evaluation/eval.sample.jsonl}"

"$PYTHON_BIN" "$ROOT_DIR/scripts/cleaning/normalize_cases.py" \
  --input "$INPUT_JSONL" \
  --output "$NORMALIZED_JSONL"

"$PYTHON_BIN" "$ROOT_DIR/scripts/cleaning/validate_schema.py" \
  --input "$NORMALIZED_JSONL"

"$PYTHON_BIN" "$ROOT_DIR/scripts/training/build_instruction_dataset.py" \
  --input "$NORMALIZED_JSONL" \
  --output "$TRAINING_JSONL"

"$PYTHON_BIN" "$ROOT_DIR/scripts/evaluation_data/build_eval_set.py" \
  --input "$NORMALIZED_JSONL" \
  --output "$EVAL_JSONL" \
  --size 200 \
  --seed 42

echo "Pipeline finished"
echo "- Normalized: $NORMALIZED_JSONL"
echo "- Training:   $TRAINING_JSONL"
echo "- Evaluation: $EVAL_JSONL"
