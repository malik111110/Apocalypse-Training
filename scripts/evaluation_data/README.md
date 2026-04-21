# Evaluation Data Scripts

## Purpose

Create reproducible held-out evaluation datasets from normalized cases.

## Scripts

- `build_eval_set.py`: samples a fixed-size subset with optional filtering.
- `assess_phase2_chain_readiness.py`: enforces Phase-2 quality gates (temporal, causal, partial-observability, cross-view, keyword-dependency).

## Example

```bash
python scripts/evaluation_data/build_eval_set.py \
  --input data/normalized/cases.normalized.jsonl \
  --output data/evaluation/eval.easy-medium.jsonl \
  --size 300 \
  --difficulty easy medium \
  --seed 42

python scripts/evaluation_data/assess_phase2_chain_readiness.py \
  --train data/training/train.phase2.partial_chain.apocalypse_v1.jsonl \
  --eval data/evaluation/eval.phase2.partial_chain.apocalypse_v1.jsonl \
  --report data/evaluation/phase2_chain_readiness.report.json
```