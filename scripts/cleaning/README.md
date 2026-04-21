# Cleaning Scripts

## Purpose

Prepare raw cybersecurity records into the project's normalized schema.

## Scripts

- `prepare_cleaning_candidates.py`: pre-filters raw data into accepted/rejected sets before normalization.
- `normalize_cases.py`: maps mixed input shapes into the standard case schema.
- `validate_schema.py`: validates normalized JSONL records before training/evaluation.

## Example

```bash
python scripts/cleaning/prepare_cleaning_candidates.py \
  --input data/raw/cases.collected.jsonl \
  --accepted data/raw/cases.candidates.jsonl \
  --rejected data/collection/rejected/cases.rejected.jsonl \
  --report data/collection/rejected/cases.rejected.report.json

python scripts/cleaning/normalize_cases.py \
  --input data/raw/cases.candidates.jsonl \
  --output data/normalized/cases.normalized.jsonl

python scripts/cleaning/validate_schema.py \
  --input data/normalized/cases.normalized.jsonl
```

Legacy direct flow:

```bash
python scripts/cleaning/normalize_cases.py \
  --input data/raw/cases.jsonl \
  --output data/normalized/cases.normalized.jsonl

python scripts/cleaning/validate_schema.py \
  --input data/normalized/cases.normalized.jsonl
```