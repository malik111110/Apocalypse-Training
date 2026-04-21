# Pipeline Runner

## Purpose

Run the core data flow in one command:

1. Normalize raw cases
2. Validate schema
3. Build instruction training data
4. Build evaluation subset

Collection-first preparation flow:

1. Collect from source manifest
2. Pre-clean accepted/rejected candidates
3. Normalize accepted candidates
4. Validate normalized schema

## Usage

```bash
bash scripts/pipeline/run_data_pipeline.sh
```

Optional custom paths:

```bash
bash scripts/pipeline/run_data_pipeline.sh \
  data/raw/cases.jsonl \
  data/normalized/cases.normalized.jsonl \
  data/training/train.instructions.jsonl \
  data/evaluation/eval.sample.jsonl
```

Collection-first command:

```bash
bash scripts/pipeline/run_collection_prep.sh
```

Atomic ATT&CK STIX collection command:

```bash
bash scripts/pipeline/run_atomic_collection.sh
```

Atomic pipeline outputs:

1. Base techniques only
2. With sub-techniques
3. With sub-techniques + tactic-balanced sampling

Optional arguments:

```bash
bash scripts/pipeline/run_atomic_collection.sh \
  enterprise-attack \
  data/collection/stix/enterprise-attack.json \
  data/raw/atomic/atomic_enterprise-attack.jsonl \
  data/raw/atomic/atomic_enterprise-attack_with_subtechniques.jsonl \
  data/raw/atomic/atomic_enterprise-attack_with_subtechniques_balanced.jsonl \
  0
```

Notes:

1. The final argument is `balanced_per_tactic` (`0` means auto-balance).
2. Tactic-balanced sampling keeps tactic distribution from being dominated by high-volume technique families.
3. ATT&CK description text is full-length by default; use `--description-max-chars` only when you want explicit truncation in direct script runs.

