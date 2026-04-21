# Data Collection Scripts

## Purpose

Merge multiple upstream sources into a single raw JSONL before cleaning.

## Scripts

- `collect_from_manifest.py`: reads a manifest of JSON/JSONL sources and writes merged raw data.
- `fetch_attack_stix.py`: downloads ATT&CK STIX bundle JSON for enterprise/mobile/ICS.
- `build_atomic_training_from_stix.py`: builds phase-1 atomic training JSONL from STIX attack patterns, with optional sub-technique inclusion and tactic-balanced sampling.
- `build_enumeration_operations_dataset.py`: builds non-MITRE-focused instruction datasets from local enumeration markdown playbooks, emphasizing information extraction, techniques, tool calls, command execution, and operation possibilities.

## Example

```bash
python scripts/data_collection/collect_from_manifest.py \
  --manifest data/collection/manifests/sources.example.json
```

STIX download + atomic dataset build:

```bash
python scripts/data_collection/fetch_attack_stix.py \
  --domain enterprise-attack \
  --output data/collection/stix/enterprise-attack.json \
  --overwrite

python scripts/data_collection/build_atomic_training_from_stix.py \
  --stix-input data/collection/stix/enterprise-attack.json \
  --output data/raw/atomic/atomic_mitre_attack.jsonl

python scripts/data_collection/build_atomic_training_from_stix.py \
  --stix-input data/collection/stix/enterprise-attack.json \
  --output data/raw/atomic/atomic_mitre_attack_with_subtechniques.jsonl \
  --include-subtechniques

python scripts/data_collection/build_atomic_training_from_stix.py \
  --stix-input data/collection/stix/enterprise-attack.json \
  --output data/raw/atomic/atomic_mitre_attack_with_subtechniques_balanced.jsonl \
  --include-subtechniques \
  --tactic-balanced \
  --balanced-per-tactic 0

# Optional: cap ATT&CK description length (default is full text, no truncation)
python scripts/data_collection/build_atomic_training_from_stix.py \
  --stix-input data/collection/stix/enterprise-attack.json \
  --output data/raw/atomic/atomic_mitre_attack.jsonl \
  --description-max-chars 400
```

Then run pre-cleaning:

```bash
python scripts/cleaning/prepare_cleaning_candidates.py \
  --input data/raw/cases.collected.jsonl \
  --accepted data/raw/cases.candidates.jsonl \
  --rejected data/collection/rejected/cases.rejected.jsonl \
  --report data/collection/rejected/cases.rejected.report.json
```

Enumeration markdown to instruction dataset:

```bash
python scripts/data_collection/build_enumeration_operations_dataset.py \
  --base-dir . \
  --samples-per-file 5 \
  --output-raw data/raw/enumeration.playbooks.operations.jsonl \
  --output-train data/training/train.enumeration.operations.instructions.jsonl \
  --output-eval data/evaluation/eval.enumeration.operations.instructions.jsonl \
  --report data/raw/enumeration.playbooks.operations.report.json
```
