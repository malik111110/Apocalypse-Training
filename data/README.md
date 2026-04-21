# Data Layout

This folder organizes datasets across the training pipeline.

- `collection/`: source intake workspace (incoming files, manifests, rejected records).
- `raw/`: source material before normalization.
- `normalized/`: records standardized to the core JSON schema.
- `training/`: instruction-formatted data used for fine-tuning.
- `evaluation/`: held-out evaluation sets and benchmark slices.
- `samples/`: small examples for quick validation and demos.

Suggested flow:

1. Place incoming files in `raw/`.
2. Or use `collection/` + source manifests to merge multiple feeds first.
3. Run cleaning scripts to produce normalized JSONL in `normalized/`.
4. Build training/evaluation subsets from normalized data.
5. Keep immutable snapshots in `evaluation/` for reproducible scoring.