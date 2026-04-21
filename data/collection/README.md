# Data Collection Workspace

This area is for data intake before the main normalization pipeline.

- `incoming/`: place source files from simulations, CVE datasets, and pentest exports.
- `staging/`: optional temporary files during merges/transforms.
- `manifests/`: source manifests consumed by collection scripts.
- `rejected/`: records rejected during pre-cleaning checks.

Recommended flow:

1. Add source files to `incoming/`.
2. Define sources in `manifests/sources.example.json` (copy and edit).
3. Run collection script to build a raw merged JSONL.
4. Run pre-cleaning script to split accepted/rejected candidates.
5. Continue with normalization and schema validation.
