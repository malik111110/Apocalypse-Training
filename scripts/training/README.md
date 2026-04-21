# Training Scripts

## Purpose

Convert normalized cases into instruction-format records used by fine-tuning jobs.

## Scripts

- `build_instruction_dataset.py`: emits JSONL rows containing instruction, input, expected_output, and text fields.
- `build_phase_prompt_dataset.py`: renders phase-specific prompt templates from normalized cases.

## Example

```bash
python scripts/training/build_instruction_dataset.py \
  --input data/normalized/cases.normalized.jsonl \
  --output data/training/train.instructions.jsonl

python scripts/training/build_phase_prompt_dataset.py \
  --input data/normalized/cases.normalized.jsonl \
  --template prompts/templates/phase3_full_scenario.md \
  --output data/training/train.phase3.prompts.jsonl \
  --phase phase3_full_scenario
```
