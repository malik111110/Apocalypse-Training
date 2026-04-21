# Prompt Templates

These templates are aligned with the Apocalypse training phases and enforce consistent instruction format.

## Placeholder Convention

Use double-brace placeholders and replace them during dataset generation:

- `{{case_id}}`
- `{{context_json}}`
- `{{input_json}}`
- `{{reasoning_json}}`
- `{{detection_json}}`
- `{{mitigation_json}}`
- `{{response_json}}`
- `{{meta_json}}`
- `{{tool_output_json}}`

## Files

- `phase1_atomic.md`
- `phase2_partial_chain.md`
- `phase3_full_scenario.md`
- `phase4_adversarial.md`
- `phase5_tool_alignment.md`
- `structured_output_contract.json`
