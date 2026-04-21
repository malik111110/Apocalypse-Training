# Offensive Operations Instruction Dataset Spec (Serious Mode)

## Goal
Train the model to execute realistic, step-by-step offensive operations from partial machine evidence.
The model must infer, branch, validate, and report, not memorize walkthrough answers.

## What Good Looks Like
- Multi-stage operation flow, not one-shot exploitation.
- Numbered phases with explicit decision gates.
- Evidence-driven progress: every move tied to collected artifacts.
- Fallback path when a branch fails.
- OPSEC and scope boundaries included.
- Final self-assessment of operation solidity.

## Required Record Schema
Each JSONL row must include:
- id
- instruction
- input
- expected_output
- text

### input (minimum)
- target
  - slug
  - title
  - source
  - platform
  - target_type
- objective
- sections_in_scope
- observed_commands
- operation_mode
- constraints

### expected_output (minimum)
- reasoning
  - mode
  - anti_memorization_rules
  - thinking_steps
  - possibility_branches
  - evidence_collection_plan
  - bug_hunting_paths
  - command_execution_plan
  - decision_points
  - confidence_guidance
  - operation_requirements
- operation_runbook
  - operation_profile
  - step_by_step_operation (numbered list)
  - cross_target_hypotheses
  - opsec_controls
- assessment
  - score (0-100)
  - solid_for_project (boolean)
  - strengths
  - risks
  - status

## Step-by-Step Operation Contract
Each step in operation_runbook.step_by_step_operation must contain:
- step (integer, ascending)
- phase
- objective
- primary_commands
- fallback_commands
- required_evidence
- decision_gate
- success_criteria
- failure_action

## Anti-Memorization Rules
- Do not emit room/machine answers or flags as default outputs.
- Do not trust a known path unless current evidence confirms it.
- Keep at least two active hypotheses until one is rejected by evidence.
- Prefer command choices that disambiguate hypotheses.

## Quality Gates (Project Readiness)
Dataset should pass all of the following:
- Schema completeness: 100%
- Records with numbered runbook steps: >= 95%
- Mean operation steps per record: >= 6
- Mean observed_commands per record: >= 6
- Records with fallback branches: >= 95%
- Records with OPSEC controls: >= 95%
- Records with assessment score >= 75: >= 70%

## Training Usage Guidance
- Use serious mode datasets for SFT/instruction tuning.
- Keep a held-out eval split from the same schema.
- Track pre/post metrics on branch quality, evidence grounding, and failure handling.

## Recommended Outputs
- HTB train: data/training/train.htb.serious_ops.instructions.jsonl
- HTB eval: data/evaluation/eval.htb.serious_ops.instructions.jsonl
- THM train: data/training/train.thm.serious_ops.instructions.jsonl
- THM eval: data/evaluation/eval.thm.serious_ops.instructions.jsonl
