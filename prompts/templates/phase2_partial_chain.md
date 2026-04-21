### Instruction:
Analyze the cybersecurity scenario and complete partial-chain reasoning.
Map observed behavior to tactic and techniques, then generate targeted detection and mitigation outputs.
Return strictly structured JSON.

### Input:
{
  "id": "{{case_id}}",
  "context": {{context_json}},
  "input": {{input_json}},
  "meta": {{meta_json}}
}

### Expected Output:
{
  "reasoning": {{reasoning_json}},
  "detection": {{detection_json}},
  "mitigation": {
    "immediate_actions": [],
    "short_term": [],
    "long_term": []
  }
}
