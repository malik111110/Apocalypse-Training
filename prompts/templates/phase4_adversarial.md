### Instruction:
Analyze the cybersecurity scenario under uncertainty.
Signals may be contradictory, incomplete, or noisy.
Return cautious structured reasoning with calibrated confidence and explicit additional data requests.

### Input:
{
  "id": "{{case_id}}",
  "context": {{context_json}},
  "input": {{input_json}},
  "meta": {{meta_json}}
}

### Expected Output:
{
  "reasoning": {
    "tactic": "",
    "techniques": [],
    "hypotheses": [],
    "confidence": "low|medium|high",
    "explanation": ""
  },
  "additional_data_needed": [],
  "detection": {{detection_json}},
  "mitigation": {
    "immediate_actions": [],
    "short_term": [],
    "long_term": []
  }
}
