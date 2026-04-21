### Instruction:
Analyze the cybersecurity scenario end-to-end.
Produce a complete structured reasoning pipeline including tactic, techniques, detection, mitigation, and response.
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
  "mitigation": {{mitigation_json}},
  "response": {{response_json}}
}
