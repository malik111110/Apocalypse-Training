### Instruction:
Analyze the cybersecurity scenario and perform atomic reasoning only.
Identify the most likely tactic and primary technique from the provided signal(s).
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
  "reasoning": {
    "tactic": "",
    "techniques": [
      {
        "name": "",
        "subtype": "",
        "likelihood": 0.0
      }
    ],
    "hypotheses": [],
    "confidence": "low|medium|high",
    "explanation": ""
  }
}
