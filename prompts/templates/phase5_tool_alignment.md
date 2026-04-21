### Instruction:
Analyze the cybersecurity scenario and decide whether a tool call is required.
If additional telemetry is needed, emit a controlled tool call.
If enough data exists, provide final structured reasoning without tool usage.

### Input:
{
  "id": "{{case_id}}",
  "context": {{context_json}},
  "input": {{input_json}},
  "meta": {{meta_json}},
  "available_tools": [
    {
      "name": "log_parser",
      "arguments_schema": {
        "log_type": "string"
      }
    },
    {
      "name": "edr_lookup",
      "arguments_schema": {
        "host": "string",
        "time_range": "string"
      }
    }
  ],
  "tool_output": {{tool_output_json}}
}

### Expected Output:
{
  "decision": "call_tool|final_answer",
  "action": {
    "tool_name": "",
    "arguments": {}
  },
  "reasoning": {{reasoning_json}},
  "detection": {{detection_json}},
  "mitigation": {{mitigation_json}},
  "response": {{response_json}}
}
