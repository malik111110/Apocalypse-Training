# Cybersecurity LLM Training Specification

## MITRE ATT&CK–Aligned Reasoning Model (LLaMA-Based)

---

# 1. Objective

Design and fine-tune a Large Language Model (LLM) to perform structured cybersecurity reasoning aligned with MITRE ATT&CK, focusing on:

* Attack detection
* Technique classification
* Defensive strategy generation
* Incident response reasoning
* Controlled tool orchestration

The model must behave as a **decision-support engine**, not a conversational chatbot.

---

# 2. System Overview

### Training Pipeline

```
Raw Data
 → Normalization
 → Structuring (JSON)
 → Phase 1: Atomic Training
 → Phase 2: Partial Chains
 → Phase 3: Full Scenarios
 → Phase 4: Adversarial Training
 → Phase 5: Tool Alignment
 → Fine-tuning (LoRA / QLoRA)
 → Evaluation
```

---

# 3. Data Schema Design

## 3.1 Core JSON Structure

```json
{
  "id": "unique_case_id",
  "context": {
    "environment": "Windows AD / Cloud / Hybrid",
    "industry": "finance / healthcare / SaaS",
    "critical_assets": ["domain_controller", "db_server"],
    "security_stack": ["EDR", "SIEM"]
  },
  "input": {
    "signals": [],
    "alerts": [],
    "raw_logs": []
  },
  "reasoning": {
    "tactic": "",
    "techniques": [],
    "hypotheses": [],
    "confidence": "low|medium|high",
    "explanation": ""
  },
  "detection": {
    "rules": [],
    "ioc": [],
    "behavior_patterns": []
  },
  "mitigation": {
    "immediate_actions": [],
    "short_term": [],
    "long_term": []
  },
  "response": {
    "containment": [],
    "investigation": [],
    "recovery": []
  },
  "meta": {
    "source": "CVE / simulation / pentest",
    "difficulty": "easy|medium|hard",
    "attack_stage": "initial_access|execution|persistence|..."
  }
}
```

---

## 3.2 Signals Format

```json
"signals": [
  {
    "type": "process_creation",
    "timestamp": "2026-04-18T10:15:00Z",
    "host": "workstation-22",
    "details": {
      "parent_process": "winword.exe",
      "child_process": "powershell.exe",
      "command": "powershell -enc ..."
    }
  }
]
```

---

## 3.3 Reasoning Block

```json
"reasoning": {
  "tactic": "execution",
  "techniques": [
    {
      "name": "Command and Scripting Interpreter",
      "subtype": "PowerShell",
      "likelihood": 0.92
    }
  ],
  "hypotheses": [
    "Malicious macro spawning PowerShell",
    "User-triggered script execution"
  ],
  "confidence": "high",
  "explanation": "Encoded PowerShell combined with unusual parent process indicates malicious execution"
}
```

---

## 3.4 Detection Block

```json
"detection": {
  "rules": [
    "Alert on base64 encoded PowerShell commands",
    "Detect Office spawning shell processes"
  ],
  "ioc": [
    "powershell.exe -enc",
    "winword.exe → powershell.exe"
  ],
  "behavior_patterns": [
    "Office macro abuse",
    "Script-based execution"
  ]
}
```

---

## 3.5 Mitigation Block

```json
"mitigation": {
  "immediate_actions": [
    "Terminate suspicious process",
    "Isolate host"
  ],
  "short_term": [
    "Disable macros",
    "Restrict PowerShell execution"
  ],
  "long_term": [
    "Application whitelisting",
    "Security awareness training"
  ]
}
```

---

# 4. Training Phases

## Phase 1 — Atomic Capability Training

### Objective

Teach isolated skills:

* Signal interpretation
* Log classification
* Technique identification

### Dataset Type

* Small, precise, high-quality samples

### Example

```json
{
  "input": {
    "signals": ["encoded PowerShell command"]
  },
  "output": {
    "tactic": "execution",
    "technique": "PowerShell"
  }
}
```

---

## Phase 2 — Partial Chain Reasoning

### Objective

Teach relationships between concepts.

### Examples

* Signal → Tactic → Technique
* Technique → Detection → Mitigation

### Output Style

Structured reasoning (no long-form text)

---

## Phase 3 — Full Scenario Training

### Objective

Teach complete reasoning under realistic conditions.

### Input

* Context
* Multiple signals
* Noise

### Output

Full structured reasoning pipeline:

* Tactic
* Techniques
* Detection
* Mitigation
* Response

---

## Phase 4 — Adversarial Training

### Objective

Improve robustness.

### Inject:

* Missing logs
* Contradictory signals
* False positives

### Expected Behavior:

* Low confidence outputs
* Multiple hypotheses
* Request for additional data

---

## Phase 5 — Tool Calling Alignment

### Objective

Teach controlled interaction with external systems.

### Example

```json
{
  "action": "call_tool",
  "tool_name": "log_parser",
  "arguments": {
    "log_type": "windows_event"
  }
}
```

### Train:

* When to call tools
* How to interpret tool output
* When not to call tools

---

# 5. Instruction Formatting

Convert JSON into instruction-based training format:

```
### Instruction:
Analyze the cybersecurity scenario.

### Input:
{JSON input}

### Expected Output:
{Structured JSON output}
```

Consistency is mandatory.

---

# 6. Fine-Tuning Strategy

## Recommended Method

* LoRA or QLoRA

## Why

* Lower compute cost
* Faster iteration
* Modular updates

---

## Suggested Hyperparameters

| Parameter       | Value Range        |
| --------------- | ------------------ |
| Learning Rate   | 2e-5 → 5e-5        |
| Epochs          | 2 → 5              |
| Sequence Length | 4k → 8k tokens     |
| Batch Size      | Hardware dependent |

---

# 7. Dataset Distribution

| Type           | Percentage |
| -------------- | ---------- |
| Atomic Tasks   | 30%        |
| Partial Chains | 30%        |
| Full Scenarios | 40%        |

---

# 8. Evaluation Framework

## Metrics

* Tactic classification accuracy
* Technique ranking correctness
* Logical consistency
* Confidence calibration

---

## Test Set Design

Include:

* Known attack scenarios
* Edge cases
* Ambiguous situations
* False positives

---

# 9. Model Behavior Requirements

The model must:

* Express uncertainty when needed
* Avoid overconfidence
* Request missing data
* Prioritize defensive outcomes
* Maintain structured outputs

---

# 10. Common Failure Modes

### 1. Overfitting to Clean Data

→ Real-world data is noisy

### 2. Lack of Structure

→ Leads to inconsistent outputs

### 3. No Uncertainty Handling

→ Model hallucinates confidently

### 4. Context Ignorance

→ Same signal misinterpreted across environments

### 5. No Negative Examples

→ Everything flagged as malicious

---

# 11. System Architecture Perspective

The model is:

* A reasoning engine
* A decision-support system
* A controlled orchestrator

The model is not:

* A chatbot
* A vulnerability database
* An autonomous attacker

---

# 12. Final Notes

Success depends on:

* Data quality over quantity
* Structured reasoning over verbosity
* Controlled training progression
* Continuous evaluation and iteration

A well-trained model should behave like a disciplined junior SOC analyst:

* cautious
* structured
* evidence-driven
* context-aware

Anything else is just confident noise.

---
