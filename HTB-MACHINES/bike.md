# HTB Bike - Node/Express SSTI to Command Execution

Scope: authorized HTB lab only.
Focus: template injection detection, sandbox bypass, and command execution through server-side template context.

---

## 1. Investigation Objective

1. Map exposed services and web technology stack.
2. Verify server-side template evaluation behavior.
3. Confirm impact from arithmetic injection to OS command execution.
4. Validate privilege context and sensitive data exposure.

---

## 2. Recon and Technology Fingerprinting

```bash
nmap -sC -sV -Pn -p- <TARGET_IP>
curl -I http://<TARGET_IP>
```

Common Bike findings:
- 22/tcp SSH
- 80/tcp HTTP (Node.js / Express)

Template engine clue:
- Error traces and response behavior indicate Handlebars-style rendering.

---

## 3. SSTI Validation

Probe payload:

```text
{{7*7}}
```

If response evaluates to `49`, server-side expression execution is likely present.

Further probing may show `require is not defined`, indicating partial sandboxing but not full isolation.

---

## 4. Command Execution Path

In this machine flow, payload pivots through constructor and process object to invoke child process execution.

Validation command goal:
- `whoami`

Observed result:
- command output returns `root`, indicating high-impact execution context.

Follow-up artifact checks:

```bash
ls /root
cat /root/root.txt
```

---

## 5. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn -p- 10.10.11.XXX
PORT   STATE SERVICE VERSION
22/tcp open  ssh
80/tcp open  http    Node.js (Express)

analyst@kali:~$ curl -I http://10.10.11.XXX
HTTP/1.1 200 OK
X-Powered-By: Express

Injected payload:
{{7*7}}
Response:
49

Injected payload (encoded in request parameter):
... constructor/process-based template expression ...

Response snippet:
root

Follow-up command evidence:
ls /root
root.txt
```

---

## 6. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "bike_node_handlebars_ssti_to_root_context_exec",
	"input_signals": [
		"Node.js Express service exposed on HTTP",
		"Template expression {{7*7}} evaluated server-side",
		"Sandbox error references require not defined",
		"Constructor/process-based payload returns whoami=root"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Application Fingerprinting",
			"confidence": 0.92,
			"evidence": "headers and behavior indicate Express/Handlebars stack"
		},
		{
			"step": 2,
			"tactic": "execution",
			"technique": "Server-Side Template Injection",
			"confidence": 0.95,
			"evidence": "arithmetic template payload evaluated by server"
		},
		{
			"step": 3,
			"tactic": "privilege_escalation",
			"technique": "Command and Scripting Interpreter",
			"confidence": 0.9,
			"evidence": "process-based payload executed whoami with root output"
		}
	],
	"hypotheses": [
		"Additional template fields may be injectable without encoding",
		"Other routes may allow persistent template payload storage",
		"Root execution context suggests unsafe service runtime privileges"
	],
	"uncertainties": [
		"Unknown whether containerization limits host-level impact",
		"No verification yet of outbound network restrictions from process",
		"Audit coverage for template rendering errors is unknown"
	],
	"tool_calls": [
		{"name": "ssti_sink_mapper", "priority": "high"},
		{"name": "node_runtime_privilege_auditor", "priority": "high"},
		{"name": "template_payload_sanitization_tester", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Disable dynamic template evaluation for user-controlled input",
			"Drop service privileges from root to unprivileged account",
			"Patch vulnerable rendering path and redeploy"
		],
		"hardening": [
			"Use strict template allowlists and escaping policies",
			"Sandbox rendering engine with minimized global object access",
			"Apply process-level seccomp/AppArmor/container restrictions"
		],
		"monitoring": [
			"Alert on template syntax tokens in user inputs",
			"Track process spawn events from web worker context",
			"Monitor access attempts to root-owned filesystem paths"
		]
	}
}
```