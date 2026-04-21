# Execution Enumeration Playbook (ATT&CK TA0002, Dataset-Ready)

> Purpose: produce high-quality execution-technique traces for model training and analyst runbooks.
> Scope: authorized lab, purple-team, and sanctioned red-team simulations only.

Execution is the adversary tactic focused on running adversary-controlled code on local or remote systems.

- ATT&CK Tactic ID: TA0002
- Created: 17 October 2018
- Last Modified: 25 April 2025

---

## 0. Safety, Logging, and Reproducibility

### 0.1 Engagement Guardrails

1. Use only approved target systems.
2. Do not run destructive payloads.
3. Prefer benign command markers in simulation.
4. Capture command, output, timestamp, and operator note for every step.

### 0.2 Evidence Wrapper

```bash
mkdir -p evidence

run_exec() {
  local technique="$1"
  local label="$2"
  shift 2
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "[$ts] [$technique] $label" | tee -a evidence/execution.log
  "$@" 2>&1 | tee "evidence/${ts}_${technique}_${label}.txt"
}

# Example
run_exec "T1059.004" "unix_shell_whoami" sh -lc 'whoami && id'
```

### 0.3 Training Record Minimum

```json
{
  "technique": "T1059.004",
  "technique_name": "Unix Shell",
  "scenario": "Operator executes shell discovery commands on Linux endpoint",
  "command": "sh -lc 'whoami && id'",
  "tool_result": {
    "status": "success",
    "highlights": ["user=www-data", "groups=www-data"]
  },
  "analyst_interpretation": "Shell execution succeeded under low-priv service account",
  "confidence": 0.95,
  "mitigation_hint": "Constrain shell access and enforce least privilege"
}
```

---

## 1. Cloud and Container Execution Paths

## T1651 Cloud Administration Command

Scenario:
- Adversary abuses cloud management channels to run commands inside VMs.

Execution:

```bash
run_exec "T1651" "aws_ssm_send_command" aws ssm send-command --instance-ids i-0123456789abcdef0 --document-name AWS-RunShellScript --parameters commands='["echo ta0002_test","uname -a"]'
run_exec "T1651" "azure_runcommand" az vm run-command invoke -g rg-demo -n vm-demo --command-id RunShellScript --scripts "echo ta0002_test && hostname"
```

Example result:

```text
CommandId: 8f2b....
Status: Success
StdOut: ta0002_test
StdOut: Linux vm-demo 5.15...
```

## T1609 Container Administration Command

Scenario:
- Adversary issues commands through container administration services.

Execution:

```bash
run_exec "T1609" "docker_exec" docker exec app-container /bin/sh -c 'echo ta0002_container && id'
run_exec "T1609" "kubelet_exec" kubectl exec -n prod deploy/web -- sh -c 'echo ta0002_container && whoami'
```

Example result:

```text
ta0002_container
uid=0(root) gid=0(root)
```

## T1610 Deploy Container

Scenario:
- Adversary deploys a container to execute code and potentially bypass controls.

Execution:

```bash
run_exec "T1610" "kubectl_run" kubectl run ta0002-demo --image=alpine --restart=Never -- sh -c 'echo ta0002_deploy && sleep 30'
run_exec "T1610" "kubectl_get_pod" kubectl get pod ta0002-demo -o wide
```

Example result:

```text
pod/ta0002-demo created
NAME         READY   STATUS      NODE
 ta0002-demo 1/1     Running     worker-2
```

## T1675 ESXi Administration Command

Scenario:
- Adversary uses ESXi administrative channels to execute guest actions.

Execution:

```bash
run_exec "T1675" "govc_guest_run" govc guest.run -vm vm-win10 -l 'administrator:***' cmd /c "echo ta0002_esxi"
```

Example result:

```text
Program exited with code 0
Output: ta0002_esxi
```

## T1648 Serverless Execution

Scenario:
- Adversary triggers serverless functions to execute code in cloud context.

Execution:

```bash
run_exec "T1648" "aws_lambda_invoke" aws lambda invoke --function-name ta0002-demo --payload '{"action":"healthcheck"}' evidence/lambda_out.json
run_exec "T1648" "gcp_function_call" gcloud functions call ta0002-demo --data '{"action":"healthcheck"}'
```

Example result:

```text
StatusCode: 200
Payload: {"ok":true,"marker":"ta0002_serverless"}
```

---

## 2. T1059 Command and Scripting Interpreter

## T1059 Command and Scripting Interpreter (Parent)

Scenario:
- Adversary runs commands/scripts via native interpreters.

Execution:

```bash
run_exec "T1059" "generic_interpreter" sh -lc 'echo ta0002_t1059 && date -u'
```

Example result:

```text
ta0002_t1059
2026-04-21T...
```

## T1059.001 PowerShell

```bash
run_exec "T1059.001" "powershell_inline" powershell -NoProfile -Command "Write-Output 'ta0002_ps'; Get-Process | Select-Object -First 3"
```

Example result:

```text
ta0002_ps
Handles NPM(K) PM(K) WS(K) ProcessName
```

## T1059.002 AppleScript

```bash
run_exec "T1059.002" "osascript_echo" osascript -e 'display dialog "ta0002_applescript" buttons {"OK"} default button 1'
```

Example result:

```text
button returned:OK
```

## T1059.003 Windows Command Shell

```bash
run_exec "T1059.003" "cmd_exec" cmd /c "echo ta0002_cmd && whoami"
```

Example result:

```text
ta0002_cmd
corp\\user01
```

## T1059.004 Unix Shell

```bash
run_exec "T1059.004" "unix_shell" sh -lc 'echo ta0002_unix && uname -a && id'
```

Example result:

```text
ta0002_unix
Linux host01 5.15...
uid=1001(user01) gid=1001(user01)
```

## T1059.005 Visual Basic

```bash
run_exec "T1059.005" "vbscript_cscript" cscript //nologo demo.vbs
```

Example result:

```text
ta0002_vb
```

## T1059.006 Python

```bash
run_exec "T1059.006" "python_inline" python3 -c "import os,platform; print('ta0002_python'); print(platform.platform()); print(os.getuid() if hasattr(os,'getuid') else 'n/a')"
```

Example result:

```text
ta0002_python
Linux-5.15...
1001
```

## T1059.007 JavaScript

```bash
run_exec "T1059.007" "node_inline" node -e "console.log('ta0002_js'); console.log(process.version)"
```

Example result:

```text
ta0002_js
v20.x.x
```

## T1059.008 Network Device CLI

```bash
run_exec "T1059.008" "network_cli_show" ssh admin@router01 'show version; show running-config | include hostname'
```

Example result:

```text
Cisco IOS XE Software, Version 17.x
hostname branch-router-01
```

## T1059.009 Cloud API

```bash
run_exec "T1059.009" "aws_cli_api" aws ec2 describe-instances --max-items 5
run_exec "T1059.009" "az_cli_api" az vm list -d -o table
```

Example result:

```text
Reservations: [...]
Name     ResourceGroup  PowerState
```

## T1059.010 AutoHotKey & AutoIT

```bash
run_exec "T1059.010" "autohotkey_script" AutoHotkey.exe .\\demo.ahk
run_exec "T1059.010" "autoit_script" autoit3.exe .\\demo.au3
```

Example result:

```text
Script executed: ta0002_automation
```

## T1059.011 Lua

```bash
run_exec "T1059.011" "lua_inline" lua -e "print('ta0002_lua'); os.execute('whoami')"
```

Example result:

```text
ta0002_lua
user01
```

## T1059.012 Hypervisor CLI

```bash
run_exec "T1059.012" "esxcli_list_vms" ssh root@esxi01 'esxcli vm process list'
```

Example result:

```text
Display Name: vm-app-01
World ID: 12345
```

## T1059.013 Container CLI/API

```bash
run_exec "T1059.013" "docker_api_exec" curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/app-container/exec
run_exec "T1059.013" "kubectl_api_exec" kubectl exec -n dev pod/api-7f9 -- sh -c 'echo ta0002_container_api'
```

Example result:

```text
ExecId: 4b1f...
ta0002_container_api
```

---

## 3. Exploitation, IPC, Native API, and Pipeline Abuse

## T1203 Exploitation for Client Execution

Scenario:
- Client application vulnerability is triggered for code execution.

Execution simulation:

```bash
run_exec "T1203" "client_exploit_sim" python3 simulate_client_exploit.py --target doc_viewer --mode benign
```

Example result:

```text
Exploit path reached
Marker process spawned: ta0002_client_exec_test
```

## T1674 Input Injection

```bash
run_exec "T1674" "keystroke_injection_sim" python3 simulate_input_injection.py --sequence "WIN+R;cmd;/c echo ta0002_input"
```

Example result:

```text
Injected 14 keystroke events
Observed process: cmd.exe
```

## T1559 Inter-Process Communication (Parent)

```bash
run_exec "T1559" "ipc_baseline" python3 ipc_demo.py --mode message --marker ta0002_ipc
```

Example result:

```text
IPC channel established
Command token received: ta0002_ipc
```

## T1559.001 Component Object Model

```bash
run_exec "T1559.001" "com_object_invoke" powershell -NoProfile -Command "$w=New-Object -ComObject WScript.Shell; $w.Run('cmd /c echo ta0002_com')"
```

Example result:

```text
Process created via COM automation: cmd.exe
```

## T1559.002 Dynamic Data Exchange

```bash
run_exec "T1559.002" "dde_sim" python3 simulate_dde_trigger.py --doc sample_dde.doc --marker ta0002_dde
```

Example result:

```text
DDE field evaluated
Command launched: cmd.exe /c echo ta0002_dde
```

## T1559.003 XPC Services

```bash
run_exec "T1559.003" "xpc_message" python3 xpc_demo.py --service com.example.helper --payload ta0002_xpc
```

Example result:

```text
XPC reply: accepted
Action marker: ta0002_xpc
```

## T1106 Native API

```bash
run_exec "T1106" "native_api_sim" python3 native_api_demo.py --api CreateProcessW --marker ta0002_native
```

Example result:

```text
API call success: CreateProcessW
Child PID: 4421
```

## T1677 Poisoned Pipeline Execution

```bash
run_exec "T1677" "pipeline_poison_sim" python3 simulate_pipeline_poison.py --repo demo-ci --stage build --marker ta0002_pipeline
```

Example result:

```text
Injected command observed in build step
Runner executed marker: ta0002_pipeline
```

---

## 4. T1053 Scheduled Task or Job

## T1053 Scheduled Task or Job (Parent)

```bash
run_exec "T1053" "generic_schedule" python3 schedule_demo.py --once --command "echo ta0002_schedule"
```

Example result:

```text
Job scheduled
Job ran successfully
```

## T1053.002 At

```bash
run_exec "T1053.002" "at_job" at now + 1 minute <<'EOF'
sh -c 'echo ta0002_at >> /tmp/ta0002_at.log'
EOF
```

Example result:

```text
job 17 at Tue Apr 21 12:01:00 2026
```

## T1053.003 Cron

```bash
run_exec "T1053.003" "cron_add" bash -lc '(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/sh -c \"echo ta0002_cron >> /tmp/ta0002_cron.log\"") | crontab -'
```

Example result:

```text
crontab installed
```

## T1053.005 Scheduled Task

```bash
run_exec "T1053.005" "schtasks_create" schtasks /create /tn TA0002Demo /sc minute /mo 5 /tr "cmd /c echo ta0002_schtasks"
```

Example result:

```text
SUCCESS: The scheduled task "TA0002Demo" has successfully been created.
```

## T1053.006 Systemd Timers

```bash
run_exec "T1053.006" "systemd_timer_setup" bash -lc 'systemctl --user daemon-reload && systemctl --user list-timers | head'
```

Example result:

```text
NEXT                         LEFT  LAST PASSED UNIT
```

## T1053.007 Container Orchestration Job

```bash
run_exec "T1053.007" "k8s_cronjob" kubectl create cronjob ta0002-job --image=alpine --schedule="*/10 * * * *" -- sh -c 'echo ta0002_k8s_job'
```

Example result:

```text
cronjob.batch/ta0002-job created
```

---

## 5. Modules, Deployment Tools, Services

## T1129 Shared Modules

```bash
run_exec "T1129" "shared_module_load" python3 shared_module_demo.py --module ./libdemo.so --marker ta0002_shared
```

Example result:

```text
Loaded module: libdemo.so
Export executed: marker()
```

## T1072 Software Deployment Tools

```bash
run_exec "T1072" "sccm_like_push_sim" python3 simulate_software_deploy.py --platform sccm --package ta0002-demo --command "echo ta0002_deploy"
```

Example result:

```text
Deployment task accepted
Target endpoints reached: 24/24
```

## T1569 System Services (Parent)

```bash
run_exec "T1569" "service_control_overview" python3 service_exec_demo.py --marker ta0002_service
```

Example result:

```text
Service execution path invoked
```

## T1569.001 Launchctl

```bash
run_exec "T1569.001" "launchctl_submit" launchctl submit -l com.example.ta0002 -- /bin/sh -c 'echo ta0002_launchctl'
```

Example result:

```text
Submitted job: com.example.ta0002
```

## T1569.002 Service Execution

```bash
run_exec "T1569.002" "sc_create" sc create TA0002Demo binPath= "cmd /c echo ta0002_service_exec"
run_exec "T1569.002" "sc_start" sc start TA0002Demo
```

Example result:

```text
[SC] CreateService SUCCESS
STATE: RUNNING
```

## T1569.003 Systemctl

```bash
run_exec "T1569.003" "systemctl_start" sudo systemctl start ta0002-demo.service
run_exec "T1569.003" "systemctl_status" systemctl status ta0002-demo.service --no-pager
```

Example result:

```text
Active: active (running)
```

---

## 6. T1204 User Execution

## T1204 User Execution (Parent)

Scenario:
- Execution relies on user action from social engineering chain.

```bash
run_exec "T1204" "user_action_sim" python3 simulate_user_execution.py --mode benign --marker ta0002_user_exec
```

Example result:

```text
User action captured: open_file
Follow-on process observed
```

## T1204.001 Malicious Link

```bash
run_exec "T1204.001" "link_click_sim" python3 simulate_link_click.py --url https://demo.example/link --marker ta0002_link
```

Example result:

```text
HTTP GET /link
Child process event correlated within 5s
```

## T1204.002 Malicious File

```bash
run_exec "T1204.002" "file_open_sim" python3 simulate_file_open.py --file invoice_demo.docm --marker ta0002_file
```

Example result:

```text
Document opened
Macro path executed in simulation mode
```

## T1204.003 Malicious Image

```bash
run_exec "T1204.003" "image_deploy_sim" python3 simulate_image_run.py --image demo/backdoored:test --marker ta0002_image
```

Example result:

```text
Image pulled
Container started
Marker emitted: ta0002_image
```

## T1204.004 Malicious Copy and Paste

```bash
run_exec "T1204.004" "clickfix_sim" python3 simulate_copy_paste.py --payload "echo ta0002_copypaste" --interpreter powershell
```

Example result:

```text
Clipboard content executed by user action
Command marker observed
```

## T1204.005 Malicious Library

```bash
run_exec "T1204.005" "library_install_sim" python3 simulate_library_install.py --registry demo-pypi --package ta0002-lib --marker ta0002_library
```

Example result:

```text
Package installed in test venv
Post-install hook executed marker
```

---

## 7. T1047 Windows Management Instrumentation

## T1047 Windows Management Instrumentation

Scenario:
- Adversary uses WMI execution paths for local or remote command launch.

Execution:

```bash
run_exec "T1047" "wmic_process_call" wmic process call create "cmd /c echo ta0002_wmi"
run_exec "T1047" "powershell_wmi" powershell -NoProfile -Command "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd /c echo ta0002_wmi_ps'"
```

Example result:

```text
Executing (Win32_Process)->Create()
Method execution successful.
ReturnValue = 0
```

---

## 8. Practical Correlation Fields for Training

For each execution event, collect:

1. Parent process.
2. Child process.
3. Command line.
4. Integrity or privilege context.
5. User and host identity.
6. Network side effects if present.
7. Linked ATT&CK ID.

Suggested normalized object:

```json
{
  "technique": "T1047",
  "host": "wkst-22",
  "parent_process": "wmic.exe",
  "child_process": "cmd.exe",
  "command_line": "cmd /c echo ta0002_wmi",
  "privilege": "medium",
  "result": "success",
  "confidence": 0.93
}
```

---

## 9. Coverage Checklist (Requested IDs)

Included IDs:

- Cloud and platform execution: T1651, T1609, T1610, T1675, T1648.
- Interpreter family: T1059, T1059.001, T1059.002, T1059.003, T1059.004, T1059.005, T1059.006, T1059.007, T1059.008, T1059.009, T1059.010, T1059.011, T1059.012, T1059.013.
- Execution enablers: T1203, T1674, T1559, T1559.001, T1559.002, T1559.003, T1106, T1677.
- Scheduled execution: T1053, T1053.002, T1053.003, T1053.005, T1053.006, T1053.007.
- Service and module execution: T1129, T1072, T1569, T1569.001, T1569.002, T1569.003.
- User-driven execution: T1204, T1204.001, T1204.002, T1204.003, T1204.004, T1204.005.
- Windows management execution: T1047.

This playbook is intentionally execution-focused and dataset-oriented so your model can learn technique behavior from realistic scenario, command, and output triples.
