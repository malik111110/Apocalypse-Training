# macOS Enumeration Playbook

> macOS host enumeration for authorized security assessments.
> Focus: local privilege escalation paths, persistence mechanisms, credential artifacts, and enterprise management misconfigurations.

---

## 1. System and User Context

```bash
sw_vers
uname -a
id
whoami
hostname
date
```

Quick goals:
- Identify macOS version and build for known local privilege escalation exposure
- Confirm current privileges and group membership (`admin`, `staff`, etc.)
- Establish host role and naming pattern

---

## 2. Local Users, Groups, and Admin Rights

```bash
# Local users
dscl . list /Users

# Local groups and membership
dscl . list /Groups
dseditgroup -o checkmember -m "$USER" admin

# Full user attributes
dscl . -read /Users/$USER

# Recent logins
last | head -40
```

Red flags:
- Unexpected users in `admin` group
- Service-style users with interactive login shells
- Recently added local admin users without change records

---

## 3. Process, Launch Agents, and Persistence

```bash
ps aux | head -120
launchctl list
ls -la /Library/LaunchAgents
ls -la /Library/LaunchDaemons
ls -la ~/Library/LaunchAgents
```

Look for:
- Unsigned or unusual binaries in LaunchAgents/LaunchDaemons
- Persistence entries executing from user-writable paths
- Unknown processes with `osascript`, `curl`, or shell one-liners

---

## 4. Security Controls and System Integrity

```bash
# SIP status
csrutil status

# Gatekeeper status
spctl --status

# FileVault status
fdesetup status

# Firewall state
defaults read /Library/Preferences/com.apple.alf globalstate
```

Interpretation:
- SIP disabled on managed fleet can widen local exploit blast radius
- Gatekeeper disabled increases untrusted app execution risk
- FileVault disabled increases data exposure after theft

---

## 5. Network and Remote Access Surface

```bash
ifconfig
netstat -anv | head -120
lsof -i -P -n | head -120

# Check remote access services
systemsetup -getremotelogin
systemsetup -getremoteappleevents
```

Findings to capture:
- Listening services exposed on non-standard ports
- SSH/ARD enabled where policy forbids remote admin
- Unusual outbound C2-like periodic connections

---

## 6. Credential and Secret Exposure Checks

```bash
# Shell histories
ls -la ~/.zsh_history ~/.bash_history 2>/dev/null

# SSH material
ls -la ~/.ssh

# Common secret patterns in config files
grep -RInE 'password|token|secret|apikey|PRIVATE KEY' ~/Library /etc /Users 2>/dev/null | head -200
```

High-value artifacts:
- Cloud CLI credentials (`aws`, `gcloud`, `azure`)
- API keys in developer tool configs
- Private keys with weak file permissions

---

## 7. Tool-Call Strategy (For Model-Oriented Workflows)

Recommended tool calls:
- `macos_persistence_audit`: Enumerate launchd artifacts and score suspicious persistence
- `macos_control_posture`: Assess SIP, Gatekeeper, FileVault, firewall hardening status
- `credential_artifact_scan`: Collect exposed keys/tokens with confidence scoring
- `macos_network_profile`: Map listening services and suspicious remote endpoints

Decision sequence:
1. Establish user privilege and admin membership
2. Enumerate launchd persistence vectors
3. Validate host hardening controls
4. Identify secret exposure and remote-access risk
5. Prioritize mitigations and containment

---

## 8. Detection and Mitigation Guidance

Detection ideas:
- Alert on unauthorized writes in `/Library/LaunchDaemons` and `~/Library/LaunchAgents`
- Monitor repeated `launchctl` modifications by non-admin processes
- Flag suspicious AppleScript and shell chains from GUI apps

Mitigation actions:
- Enforce MDM baseline for SIP/Gatekeeper/FileVault/firewall
- Restrict local admin rights and review group changes
- Rotate exposed developer credentials and revoke stale tokens
- Baseline and sign approved persistence-related binaries

