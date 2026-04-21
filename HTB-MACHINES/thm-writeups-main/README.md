# THM Writeups
Hey! Glad to have ya here!

This is a collection of writeups for CTF challenges and stuff by me (specifically the ones from TryHackMe). If these help you in any way, please consider dropping a star or something :)

## Index
- [Alfred](./alfred/)
- [Anthem by Chevalier](./anthem-chevalier/)
- [Blue](./blue/)
- [Boiler CTF](./boiler-ctf/)
- [Bounty Hacker](./bounty-hacker/)
- [Brooklyn Nine Nine](./brooklyn-nine-nine/)
- [Brute It](./brute-it/)
- [Cat Pictures 2](./cat-pictures-2/)
- [Chocolate Factory](./chocolate-factory/) 
- [Daily Bugle](./daily-bugle/)
- [dogcat](./dogcat/) 
- [Game Zone](./game-zone/)
- [HackPark](./hackpark/)
- [Ice](./ice/)
- [Ignite by DarkStar7471](./ignite-darkstar7471/)
- [Kenobi](./kenobi/)
- [Lazy Admin](./lazy-admin/)
- [Mr. Robot CTF](./mr-robot-ctf/)
- [Overpass](./overpass/)
- [Overpass 2](./overpass-2/)
- [Red](./redisl33t/) 
- [Relevant](./relevant/)
- [Reversing ELF](./reversing-elf) 
- [Skynet](./skynet/)
- [Startup by elbee](./startup-elbee/)
- [Steel Mountain](./steel-mountain/)
- [ToolsRUs](./toolsrus/)
- [Windows 10 Privilege Escalation room by tib3rius](./windows-10-privesc-tib3rius)
- [Wgel CTF](/wgel-ctf/)

---

## Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV <TARGET_IP>
[+] Enumerated exposed services and probable attack surface

analyst@kali:~$ gobuster dir -u http://<TARGET_IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Identified candidate paths/endpoints for validation

analyst@kali:~$ searchsploit <service_or_version>
[+] Mapped service/version to exploit hypotheses for lab validation
```

## Analyst Reasoning Chain (Dataset-Style)

```json
{
  "scenario": "thm-writeups-index_recon_to_access_chain",
  "input_signals": [
    "Service exposure identified during enumeration",
    "At least one actionable endpoint or protocol weakness observed",
    "Credential, version, or configuration clues support exploitation hypotheses"
  ],
  "attack_chain": [
    {
      "step": 1,
      "tactic": "reconnaissance",
      "technique": "Active Service and Surface Discovery",
      "confidence": 0.93,
      "evidence": "Port and service inventory built from scan output"
    },
    {
      "step": 2,
      "tactic": "initial_access",
      "technique": "Valid Accounts / Misconfiguration / Known Vulnerability",
      "confidence": 0.86,
      "evidence": "Room-specific access path established from discovered clues"
    },
    {
      "step": 3,
      "tactic": "privilege_escalation",
      "technique": "Local Misconfiguration or Credential Abuse",
      "confidence": 0.79,
      "evidence": "Escalation candidate identified and validated in lab context"
    }
  ],
  "hypotheses": [
    "Additional services on the same host may share weak configuration patterns",
    "Recovered credentials or hashes may be reused across management interfaces",
    "Legacy software components may expose further exploit paths"
  ],
  "uncertainties": [
    "Exact production relevance of lab misconfigurations",
    "Extent of network segmentation and monitoring controls",
    "Whether similar weaknesses exist in adjacent systems"
  ],
  "tool_calls": [
    {"name": "thm-writeups-index_surface_mapper", "priority": "high"},
    {"name": "thm-writeups-index_credential_validator", "priority": "high"},
    {"name": "thm-writeups-index_privesc_path_checker", "priority": "medium"}
  ],
  "mitigation": {
    "immediate": [
      "Patch or disable the exploited service/path",
      "Rotate exposed credentials and invalidate old sessions",
      "Restrict administrative interfaces to trusted network segments"
    ],
    "hardening": [
      "Apply least-privilege permissions on services and scheduled tasks",
      "Remove default credentials and enforce strong authentication",
      "Continuously scan for outdated components and exposed assets"
    ],
    "monitoring": [
      "Alert on anomalous scanning and endpoint enumeration patterns",
      "Detect suspicious authentication and lateral movement attempts",
      "Track privilege escalation indicators and abnormal process creation"
    ]
  }
}
```
