# 🔍 CyberScan — Python Port Scanner

> **Phase 1 of my Cybersecurity Portfolio** | Network Reconnaissance Tool

A multithreaded TCP port scanner built from scratch in Python. Performs service fingerprinting and banner grabbing to identify what software is running on open ports — the same core technique used by professional penetration testers.

---

## 📸 Sample Output

```
═══════════════════════════════════════════════════════
  🔍  CyberScan - Python Port Scanner
═══════════════════════════════════════════════════════
  Target   : scanme.nmap.org
  IP       : 45.33.32.156
  Ports    : 1 - 1024
  Threads  : 100
  Started  : 2026-02-17 14:11:38
═══════════════════════════════════════════════════════
  [OPEN]  Port    22  SSH      → SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  [OPEN]  Port    80  HTTP     → HTTP/1.1 200 OK
═══════════════════════════════════════════════════════
  SCAN COMPLETE in 11.17 seconds
  2 open port(s) found
═══════════════════════════════════════════════════════
```

---

## 🧠 What I Learned Building This

### TCP/IP & The 3-Way Handshake
Every port scan works by attempting a TCP connection. Under the hood:
1. Scanner sends **SYN** — "Can we connect?"
2. Open port replies **SYN-ACK** — "Yes!"
3. Closed port replies **RST** — "No."
4. Firewalled port gives **no response** — silently dropped

Understanding this made networking click for me in a way reading about it never did.

### Sockets
Python's `socket` library is the foundation of all network programming. `socket.connect_ex()` returns `0` on success (port open) and a non-zero error code on failure. Everything else in the scanner builds on this one call.

### Threading & Queues
Scanning ports one-by-one with a 1-second timeout means 1024 ports = 17 minutes. Using 100 threads with a `Queue` brings that down to ~11 seconds. This was my first real-world use of multithreading and showed me why concurrency matters in security tooling.

### Banner Grabbing & Service Fingerprinting
After connecting to an open port, many services send a banner identifying themselves. Port 902 on my machine revealed `220 VMware Authentication Daemon Version 1.10` — exposing the exact software and version. A real attacker would search that string against CVE databases to find known vulnerabilities.

---

## 🚀 Usage

```bash
# Basic usage
python port_scanner.py <target> <start_port> <end_port>

# Scan your own machine (always legal)
python port_scanner.py 127.0.0.1 1 1024

# Scan nmap's official test server (legal — exists for practice)
python port_scanner.py scanme.nmap.org 1 1024

# Scan a specific range
python port_scanner.py 192.168.1.1 1 500
```

**Requirements:** Python 3.x — no external libraries needed (uses only the standard library)

---

## 🔬 Real Scan Results & Analysis

### My Machine — 127.0.0.1

| Port | Service | Analysis |
|------|---------|----------|
| 135 | Microsoft RPC | Standard Windows service for inter-process communication |
| 139 | NetBIOS | Legacy Windows file sharing — present on network interface |
| 445 | SMB | Windows file sharing. Famously exploited by WannaCry (EternalBlue/MS17-010) |
| 623 | IPMI | Management interface — potentially sensitive |
| 902 | VMware | `VMware Authentication Daemon v1.10` — identified via banner grab |
| 912 | VMware | `VMware Authentication Daemon v1.0` — older protocol version also running |

### scanme.nmap.org — 45.33.32.156

| Port | Service | Analysis |
|------|---------|----------|
| 22 | SSH | `OpenSSH 6.6.1p1 Ubuntu` — version exposed via banner. This version has known CVEs. |
| 80 | HTTP | Web server running. Next step: web vulnerability scan |

### Home Router — 192.168.1.1

| Port | Service | Analysis |
|------|---------|----------|
| 53 | DNS | Router acting as local DNS resolver for the network |
| 443 | HTTPS | Admin panel — HTTP (port 80) is disabled, forcing encrypted access. Good security posture. |

**Key finding:** The SSH banner on `scanme.nmap.org` revealed `OpenSSH 6.6.1p1` — searching `OpenSSH 6.6.1 CVE` returns multiple vulnerabilities including CVE-2016-0777 (information leak) and CVE-2016-0778 (buffer overflow). This is the exact workflow used in real penetration tests: scan → fingerprint → research CVEs → exploit.

---

## ⚙️ How It Works

```
Target hostname
      │
      ▼
DNS Resolution (socket.gethostbyname)
      │
      ▼
Port Queue (Queue object filled with port numbers)
      │
      ▼
Thread Pool (100 worker threads)
   │      │      │
   ▼      ▼      ▼
scan_port() × 100 simultaneous
   │
   ├── socket.connect_ex() → 0 = OPEN
   │
   └── grab_banner() → read service response
      │
      ▼
Results printed + summary report
```

---

## 📚 Key Concepts Demonstrated

- **Network programming** — TCP sockets from scratch
- **Multithreading** — concurrent port scanning with thread-safe queues
- **Banner grabbing** — service version identification
- **Reconnaissance methodology** — the first phase of any penetration test
- **CVE research workflow** — from version number to known vulnerability

---

## ⚠️ Legal Notice

Only scan systems you **own** or have **explicit written permission** to scan. Unauthorized port scanning is illegal in most countries. Safe targets for practice:
- `127.0.0.1` — your own machine
- `scanme.nmap.org` — nmap's official practice server
- Your own home lab VMs

---

## 🗺️ What's Next

This is **Phase 1** of my cybersecurity learning path. Coming up:

- [ ] **Cipher Cracker** — Caesar & Vigenère cipher brute-forcer (Phase 1)
- [ ] **Home Lab** — Kali Linux + Metasploitable2 in VMware (Phase 1)
- [ ] **Web App Pentesting** — DVWA SQL injection & XSS (Phase 2)
- [ ] **Packet Analyzer** — ARP spoofing detection with Scapy (Phase 2)
- [ ] **CTF Writeups** — TryHackMe / Hack The Box (Phase 3)

---

*Built as part of a self-directed cybersecurity learning path aimed at a career in penetration testing.*
