#!/usr/bin/env python3
"""
======================================
  CyberScan - Python Port Scanner
  Phase 1 Cybersecurity Portfolio Project
======================================

WHAT THIS DOES:
  Scans a target host for open TCP ports by attempting
  socket connections. Mimics the core behavior of nmap.

HOW IT WORKS:
  1. Resolves the hostname to an IP address
  2. Iterates over a range of ports
  3. Tries to open a TCP connection to each port
  4. If the connection succeeds → port is OPEN
  5. If it fails/times out → port is CLOSED or FILTERED
  6. Attempts to grab the service banner (e.g. "SSH-2.0-OpenSSH")

CONCEPTS YOU'RE LEARNING:
  - TCP/IP fundamentals (how connections work)
  - Sockets (the building block of all networking)
  - Threading (scanning multiple ports simultaneously)
  - Service fingerprinting (identifying what runs on a port)
"""

import socket
import threading
import sys
import time
from datetime import datetime
from queue import Queue

# ─────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────
TIMEOUT = 1.0          # Seconds to wait for a connection (lower = faster but less accurate)
MAX_THREADS = 100      # How many ports to scan simultaneously
BANNER_TIMEOUT = 2.0   # Seconds to wait for a service banner

# Common ports and their service names (your own mini /etc/services)
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


# ─────────────────────────────────────────
#  CORE SCANNING FUNCTIONS
# ─────────────────────────────────────────

def resolve_host(target: str) -> str:
    """
    Converts a hostname like 'google.com' into an IP address like '142.250.80.46'.
    Uses DNS (Domain Name System) lookup — the internet's phone book.
    """
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve hostname: {target}")
        sys.exit(1)


def grab_banner(ip: str, port: int) -> str:
    """
    After connecting to an open port, some services immediately send
    a 'banner' identifying themselves (e.g., "220 FTP server ready").
    This function tries to read that banner.
    
    WHY THIS MATTERS: Banner grabbing is used in real pentests to
    identify software versions, which can then be checked for CVEs.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((ip, port))
            # Some services need a nudge before they send their banner
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            # Return just the first line (the important part)
            return banner.split("\n")[0][:80]
    except Exception:
        return ""


def scan_port(ip: str, port: int) -> dict:
    """
    The heart of the scanner. Attempts a TCP connection to a single port.
    
    TCP 3-Way Handshake (what happens under the hood):
      1. We send SYN  → "Can we connect?"
      2. Server sends SYN-ACK → "Yes, connecting!"  (port is OPEN)
         OR
         Server sends RST → "No."  (port is CLOSED)
         OR
         No response at all  (port is FILTERED by a firewall)
      3. We send ACK → "Great, connected!"
      
    socket.connect_ex() returns 0 on success (port open), non-zero on failure.
    """
    result = {
        "port": port,
        "state": "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner": ""
    }
    
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            # connect_ex returns error code (0 = success = port open)
            error_code = s.connect_ex((ip, port))
            
            if error_code == 0:
                result["state"] = "open"
                result["banner"] = grab_banner(ip, port)
    except socket.error:
        pass
    
    return result


# ─────────────────────────────────────────
#  THREADING ENGINE
#  (Scans many ports at once instead of one-by-one)
# ─────────────────────────────────────────

open_ports = []
lock = threading.Lock()

def worker(ip: str, port_queue: Queue):
    """
    Each thread runs this function. It grabs ports from the queue
    and scans them until the queue is empty.
    
    WHY THREADING: Scanning ports one-by-one with a 1s timeout means
    scanning 1000 ports takes 1000 seconds. With 100 threads, it takes ~10s.
    """
    while not port_queue.empty():
        port = port_queue.get()
        result = scan_port(ip, port)
        
        if result["state"] == "open":
            with lock:  # Prevent threads from printing at the same time
                open_ports.append(result)
                service = result["service"]
                banner = f" → {result['banner']}" if result["banner"] else ""
                print(f"  [OPEN]  Port {port:5d}  {service:<15}{banner}")
        
        port_queue.task_done()


# ─────────────────────────────────────────
#  MAIN SCANNER
# ─────────────────────────────────────────

def run_scan(target: str, start_port: int = 1, end_port: int = 1024):
    """
    Orchestrates the full scan:
    1. Resolve hostname → IP
    2. Fill a queue with port numbers to scan
    3. Spawn worker threads
    4. Wait for all threads to finish
    5. Print the summary report
    """
    print("\n" + "═" * 55)
    print("  🔍  CyberScan - Python Port Scanner")
    print("═" * 55)
    
    # Step 1: Resolve the target
    ip = resolve_host(target)
    print(f"  Target   : {target}")
    print(f"  IP       : {ip}")
    print(f"  Ports    : {start_port} - {end_port}")
    print(f"  Threads  : {MAX_THREADS}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 55)
    print()
    
    start_time = time.time()
    
    # Step 2: Load all ports into the queue
    port_queue = Queue()
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    
    # Step 3: Spawn threads
    threads = []
    thread_count = min(MAX_THREADS, end_port - start_port + 1)
    
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(ip, port_queue), daemon=True)
        threads.append(t)
        t.start()
    
    # Step 4: Wait for completion
    port_queue.join()
    
    elapsed = time.time() - start_time
    
    # Step 5: Print summary
    print()
    print("═" * 55)
    print(f"  SCAN COMPLETE in {elapsed:.2f} seconds")
    print(f"  {len(open_ports)} open port(s) found")
    print("═" * 55)
    
    if open_ports:
        print("\n  OPEN PORTS SUMMARY:")
        print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<15} {'BANNER'}")
        print("  " + "─" * 50)
        for r in sorted(open_ports, key=lambda x: x["port"]):
            banner = r["banner"][:35] + "..." if len(r["banner"]) > 35 else r["banner"]
            print(f"  {r['port']:<8} {'OPEN':<10} {r['service']:<15} {banner}")
    
    print()
    return open_ports


# ─────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────

if __name__ == "__main__":
    # Example usage - scan your own machine (always legal!)
    # Change these values to experiment
    
    TARGET = "127.0.0.1"   # localhost - safe to scan anytime
    START_PORT = 1
    END_PORT = 1024
    
    # You can also pass arguments from command line:
    # python port_scanner.py scanme.nmap.org 1 500
    if len(sys.argv) >= 2:
        TARGET = sys.argv[1]
    if len(sys.argv) >= 3:
        START_PORT = int(sys.argv[2])
    if len(sys.argv) >= 4:
        END_PORT = int(sys.argv[3])
    
    # ⚠️  LEGAL NOTICE:
    # Only scan systems you OWN or have EXPLICIT written permission to scan.
    # Scanning without permission is illegal in most countries.
    # Safe targets: 127.0.0.1 (your machine), scanme.nmap.org (nmap's test server)
    
    results = run_scan(TARGET, START_PORT, END_PORT)
