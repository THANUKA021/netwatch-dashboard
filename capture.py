"""
capture.py — Network Packet Capture Module
==========================================
This module handles the raw packet sniffing.

It tries to use Scapy first (most feature-rich), then falls back to
PyShark (Wireshark-based), and if neither is available it generates
DEMO data so you can still see the dashboard working without root access
or a special library installed.

Key concepts for beginners:
  - A "packet" is a small chunk of data sent over the network.
  - Every packet has a source IP (who sent it), destination IP (who receives it),
    and a protocol (the "language" used — TCP, UDP, DNS, HTTP, etc.).
  - Sniffing = listening to all packets passing through your network interface.
"""

import os
import time
import random
import logging
import threading
from datetime import datetime

# We'll try importing capture libraries in order of preference
CAPTURE_MODE = "demo"   # will be updated below

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
    CAPTURE_MODE = "scapy"
    logging.info("Scapy found — using Scapy for packet capture.")
except ImportError:
    try:
        import pyshark
        CAPTURE_MODE = "pyshark"
        logging.info("PyShark found — using PyShark for packet capture.")
    except ImportError:
        logging.warning(
            "Neither Scapy nor PyShark found. "
            "Running in DEMO mode with simulated traffic."
        )

from db import insert_packet

# A thread-safe buffer holding the last 1 000 captured packets (for quick access)
_packet_buffer = []
_buffer_lock   = threading.Lock()
BUFFER_SIZE    = 1000


def get_packet_buffer():
    """Return a copy of the in-memory packet buffer (thread-safe)."""
    with _buffer_lock:
        return list(_packet_buffer)


def _add_to_buffer(packet_dict):
    """Append a packet dict to the ring buffer, dropping oldest if full."""
    with _buffer_lock:
        _packet_buffer.append(packet_dict)
        if len(_packet_buffer) > BUFFER_SIZE:
            _packet_buffer.pop(0)


# ══════════════════════════════════════════════════════════════════════════════
# SCAPY CAPTURE
# ══════════════════════════════════════════════════════════════════════════════

def _scapy_process(pkt, db_path):
    """
    Called by Scapy for every captured packet.
    We extract fields we care about and save to DB + buffer.
    """
    # Only process packets that have an IP layer (ignore ARP, etc.)
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    size   = len(pkt)           # total packet length in bytes
    ts     = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # Determine the application-layer protocol
    proto = "OTHER"
    info  = ""

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        proto = "DNS"
        try:
            info = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        except Exception:
            info = ""
    elif pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if dport in (80, 8080) or sport in (80, 8080):
            proto = "HTTP"
        elif dport == 443 or sport == 443:
            proto = "HTTPS"
        elif dport == 22  or sport == 22:
            proto = "SSH"
        elif dport == 21  or sport == 21:
            proto = "FTP"
        else:
            proto = "TCP"
        info = f"{sport}→{dport}"
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto = "UDP"
        info = f"{sport}→{dport}"

    record = {
        "timestamp": ts,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "protocol":  proto,
        "size":      size,
        "info":      info,
    }

    insert_packet(db_path, record)
    _add_to_buffer(record)


def _run_scapy(db_path):
    """Start Scapy's continuous sniffer (requires root/sudo)."""
    logging.info("Scapy sniffer starting…")
    # store=False means Scapy won't keep packets in RAM (saves memory)
    sniff(
        prn=lambda pkt: _scapy_process(pkt, db_path),
        store=False,
        filter="ip",          # BPF filter: only IP packets
    )


# ══════════════════════════════════════════════════════════════════════════════
# PYSHARK CAPTURE
# ══════════════════════════════════════════════════════════════════════════════

def _run_pyshark(db_path):
    """Use PyShark (TShark/Wireshark backend) to capture packets."""
    import pyshark
    logging.info("PyShark sniffer starting…")

    cap = pyshark.LiveCapture(display_filter="ip")
    for pkt in cap.sniff_continuously():
        try:
            ts     = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            size   = int(pkt.length)

            proto = pkt.highest_layer
            info  = ""

            # Simplify protocol names
            if "DNS" in proto:
                proto = "DNS"
                try:
                    info = pkt.dns.qry_name
                except Exception:
                    pass
            elif proto in ("HTTP", "HTTP2"):
                proto = "HTTP"
            elif "TLS" in proto or proto == "SSL":
                proto = "HTTPS"
            elif proto not in ("TCP", "UDP"):
                proto = proto[:10]   # cap length for display

            record = {
                "timestamp": ts,
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "protocol":  proto,
                "size":      size,
                "info":      info,
            }
            insert_packet(db_path, record)
            _add_to_buffer(record)

        except AttributeError:
            continue   # packet missing expected layer — skip


# ══════════════════════════════════════════════════════════════════════════════
# DEMO MODE — simulated traffic
# ══════════════════════════════════════════════════════════════════════════════

# Simulated network participants
DEMO_DEVICES = [
    "192.168.1.1",   # router
    "192.168.1.10",  # laptop
    "192.168.1.11",  # desktop
    "192.168.1.20",  # phone
    "192.168.1.21",  # tablet
    "10.0.0.5",      # server
    "10.0.0.6",      # NAS
    "8.8.8.8",       # Google DNS
    "1.1.1.1",       # Cloudflare DNS
    "172.217.14.100",# Google
]

DEMO_PROTOCOLS = ["TCP", "UDP", "DNS", "HTTP", "HTTPS", "SSH", "FTP", "OTHER"]
DEMO_PROTO_WEIGHTS = [30, 20, 15, 12, 15, 3, 2, 3]  # probability weights

DEMO_SIZES = {
    "DNS":   (40,  200),
    "HTTP":  (200, 8000),
    "HTTPS": (200, 6000),
    "TCP":   (60,  1500),
    "UDP":   (60,  1200),
    "SSH":   (100, 400),
    "FTP":   (100, 2000),
    "OTHER": (40,  600),
}


def _run_demo(db_path):
    """
    Generate fake but realistic-looking network traffic.
    Useful when you can't run as root or don't have Scapy/PyShark.
    Also simulates one 'heavy' device to demonstrate anomaly detection.
    """
    logging.info("DEMO mode: generating simulated packets.")

    # One device will be the 'heavy' anomaly device
    heavy_device = "192.168.1.11"
    counter = 0

    while True:
        # Generate a burst of 5-15 packets every second
        burst = random.randint(5, 15)
        for _ in range(burst):
            proto = random.choices(DEMO_PROTOCOLS, weights=DEMO_PROTO_WEIGHTS, k=1)[0]
            lo, hi = DEMO_SIZES[proto]
            size   = random.randint(lo, hi)

            # Heavy device sends/receives 10× more traffic
            if random.random() < 0.25:
                src = heavy_device
                size *= random.randint(5, 12)
            else:
                src = random.choice(DEMO_DEVICES)

            dst = random.choice([d for d in DEMO_DEVICES if d != src])
            ts  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            record = {
                "timestamp": ts,
                "src_ip":    src,
                "dst_ip":    dst,
                "protocol":  proto,
                "size":      size,
                "info":      f"demo-{counter}",
            }
            insert_packet(db_path, record)
            _add_to_buffer(record)
            counter += 1

        time.sleep(1)   # wait 1 second between bursts


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def start_capture(db_path):
    """
    Choose the best available capture method and start it.
    Called in a background thread by app.py.
    """
    if CAPTURE_MODE == "scapy":
        _run_scapy(db_path)
    elif CAPTURE_MODE == "pyshark":
        _run_pyshark(db_path)
    else:
        _run_demo(db_path)
