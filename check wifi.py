#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suspicious Outbound Connection Detector - Enhanced 2026
- Phát hiện beaconing linh hoạt hơn
- Theo dõi volume & direction (out/in)
- Parent chain check (2 levels)
- Log rotation cơ bản
- Giữ nguyên file log: suspicious_sessions.log
"""

import psutil
import time
import socket
import ipaddress
from datetime import datetime
from collections import defaultdict, deque
import os

# ===== CONFIGURATION =====
CHECK_INTERVAL       = 1.2
MIN_DURATION         = 5           # giây
LOG_FILE             = "suspicious_sessions.log"
LOG_MAX_SIZE_MB      = 10

SAFE_PORTS = {21, 22, 53, 80, 123, 443, 853, 3478, 5228, 8080, 8443}
C2_COMMON_PORTS = {
    4444, 5555, 1337, 31337, 6666, 6667, 8000, 8089, 9001, 9002,
    10443, 44300, 4433, 7443, 9999, 12345, 444, 7777
}

SUSPICIOUS_PATH_KEYWORDS = [
    "appdata", "temp", "\\roaming\\", "\\local\\", "downloads",
    "\\public\\", "\\programdata\\", "\\users\\public\\"
]

FAKE_PROCESS_NAMES = [
    "svch0st", "expl0rer", "winlogin", "chrome_update", "rundll32x",
    "mshta", "regsvr", "wscript", "cscript", "powershellx"
]

# Whitelist process (name + path fragment)
SAFE_PROCESS_PATHS = {
    "chrome.exe":      ["\\google\\chrome\\", "\\chromium\\"],
    "msedge.exe":      ["\\microsoft\\edge\\"],
    "firefox.exe":     ["\\mozilla firefox\\"],
    "opera.exe":       ["\\opera\\"],
    "brave.exe":       ["\\brave\\"],
    "svchost.exe":     ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "services.exe":    ["\\windows\\system32\\"],
    "lsass.exe":       ["\\windows\\system32\\"],
    "winlogon.exe":    ["\\windows\\system32\\"],
    "explorer.exe":    ["\\windows\\"],
}

# Basic deny list (có thể mở rộng)
DENY_DEST_HOSTS = {
    "pastebin.com", "raw.githubusercontent.com", "controlc.com",
    "controlc.net", "0bin.net", "hastebin.com"
}

# Beacon tuning
MAX_BEACON_SAMPLES     = 14
STRONG_BEACON_MIN_SAMPLES = 7
BEACON_JITTER_PCT      = 0.50       # cho phép jitter lớn hơn
MIN_BEACON_INTERVAL    = 5
MAX_BEACON_INTERVAL    = 1200       # 20 phút

# Global state
active_sessions    = {}
beacon_stats       = defaultdict(lambda: deque(maxlen=MAX_BEACON_SAMPLES))
dns_cache          = {}
tracked_pids       = set()          # giảm scan cho process đã biết an toàn

print("Enhanced suspicious connection monitor started...")
print(f"Logging to: {os.path.abspath(LOG_FILE)}\n")

# ===== HELPER FUNCTIONS =====

def rotate_log_if_needed():
    if not os.path.exists(LOG_FILE):
        return
    size_mb = os.path.getsize(LOG_FILE) / (1024 * 1024)
    if size_mb > LOG_MAX_SIZE_MB:
        backup = f"{LOG_FILE}.{datetime.now():%Y%m%d_%H%M%S}.bak"
        try:
            os.rename(LOG_FILE, backup)
            print(f"Log rotated → {backup}")
        except:
            pass

def resolve_ip(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        dns_cache[ip] = host.lower()
    except:
        dns_cache[ip] = "Unknown"
    return dns_cache[ip]

def is_public_ip(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_global
    except:
        return False

def is_safe_process(name, path):
    name = name.lower()
    path = path.lower()
    if name not in SAFE_PROCESS_PATHS:
        return False
    return any(p in path for p in SAFE_PROCESS_PATHS[name])

def get_parent_chain(proc, levels=2):
    chain = []
    current = proc
    for _ in range(levels):
        try:
            parent = current.parent()
            if not parent:
                break
            chain.append(f"{parent.name()} ({parent.pid})")
            current = parent
        except:
            break
    return " → ".join(reversed(chain)) if chain else "Unknown"

def classify_flags(remote_port, remote_ip, host):
    flags = set()
    if remote_port in C2_COMMON_PORTS:
        flags.add("C2_COMMON_PORT")
    if remote_port > 40000:
        flags.add("HIGH_EPHEMERAL_PORT")
    if is_public_ip(remote_ip) and remote_port not in SAFE_PORTS:
        flags.add("PUBLIC_NONSTD_PORT")
    if host in DENY_DEST_HOSTS:
        flags.add("DENYLIST_HOST")
    return flags

def detect_beaconing(timestamps):
    if len(timestamps) < 4:
        return False, None, None, "weak"

    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    avg = sum(intervals) / len(intervals)

    if not (MIN_BEACON_INTERVAL <= avg <= MAX_BEACON_INTERVAL):
        return False, None, None, "weak"

    variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
    std = variance ** 0.5
    cv = std / avg if avg > 0 else 999.0

    strength = "strong" if len(timestamps) >= STRONG_BEACON_MIN_SAMPLES and cv <= 0.38 else "weak"

    if cv <= BEACON_JITTER_PCT:
        return True, round(avg, 1), round(cv, 3), strength

    return False, None, None, "weak"

def calc_severity(flags, beacon_strength="weak"):
    weights = {
        "C2_COMMON_PORT":      6,
        "DENYLIST_HOST":       6,
        "BEACONING":           5 if beacon_strength == "strong" else 3,
        "FAKE_SYSTEM_NAME":    5,
        "SUSPICIOUS_PATH":     4,
        "HIGH_EPHEMERAL_PORT": 2,
        "PUBLIC_NONSTD_PORT":  2,
        "RAW_IP_NO_DNS":       2,
        "OUTBOUND_HEAVY":      3,
        "INBOUND_HEAVY":       3,
    }
    score = sum(weights.get(f, 1) for f in flags)
    if "BEACONING" in flags and beacon_strength == "strong":
        score += 3

    if score >= 12: return "HIGH",   score
    if score >=  7: return "MEDIUM", score
    return         "LOW",    score

# ===== MAIN LOOP =====

while True:
    now = time.time()
    seen = set()

    rotate_log_if_needed()

    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status != psutil.CONN_ESTABLISHED:
                continue
            if conn.type != socket.SOCK_STREAM or not conn.raddr or not conn.pid or conn.pid <= 0:
                continue

            remote_ip, remote_port = conn.raddr
            if remote_ip.startswith(("127.", "::1", "fe80::", "fc", "fd")):
                continue

            key = (conn.pid, remote_ip, remote_port)
            seen.add(key)

            beacon_key = (remote_ip, remote_port)
            beacon_stats[beacon_key].append(now)

            if key in active_sessions:
                continue

            # Lấy thông tin process
            try:
                proc = psutil.Process(conn.pid)
                app_name = proc.name() or "N/A"
                exe_path = proc.exe() or "N/A"
                proc_start = proc.create_time()
                parent_chain = get_parent_chain(proc)
                cmdline = " ".join(proc.cmdline() or [])[:400]

                # Optional: bytes sent/recv
                sent = conn.bytes_sent if hasattr(conn, 'bytes_sent') else None
                recv = conn.bytes_recv if hasattr(conn, 'bytes_recv') else None
            except:
                app_name = exe_path = parent_chain = cmdline = "N/A"
                proc_start = now
                sent = recv = None

            # Skip known safe process early
            if is_safe_process(app_name, exe_path):
                tracked_pids.add(conn.pid)
                continue

            flags = classify_flags(remote_port, remote_ip, resolve_ip(remote_ip))

            # Beacon
            is_beacon, avg_int, cv, strength = detect_beaconing(beacon_stats[beacon_key])
            if is_beacon:
                flags.add("BEACONING")

            # Suspicious signals
            if any(kw in exe_path.lower() for kw in SUSPICIOUS_PATH_KEYWORDS):
                flags.add("SUSPICIOUS_PATH")
            if any(fake in app_name.lower() for fake in FAKE_PROCESS_NAMES):
                flags.add("FAKE_SYSTEM_NAME")

            # Volume bias
            if sent is not None and recv is not None:
                total = sent + recv
                if total > 512:
                    if sent > recv * 3:
                        flags.add("OUTBOUND_HEAVY")
                    elif recv > sent * 3:
                        flags.add("INBOUND_HEAVY")

            if not flags:
                continue

            active_sessions[key] = {
                "app": app_name,
                "path": exe_path,
                "parent_chain": parent_chain,
                "cmdline": cmdline,
                "ip": remote_ip,
                "port": remote_port,
                "flags": flags,
                "start": now,
                "proc_start": proc_start,
                "beacon_interval": avg_int,
                "beacon_cv": cv,
                "beacon_strength": strength,
                "bytes_sent": sent,
                "bytes_recv": recv,
            }

    except Exception as e:
        print(f"Scan error: {e}")

    # Xử lý session kết thúc
    finished = []
    for key, s in list(active_sessions.items()):
        if key not in seen:
            duration = now - s["start"]
            if duration >= MIN_DURATION:
                host = resolve_ip(s["ip"])
                if host == "Unknown":
                    s["flags"].add("RAW_IP_NO_DNS")

                severity, score = calc_severity(s["flags"], s.get("beacon_strength", "weak"))

                summary = f"[{severity}] {s['app']} → {s['ip']}:{s['port']} ({host}) | dur:{int(duration)}s | score:{score}"

                log_lines = [
                    summary,
                    "-" * 70,
                    f"APP:          {s['app']}",
                    f"PARENT_CHAIN: {s['parent_chain']}",
                    f"CMDLINE:      {s['cmdline'][:300]}{'...' if len(s['cmdline']) > 300 else ''}",
                    f"PATH:         {s['path']}",
                    f"DEST:         {s['ip']}:{s['port']}  ({host})",
                    f"PROC_AGE:     {int(now - s['proc_start'])}s",
                    f"DURATION:     {int(duration)}s",
                ]

                if s.get("beacon_interval"):
                    cv_part = f" (CV={s['beacon_cv']:.3f})" if s.get("beacon_cv") else ""
                    strength_part = f" [{s['beacon_strength'].upper()}]" if s.get("beacon_strength") else ""
                    log_lines.append(f"BEACON:       ~{s['beacon_interval']}s{cv_part}{strength_part}")

                if s.get("bytes_sent") is not None:
                    log_lines.append(f"VOLUME:       sent={s['bytes_sent']:,}  recv={s['bytes_recv']:,}")

                log_lines.append("FLAGS:")
                for f in sorted(s["flags"]):
                    log_lines.append(f"  • {f}")

                log_lines.extend([
                    f"START:        {datetime.fromtimestamp(s['start'])}",
                    f"END:          {datetime.fromtimestamp(now)}",
                    "=" * 80,
                    ""
                ])

                try:
                    with open(LOG_FILE, "a", encoding="utf-8") as f:
                        f.write("\n".join(log_lines) + "\n")
                except Exception as e:
                    print(f"Log error: {e}")

            finished.append(key)

    for k in finished:
        del active_sessions[k]

    time.sleep(CHECK_INTERVAL)
