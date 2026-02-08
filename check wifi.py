#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EDR-lite Production 2026 v2 - Stable & Balanced
- Beacon jitter 70% (cân bằng false-positive/false-negative)
- DNS async + cache TTL + timeout
- Process age + parent chain + fake name/path
- Chỉ log MEDIUM/HIGH (WARNING level)
- CPU thấp, log tự rotate, dọn cache định kỳ
- Thêm UDP suspicious port check (DNS tunneling, custom C2)
"""

import psutil
import time
import socket
import ipaddress
from datetime import datetime
from collections import defaultdict, deque
import os
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import logging
from logging.handlers import RotatingFileHandler

# ================= CONFIG =================
CHECK_INTERVAL = 4.5          # cân bằng giữa phát hiện nhanh & tải CPU thấp
MIN_DURATION = 8              # tăng nhẹ để giảm log nhiễu
LOG_FILE = "suspicious_sessions.log"
LOG_MAX_SIZE = 10 * 1024 * 1024
LOG_BACKUP = 5

PROC_AGE_THRESHOLD = 300      # < 5 phút → suspicious hơn
BEACON_JITTER_PCT = 0.70      # 70% - giá trị cân bằng tốt nhất thực tế 2026

SAFE_PORTS = {21, 22, 53, 80, 123, 443, 853, 3478, 5228, 8080, 8443}

C2_COMMON_PORTS = {
    4444, 5555, 1337, 31337, 6666, 6667, 8000, 8089, 9001, 9002,
    10443, 44300, 4433, 7443, 9999, 12345, 444, 7777,
    8443, 8444, 8888, 3232, 11601, 40500               # thêm UDP-friendly ports
}

SUSPICIOUS_PATH_KEYWORDS = [
    "appdata", "temp", "\\roaming\\", "\\local\\", "downloads",
    "\\public\\", "\\programdata\\", "\\users\\public\\"
]

FAKE_PROCESS_NAMES = [
    "svch0st", "expl0rer", "winlogin", "chrome_update", "rundll32x",
    "mshta", "regsvr", "wscript", "cscript", "powershellx"
]

SAFE_PROCESS_PATHS = {
    "chrome.exe": ["\\google\\chrome\\", "\\chromium\\"],
    "msedge.exe": ["\\microsoft\\edge\\"],
    "firefox.exe": ["\\mozilla firefox\\"],
    "svchost.exe": ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "explorer.exe": ["\\windows\\"],
}

DENY_DEST_HOSTS = {
    "pastebin.com", "raw.githubusercontent.com", "controlc.com",
    "controlc.net", "0bin.net", "hastebin.com"
}

# Beacon tuning
MAX_BEACON_SAMPLES = 16
STRONG_BEACON_MIN_SAMPLES = 8
MIN_BEACON_INTERVAL = 5
MAX_BEACON_INTERVAL = 3600    # cho phép long-sleep beacons

DNS_CACHE_TTL = 14400
DNS_TIMEOUT = 1.5

# ================= LOGGING =================
handler = RotatingFileHandler(
    LOG_FILE, maxBytes=LOG_MAX_SIZE,
    backupCount=LOG_BACKUP, encoding="utf-8"
)
handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s"
))
logging.basicConfig(level=logging.INFO, handlers=[handler])

# ================= GLOBAL =================
active_sessions = {}
beacon_stats = defaultdict(lambda: deque(maxlen=MAX_BEACON_SAMPLES))
dns_cache = {}
dns_lock = threading.Lock()
dns_executor = ThreadPoolExecutor(max_workers=4)
proc_cache = {}  # pid → (name, path, start_time, cmdline)

print("EDR-lite Production 2026 v2 started")
print(f"Interval: {CHECK_INTERVAL}s | Jitter: {BEACON_JITTER_PCT*100}% | Log: {os.path.abspath(LOG_FILE)}\n")

# ================= HELPERS =================

def resolve_ip(ip):
    with dns_lock:
        if ip in dns_cache:
            ts, host = dns_cache[ip]
            if time.time() - ts < DNS_CACHE_TTL:
                return host

    def _resolve():
        try:
            return socket.gethostbyaddr(ip)[0].lower()
        except:
            return "Unknown"

    fut = dns_executor.submit(_resolve)
    try:
        host = fut.result(timeout=DNS_TIMEOUT)
    except:
        host = "Unknown/Timeout"

    with dns_lock:
        dns_cache[ip] = (time.time(), host)
    return host


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False


def get_proc_info(pid):
    if pid in proc_cache:
        return proc_cache[pid]
    try:
        p = psutil.Process(pid)
        info = (
            p.name() or "N/A",
            p.exe() or "N/A",
            p.create_time(),
            " ".join(p.cmdline() or [])[:350]
        )
    except:
        info = ("N/A", "N/A", time.time(), "N/A")
    proc_cache[pid] = info
    return info


def is_safe_process(name, path):
    name = name.lower()
    path = path.lower()
    if name not in SAFE_PROCESS_PATHS:
        return False
    return any(frag in path for frag in SAFE_PROCESS_PATHS[name])


def get_parent_chain(pid, levels=2):
    chain = []
    cur = pid
    for _ in range(levels):
        try:
            p = psutil.Process(cur).parent()
            if not p:
                break
            chain.append(f"{p.name()} ({p.pid})")
            cur = p.pid
        except:
            break
    return " → ".join(reversed(chain)) if chain else "Unknown"


def classify_flags(port, ip, kind='tcp'):
    flags = set()
    if port in C2_COMMON_PORTS:
        flags.add("C2_PORT")
    if is_public_ip(ip) and port not in SAFE_PORTS:
        flags.add("PUBLIC_NONSTD")
    if kind == 'udp' and port in {53, 40500}:
        flags.add("SUSPICIOUS_UDP")
    return flags


def detect_beacon(timestamps):
    if len(timestamps) < 4:
        return False, None, None, "weak"
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    avg = sum(intervals) / len(intervals)
    if not (MIN_BEACON_INTERVAL <= avg <= MAX_BEACON_INTERVAL):
        return False, None, None, "weak"
    variance = sum((x - avg)**2 for x in intervals) / len(intervals)
    std = variance ** 0.5
    cv = std / avg if avg > 0 else 999.0
    strength = "strong" if len(timestamps) >= STRONG_BEACON_MIN_SAMPLES and cv <= 0.38 else "weak"
    if cv <= BEACON_JITTER_PCT:
        return True, round(avg, 1), round(cv, 3), strength
    return False, None, None, "weak"


def calc_severity(flags, strength):
    weights = {
        "C2_PORT": 7,
        "BEACON": 6 if strength == "strong" else 3,
        "NEW_PROCESS": 4,
        "FAKE_NAME": 5,
        "SUSPICIOUS_PATH": 4,
        "PUBLIC_NONSTD": 3,
        "SUSPICIOUS_UDP": 4,
        "DENYLIST_HOST": 6,
    }
    score = sum(weights.get(f, 1) for f in flags)
    if "BEACON" in flags and strength == "strong":
        score += 4
    if score >= 13:
        return "HIGH", score
    if score >= 8:
        return "MEDIUM", score
    return "LOW", score


# ================= MAIN LOOP =================

while True:
    now = time.time()
    seen = set()

    try:
        for kind in ['tcp', 'udp']:
            for conn in psutil.net_connections(kind=kind):
                if kind == 'tcp' and conn.status != psutil.CONN_ESTABLISHED:
                    continue
                if not conn.raddr or not conn.pid or conn.pid <= 0:
                    continue
                ip, port = conn.raddr
                if ip.startswith(("127.", "::1", "fe80::", "fc", "fd")):
                    continue

                key = (conn.pid, ip, port, kind)
                seen.add(key)

                bkey = (ip, port, kind)
                beacon_stats[bkey].append(now)

                if key in active_sessions:
                    continue

                name, path, pstart, cmd = get_proc_info(conn.pid)
                if is_safe_process(name, path):
                    continue

                flags = classify_flags(port, ip, kind)

                if any(k in path.lower() for k in SUSPICIOUS_PATH_KEYWORDS):
                    flags.add("SUSPICIOUS_PATH")
                if any(f in name.lower() for f in FAKE_PROCESS_NAMES):
                    flags.add("FAKE_NAME")
                if now - pstart < PROC_AGE_THRESHOLD:
                    flags.add("NEW_PROCESS")

                is_b, avg, cv, strength = detect_beacon(beacon_stats[bkey])
                if is_b:
                    flags.add("BEACON")

                if not flags:
                    continue

                active_sessions[key] = {
                    "app": name,
                    "path": path,
                    "parent": get_parent_chain(conn.pid),
                    "cmd": cmd,
                    "ip": ip,
                    "port": port,
                    "kind": kind.upper(),
                    "flags": flags,
                    "start": now,
                    "proc_start": pstart,
                    "avg": avg,
                    "cv": cv,
                    "strength": strength
                }

    except Exception as e:
        logging.error(f"scan error: {e}")

    # Xử lý session kết thúc
    finished = []
    for k, s in list(active_sessions.items()):
        if k not in seen:
            dur = now - s["start"]
            if dur < MIN_DURATION:
                finished.append(k)
                continue

            host = resolve_ip(s["ip"])
            if host in DENY_DEST_HOSTS:
                s["flags"].add("DENYLIST_HOST")
            if host == "Unknown/Timeout":
                s["flags"].add("RAW_IP_NO_DNS")

            sev, score = calc_severity(s["flags"], s["strength"])

            if sev == "LOW":
                finished.append(k)
                continue

            msg = [
                f"[{sev}] {s['app']} ({s['kind']}) → {s['ip']}:{s['port']} ({host}) | dur:{int(dur)}s | score:{score}",
                f"PARENT: {s['parent']}",
                f"CMD: {s['cmd'][:300]}{'...' if len(s['cmd']) > 300 else ''}",
                f"PATH: {s['path']}",
                f"FLAGS: {', '.join(sorted(s['flags']))}"
            ]
            if s["avg"] is not None:
                msg.append(f"BEACON: ~{s['avg']}s (CV={s['cv']}) [{s['strength']}]")

            logging.warning("\n".join(msg) + "\n" + "-"*70)
            finished.append(k)

    for k in finished:
        del active_sessions[k]

    # Dọn cache
    if len(proc_cache) > 6000 or len(dns_cache) > 10000:
        proc_cache.clear()
        # dns_cache giữ lại vì TTL tự quản lý

    time.sleep(CHECK_INTERVAL)
