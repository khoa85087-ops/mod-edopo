#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EDR-lite Production 2026 v20 - Final strong version
- DNS_FAIL bỏ qua nếu host trong SAFE_DOMAINS
- UNKNOWN_SOURCE +2 boost khi BEACON + FIRST_SEEN_DEST
- Log grouped explanations: Network / Process / Behavior
- Min samples 12, jitter 50%, duration 60s
- Added file identity: size, creation time, modified time
- Added persistence hints based on path
- Added destination reuse/clustering logging
- Added DNS entropy check for high entropy domains
- Skipped ASN/Hosting tag as it requires external lookup not available in env
"""
import psutil
import time
import socket
import ipaddress
import hashlib
from collections import defaultdict, deque
import os
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
from logging.handlers import RotatingFileHandler
import statistics
import re
import math  # For entropy calculation

# ================= CONFIG =================
CHECK_INTERVAL = 5.0
MIN_DURATION = 60
LOG_FILE = "suspicious_sessions.log"
LOG_MAX_SIZE = 10 * 1024 * 1024
LOG_BACKUP = 5
PROC_AGE_THRESHOLD = 600
BEACON_JITTER_PCT = 0.50
MIN_BEACON_SAMPLES = 12
STRONG_BEACON_MIN_SAMPLES = 18
MIN_BEACON_INTERVAL = 10
MAX_BEACON_INTERVAL = 14400
MAX_CV_THRESHOLD = 0.50
MIN_CONSECUTIVE_RATIO = 0.75
BURST_THRESHOLD = 3
MIN_BYTES_FOR_EXFIL = 1024 * 50
FIRST_SEEN_TTL = 864000  # 10 ngày
SAFE_PORTS = {21, 22, 53, 80, 123, 443, 853, 3478, 5228, 8080, 8443, 1935, 19302,
              25, 465, 587, 143, 993, 110, 995, 1194, 51820, 5938, 10000, 10001, 3479, 3480}
C2_COMMON_PORTS = {4444, 5555, 1337, 31337, 6666, 6667, 8000, 8089, 9001, 9002,
                   10443, 44300, 4433, 7443, 9999, 12345, 444, 7777, 8443, 8444, 8888, 3232,
                   11601, 40500, 27015, 27016, 2302, 7778, 28960, 6112, 6113, 3724, 3389}
SUSPICIOUS_PATH_KEYWORDS = ["appdata", "temp", "\\roaming\\", "\\local\\", "downloads",
                            "\\public\\", "\\programdata\\", "\\users\\public\\", "edopro", "ygo", "duel"]
PERSISTENCE_PATH_KEYWORDS = ["startup", "programdata", "appdata\\roaming", "appdata\\local\\temp"]  # Added for persistence hints
FAKE_PROCESS_NAMES = ["svch0st", "expl0rer", "winlogin", "chrome_update", "rundll32x",
                      "mshta", "regsvr", "wscript", "cscript", "powershellx", "unknown.exe",
                      "bitsadmin", "certutil", "schtasks"]
SAFE_PROCESS_PATHS = {
    "chrome.exe": ["\\google\\chrome\\", "\\chromium\\"],
    "msedge.exe": ["\\microsoft\\edge\\"],
    "firefox.exe": ["\\mozilla firefox\\"],
    "svchost.exe": ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "explorer.exe": ["\\windows\\"],
    "zalo.exe": ["\\zalo\\", "\\appdata\\local\\programs\\zalo\\"],
    "steam.exe": ["\\steam\\"],
    "epicgameslauncher.exe": ["\\epic games\\"],
    "discord.exe": ["\\discord\\"],
    "javaw.exe": ["\\java\\", "\\minecraft\\"],
    "garenaclient.exe": ["\\garena\\"],
    "pubg.exe": ["\\garena\\", "\\tencent\\"],
    "valorant.exe": ["\\riot games\\", "\\valorant\\"],
    "wuauclt.exe": ["\\windows\\"],
    "adobearm.exe": ["\\adobe\\"],
    "nvcontainer.exe": ["\\nvidia\\"],
    "winword.exe": ["\\microsoft office\\"],
    "excel.exe": ["\\microsoft office\\"],
}
SAFE_DOMAINS = {
    "akamai.net", "cloudflare.com", "cloudflare-dns.com", "amazonaws.com", "s3.amazonaws.com",
    "azureedge.net", "googleusercontent.com", "gstatic.com", "googleapis.com",
    "windowsupdate.com", "dl.delivery.mp.microsoft.com", "steampowered.com", "epicgames.com",
    "riotgames.com", "zalo.me", "zalo.cloud", "api.zalo.me", "vng.com.vn", "garena.com",
    "viettel.vn", "fpt.vn", "bkav.vn", "adobe.com", "nvidia.com", "apple.com", "icloud.com",
}
DENY_DEST_HOSTS = {
    "pastebin.com", "raw.githubusercontent.com", "githubusercontent.com", "controlc.com",
    "0bin.net", "hastebin.com", "github.io", "bit.ly", "ngrok.io", "tryhackme.com", "hackthebox.eu"
}
HIGH_ENTROPY_THRESHOLD = 3.5  # For DNS entropy flag

# ================= LOGGING & GLOBALS =================
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[handler])
active_sessions = {}
beacon_stats = defaultdict(lambda: deque(maxlen=60))
io_stats = defaultdict(lambda: deque(maxlen=60))
seen_destinations = {}  # (effective_key, ip) -> timestamp
session_history = defaultdict(lambda: deque(maxlen=10))
dns_cache = {}
dns_lock = threading.Lock()
dns_executor = ThreadPoolExecutor(max_workers=6)
proc_cache = {}
related_procs = defaultdict(set)
dest_session_count = defaultdict(int)  # Destination -> session count
process_per_ip = defaultdict(set)  # IP -> set of process names
last_prune = time.time()
print("EDR-lite Production 2026 v20 – final strong version started\n")

# ================= HELPERS =================
def calculate_entropy(domain):
    if not domain:
        return 0.0
    from collections import Counter
    freq = Counter(domain.lower())
    length = len(domain)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return entropy

def resolve_ip(ip):
    with dns_lock:
        if ip in dns_cache and time.time() - dns_cache[ip][0] < 14400:
            return dns_cache[ip][1]
    def _resolve():
        try:
            return socket.gethostbyaddr(ip)[0].lower()
        except:
            return None
    fut = dns_executor.submit(_resolve)
    try:
        host = fut.result(timeout=1.2)
    except:
        host = None
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
        path = p.exe() or "N/A"
        name = p.name() or "N/A"
        create_time = p.create_time()
        cmd = " ".join(p.cmdline() or [])[:350]
        io_counters = p.io_counters() if hasattr(p, 'io_counters') else None
        
        # Added file identity
        file_size = os.path.getsize(path) if os.path.exists(path) else "N/A"
        file_ctime = os.path.getctime(path) if os.path.exists(path) else "N/A"
        file_mtime = os.path.getmtime(path) if os.path.exists(path) else "N/A"
        
        info = (name, path, create_time, cmd, io_counters, file_size, file_ctime, file_mtime)
    except:
        info = ("N/A", "N/A", time.time(), "N/A", None, "N/A", "N/A", "N/A")
    proc_cache[pid] = info
    return info

def get_session_key(pid, path, ip, port):
    if path and path != "N/A":
        key_str = f"{path.lower()}|{ip}|{port}"
    else:
        name, _, _, cmd, _, _, _, _ = get_proc_info(pid)
        key_str = f"{name.lower()}|{cmd[:100]}|{ip}|{port}"
    return hashlib.sha256(key_str.encode()).hexdigest()

def get_effective_dest_key(host, ip):
    if host and host not in {"Unknown", "Unknown/Timeout", None, ""}:
        return host.lower()
    return ip

def is_first_seen_destination(ip, host):
    effective_key = get_effective_dest_key(host, ip)
    key = (effective_key, ip)
    now = time.time()
    if key in seen_destinations and now - seen_destinations[key] < FIRST_SEEN_TTL:
        return False
    seen_destinations[key] = now
    return True

def is_safe_process(name, path, host):
    name_lower = name.lower()
    path_lower = path.lower()
    host_lower = host.lower() if host else ""
    if name_lower in SAFE_PROCESS_PATHS and any(frag in path_lower for frag in SAFE_PROCESS_PATHS[name_lower]):
        return True
    if any(safe in host_lower for safe in SAFE_DOMAINS):
        return True
    return False

def get_parent_chain(pid, levels=8):
    chain = []
    cur = pid
    for _ in range(levels):
        try:
            p = psutil.Process(cur).parent()
            if not p: break
            chain.append(f"{p.name()} ({p.pid})")
            related_procs[pid].add(p.pid)
            cur = p.pid
        except:
            break
    return " → ".join(reversed(chain)) if chain else "Unknown"

def classify_flags(port, ip, kind, host, name, path, dur, bytes_sent, bytes_recv, is_deny_host, is_beacon=False):
    flags = set()
    explanations = {}
    
    if port in C2_COMMON_PORTS:
        flags.add("C2_PORT")
        explanations["C2_PORT"] = "Common C2 port"
    
    if is_public_ip(ip) and port not in SAFE_PORTS:
        flags.add("PUBLIC_NONSTD")
    
    if kind == 'udp' and port in {53, 40500, 27015, 27016, 2302, 7778, 28960}:
        flags.add("SUSPICIOUS_UDP")
    
    if any(k in path.lower() for k in SUSPICIOUS_PATH_KEYWORDS):
        flags.add("SUSPICIOUS_PATH")
    
    if any(f in name.lower() for f in FAKE_PROCESS_NAMES):
        flags.add("FAKE_NAME")
    
    if dur > 3600:
        flags.add("LONG_DURATION")
    
    if bytes_sent > MIN_BYTES_FOR_EXFIL:
        flags.add("POTENTIAL_EXFIL")
    
    if is_deny_host and (is_beacon or "RAW_IP" in flags or "SUSPICIOUS_PATH" in flags):
        flags.add("DENYLIST_HOST")
    
    # DNS_FAIL chỉ flag nếu KHÔNG thuộc SAFE_DOMAINS
    host_str = host or ""
    is_safe_domain = any(safe in host_str.lower() for safe in SAFE_DOMAINS) if host_str else False
    
    if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", host_str):
        flags.add("RAW_IP")
        explanations["RAW_IP"] = "Connection to raw IP (no hostname)"
    elif host in {None, "Unknown", "Unknown/Timeout", ""} and not is_safe_domain:
        flags.add("DNS_FAIL")
        explanations["DNS_FAIL"] = "DNS resolution failed or timed out"
    
    # Added DNS entropy
    if host and not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", host):
        entropy = calculate_entropy(host)
        if entropy > HIGH_ENTROPY_THRESHOLD:
            flags.add("HIGH_DNS_ENTROPY")
            explanations["HIGH_DNS_ENTROPY"] = f"High domain entropy: {entropy:.2f} (possible DGA)"
    
    # Added persistence hint
    if any(k in path.lower() for k in PERSISTENCE_PATH_KEYWORDS):
        flags.add("PERSISTENCE_HINT")
        explanations["PERSISTENCE_HINT"] = "Path suggests possible persistence (check startup/registry)"
    
    return flags, explanations

def detect_beacon(timestamps, io_samples):
    n = len(timestamps)
    if n < MIN_BEACON_SAMPLES:
        return False, None, None, "weak", set()
    
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, n)]
    if len(intervals) < 6:
        return False, None, None, "weak", set()
    
    q1, q3 = statistics.quantiles(intervals, n=4)[1:3]
    iqr = q3 - q1
    cleaned = [x for x in intervals if q1 - 1.5*iqr <= x <= q3 + 1.5*iqr]
    
    if len(cleaned) < MIN_BEACON_SAMPLES - 3:
        return False, None, None, "too_noisy", set()
    
    avg = statistics.mean(cleaned)
    if not (MIN_BEACON_INTERVAL <= avg <= MAX_BEACON_INTERVAL):
        return False, None, None, "out_of_range", set()
    
    std = statistics.stdev(cleaned) if len(cleaned) > 1 else 0
    cv = std / avg if avg > 0 else 999.0
    
    if cv > MAX_CV_THRESHOLD:
        return False, None, None, "too_random", set()
    
    in_tolerance = sum(1 for i in cleaned if abs(i - avg)/avg <= BEACON_JITTER_PCT)
    if in_tolerance / len(cleaned) < MIN_CONSECUTIVE_RATIO:
        return False, None, None, "inconsistent", set()
    
    burst_flags = set()
    burst_count = sum(1 for i in intervals if i < avg * 0.5)
    if burst_count >= BURST_THRESHOLD:
        burst_flags.add("BURST_PATTERN")
    
    if io_samples and len(io_samples) >= 3:
        total_sent = io_samples[-1][0] - io_samples[0][0]
        total_recv = io_samples[-1][1] - io_samples[0][1]
        if total_recv > 0 and total_sent / total_recv < 0.2:
            burst_flags.add("COMMAND_POLLING")
        if total_sent > 0 and total_recv / total_sent < 0.2:
            burst_flags.add("POTENTIAL_EXFIL_IO")
    
    strength = "strong" if n >= STRONG_BEACON_MIN_SAMPLES and cv <= 0.25 else "medium" if cv <= 0.35 else "weak"
    is_beacon = cv <= BEACON_JITTER_PCT or "BURST_PATTERN" in burst_flags
    
    return is_beacon, round(avg, 1), round(cv, 3), strength, burst_flags

def update_evolution_level(session_key, flags, dur):
    levels = session_history[session_key]
    prev = levels[-1] if levels else "NEW"
    current = prev
    
    has_strong_signal = any(f in flags for f in ["COMMAND_POLLING", "FIRST_SEEN_DEST", "C2_PORT"])
    
    if "BEACON" in flags:
        if prev == "NEW":
            current = "MEDIUM" if has_strong_signal else "LOW"
        elif prev == "LOW":
            current = "MEDIUM" if has_strong_signal or dur > 900 else "LOW"
        elif prev == "MEDIUM":
            current = "HIGH" if has_strong_signal or dur > 3600 else "MEDIUM"
    
    levels.append(current)
    return current

def calc_severity(flags, strength, dur, first_seen=False, io_flags=set(), evolution="NEW", boost=0):
    weights = {
        "C2_PORT": 9,
        "BEACON": 12 if strength == "strong" else 8 if strength == "medium" else 4,
        "NEW_PROCESS": 5,
        "FAKE_NAME": 7,
        "SUSPICIOUS_PATH": 6,
        "PUBLIC_NONSTD": 4,
        "SUSPICIOUS_UDP": 5,
        "DENYLIST_HOST": 9,
        "RAW_IP": 5,
        "DNS_FAIL": 4,
        "LONG_DURATION": 4,
        "POTENTIAL_EXFIL": 8,
        "POTENTIAL_EXFIL_IO": 9,
        "COMMAND_POLLING": 7,
        "BURST_PATTERN": 6,
        "FIRST_SEEN_DEST": 6,
        "EVOLUTION_HIGH": 10,
        "UNKNOWN_SOURCE": 3,
        "HIGH_DNS_ENTROPY": 6,  # Added
        "PERSISTENCE_HINT": 5,  # Added
    }
    
    score = sum(weights.get(f, 1) for f in flags) + boost
    
    if "BEACON" in flags:
        score += 10 if strength in {"strong", "medium"} and dur > 1800 else 5
        if first_seen: score += 6
        if "COMMAND_POLLING" in io_flags: score += 5
        if "POTENTIAL_EXFIL_IO" in io_flags: score += 8
        
        # UNKNOWN_SOURCE base
        if "UNKNOWN_SOURCE" in flags:
            score += weights["UNKNOWN_SOURCE"]
        
        # Extra boost: UNKNOWN_SOURCE + BEACON + FIRST_SEEN
        if "UNKNOWN_SOURCE" in flags and first_seen:
            score += 2
    
    if evolution == "HIGH":
        score += 10
    
    if score >= 32: return "CRITICAL", score
    if score >= 24: return "HIGH", score
    if score >= 15: return "MEDIUM", score
    return "LOW", score

# ================= MAIN LOOP =================
while True:
    now = time.time()
    seen = set()
    
    try:
        current_conns = {}
        for kind in ['tcp', 'udp']:
            for conn in psutil.net_connections(kind=kind):
                if kind == 'tcp' and conn.status != psutil.CONN_ESTABLISHED: continue
                if not conn.raddr or not conn.pid or conn.pid <= 0: continue
                ip, port = conn.raddr
                if ip.startswith(("127.", "::1", "fe80::", "fc", "fd")): continue
                key = (conn.pid, ip, port, kind)
                seen.add(key)
                bkey = (ip, port, kind)
                beacon_stats[bkey].append(now)
                
                _, _, _, _, io_counter, _, _, _ = get_proc_info(conn.pid)
                if io_counter:
                    io_stats[bkey].append((io_counter.write_bytes, io_counter.read_bytes))
                
                if key not in active_sessions:
                    name, path, pstart, cmd, _, file_size, file_ctime, file_mtime = get_proc_info(conn.pid)
                    host = resolve_ip(ip) or "Unknown"
                    if is_safe_process(name, path, host):
                        continue
                    current_conns[key] = {
                        "app": name, "path": path, "parent": get_parent_chain(conn.pid),
                        "cmd": cmd, "ip": ip, "port": port, "kind": kind.upper(),
                        "start": now, "proc_start": pstart,
                        "bytes_sent": 0, "bytes_recv": 0, "host": host,
                        "file_size": file_size, "file_ctime": file_ctime, "file_mtime": file_mtime
                    }
        
        for key in list(active_sessions):
            if key in seen:
                pid = key[0]
                _, _, _, _, io_counter, _, _, _ = get_proc_info(pid)
                if io_counter:
                    active_sessions[key]["bytes_sent"] = io_counter.write_bytes
                    active_sessions[key]["bytes_recv"] = io_counter.read_bytes
        
        for key, sess in current_conns.items():
            if key not in active_sessions:
                active_sessions[key] = sess
                # Update clustering
                dest_key = get_effective_dest_key(sess["host"], sess["ip"])
                dest_session_count[dest_key] += 1
                process_per_ip[sess["ip"]].add(sess["app"])
    
    except Exception as e:
        logging.error(f"scan error: {e}")
    
    finished = []
    for k, s in list(active_sessions.items()):
        if k not in seen:
            dur = now - s["start"]
            if dur < MIN_DURATION:
                finished.append(k)
                continue
            
            bkey = (s["ip"], s["port"], s["kind"].lower())
            is_b, avg, cv, strength, burst_flags = detect_beacon(beacon_stats[bkey], io_stats.get(bkey, []))
            
            is_deny_host = s["host"] in DENY_DEST_HOSTS
            flags, explanations = classify_flags(
                s["port"], s["ip"], s["kind"].lower(), s["host"],
                s["app"], s["path"], dur, s["bytes_sent"], s["bytes_recv"],
                is_deny_host, is_beacon=is_b
            )
            
            if is_b:
                flags.add("BEACON")
                explanations["BEACON"] = f"Avg interval ~{avg}s, CV={cv}, strength={strength}"
            
            flags.update(burst_flags)
            
            first_seen = is_first_seen_destination(s["ip"], s["host"])
            if first_seen and is_b:
                flags.add("FIRST_SEEN_DEST")
                explanations["FIRST_SEEN_DEST"] = "First-seen destination + beaconing"
            
            if now - s["proc_start"] < PROC_AGE_THRESHOLD:
                flags.add("NEW_PROCESS")
            
            if s["app"].lower() not in SAFE_PROCESS_PATHS:
                flags.add("UNKNOWN_SOURCE")
            
            session_key = get_session_key(k[0], s["path"], s["ip"], s["port"])
            current_level = update_evolution_level(session_key, flags, dur)
            if current_level == "HIGH":
                flags.add("EVOLUTION_HIGH")
                explanations["EVOLUTION_HIGH"] = "Beacon severity evolved to HIGH over time"
            
            boost = 5 if {"BEACON", "POTENTIAL_EXFIL", "FAKE_NAME"} <= flags else 0
            
            sev, score = calc_severity(flags, strength, dur, first_seen, burst_flags, current_level, boost)
            
            if sev == "LOW":
                finished.append(k)
                continue
            
            related = " | Related: " + ", ".join(f"{psutil.Process(p).name()} ({p})" for p in related_procs.get(k[0], set()) if p != k[0])
            
            # Nhóm explanations theo loại cho SOC dễ đọc
            net_exp = []
            proc_exp = []
            beh_exp = []
            
            for flag, exp in sorted(explanations.items()):
                if flag in {"C2_PORT", "PUBLIC_NONSTD", "SUSPICIOUS_UDP", "DENYLIST_HOST", "RAW_IP", "DNS_FAIL", "FIRST_SEEN_DEST", "HIGH_DNS_ENTROPY"}:
                    net_exp.append(f" - {flag}: {exp}")
                elif flag in {"FAKE_NAME", "SUSPICIOUS_PATH", "NEW_PROCESS", "UNKNOWN_SOURCE", "LONG_DURATION", "PERSISTENCE_HINT"}:
                    proc_exp.append(f" - {flag}: {exp}")
                else:
                    beh_exp.append(f" - {flag}: {exp}")
            
            # Xác định loại suspicious chính
            susp_type = "Behavior"
            if beh_exp: susp_type = "Behavior"
            elif net_exp: susp_type = "Network"
            elif proc_exp: susp_type = "Process"
            
            dest_key = get_effective_dest_key(s["host"], s["ip"])
            clustering_info = f"Destination seen on {dest_session_count[dest_key]} sessions | Same IP used by {len(process_per_ip[s['ip']])} processes"
            
            msg = [
                f"[{sev}] Suspicious Session Detected | Score: {score} | Type: {susp_type} dominant | Evolution: {current_level} | Boost: {boost}",
                f"Process: {s['app']} (PID: {k[0]}) | {s['kind']} | {s['ip']}:{s['port']} ({s['host']})",
                f"Duration: {int(dur)}s | Bytes sent/recv: {s['bytes_sent']:,} / {s['bytes_recv']:,}",
                f"Parent chain: {s['parent']}{related}",
                f"Command line: {s['cmd'][:300]}{'...' if len(s['cmd']) > 300 else ''}",
                f"Executable path: {s['path']}",
                f"File info: Size={s['file_size']:,} bytes | Created={time.ctime(s['file_ctime']) if s['file_ctime'] != 'N/A' else 'N/A'} | Modified={time.ctime(s['file_mtime']) if s['file_mtime'] != 'N/A' else 'N/A'}",
                f"Clustering: {clustering_info}",
                f"Flags: {', '.join(sorted(flags))}",
                "",
                "Explanations (grouped):",
                "Network related:",
            ] + net_exp + [
                "Process related:",
            ] + proc_exp + [
                "Behavior related:",
            ] + beh_exp
            if is_b:
                msg.append("")
                msg.append(f"Beacon details: ~{avg}s interval | CV={cv} | Strength={strength} | Samples={len(beacon_stats[bkey])}")
            msg.append("")
            msg.append(f"Recommendation: {sev} alert → consider process isolation, network block, deep forensics.")
            msg.append("-"*100)
            
            logging.warning("\n".join(msg))
            finished.append(k)
    
    for k in finished:
        active_sessions.pop(k, None)
    
    if now - last_prune > 300:
        proc_cache.clear()
        dns_cache = {k: v for k, v in dns_cache.items() if now - v[0] < 28800}
        seen_destinations = {k: ts for k, ts in seen_destinations.items() if now - ts < FIRST_SEEN_TTL}
        last_prune = now
    
    time.sleep(CHECK_INTERVAL)
