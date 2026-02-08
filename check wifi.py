import psutil
import time
import socket
import ipaddress
from datetime import datetime
from collections import defaultdict, deque

# ===== CONFIG =====
CHECK_INTERVAL = 1
MIN_DURATION = 4
LOG_FILE = "suspicious_sessions.log"   # ⛔ GIỮ NGUYÊN

SAFE_PORTS = {443, 53, 80, 123, 5228, 3478, 8080, 8443}
C2_PORTS = {4444, 5555, 1337, 9001, 9002, 6667, 31337}

SUSPICIOUS_PATHS = ["appdata", "temp", "downloads"]
FAKE_NAMES = ["svch0st", "expl0rer", "winlogin", "chrome_update"]

SYSTEM_WHITELIST = {
    "chrome.exe", "msedge.exe", "firefox.exe",
    "svchost.exe", "system", "services.exe"
}

MAX_BEACON_EVENTS = 6
BEACON_JITTER = 10  # seconds

active_sessions = {}
dns_cache = {}

# IP+PORT → timestamps
beacon_stats = defaultdict(lambda: deque(maxlen=MAX_BEACON_EVENTS))

print("Tool đang chạy (EDR-level behavior detection enabled)...")

# ===== HÀM =====
def resolve_ip(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except:
        host = "Unknown"
    dns_cache[ip] = host
    return host

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False

def classify_flags(port):
    flags = set()
    if port in C2_PORTS:
        flags.add("C2 / BACKDOOR PORT")
    if port > 40000:
        flags.add("HIGH RANDOM PORT")
    if port not in SAFE_PORTS:
        flags.add("PORT LẠ")
    return flags

def detect_beaconing(times):
    if len(times) < 3:
        return False, None
    intervals = [times[i] - times[i-1] for i in range(1, len(times))]
    avg = sum(intervals) / len(intervals)
    if all(abs(i - avg) < BEACON_JITTER for i in intervals):
        return True, round(avg, 1)
    return False, None

def calc_severity(flags):
    score = 0
    weights = {
        "C2 / BACKDOOR PORT": 4,
        "BEACONING": 4,
        "RAW IP": 3,
        "SUSPICIOUS PATH": 2,
        "FAKE SYSTEM": 4,
        "PORT LẠ": 1,
        "HIGH RANDOM PORT": 1,
    }

    for f in flags:
        for k, w in weights.items():
            if k in f:
                score += w

    if score >= 8:
        return "HIGH", score
    if score >= 4:
        return "MEDIUM", score
    return "LOW", score

def get_parent_info(proc):
    try:
        parent = proc.parent()
        if parent:
            return f"{parent.name()} (PID {parent.pid})"
    except:
        pass
    return "Unknown"

# ===== LOOP =====
while True:
    now = time.time()
    seen = set()

    for conn in psutil.net_connections(kind="inet"):
        if conn.type != socket.SOCK_STREAM:
            continue
        if not conn.raddr or not conn.pid:
            continue

        remote_ip, remote_port = conn.raddr
        if remote_ip.startswith("127.") or remote_ip == "::1":
            continue

        flags = classify_flags(remote_port)
        if not flags:
            continue

        key = (conn.pid, remote_ip, remote_port)
        seen.add(key)

        if key not in active_sessions:
            try:
                proc = psutil.Process(conn.pid)
                app = proc.name()
                path = proc.exe()
                create_time = proc.create_time()
                parent_info = get_parent_info(proc)
                cmdline = " ".join(proc.cmdline())[:200]
            except:
                app = path = parent_info = cmdline = "Unknown"
                create_time = now

            app_lower = app.lower()
            if app_lower in SYSTEM_WHITELIST:
                continue

            beacon_key = (remote_ip, remote_port)
            beacon_stats[beacon_key].append(now)

            beacon, interval = detect_beaconing(beacon_stats[beacon_key])
            if beacon:
                flags.add("BEACONING (periodic C2)")

            if any(p in path.lower() for p in SUSPICIOUS_PATHS):
                flags.add("SUSPICIOUS PATH")

            if any(f in app_lower for f in FAKE_NAMES):
                flags.add("FAKE SYSTEM NAME")

            if is_public_ip(remote_ip):
                flags.add("PUBLIC IP")

            active_sessions[key] = {
                "app": app,
                "path": path,
                "ip": remote_ip,
                "port": remote_port,
                "flags": flags,
                "start": now,
                "proc_start": create_time,
                "parent": parent_info,
                "cmdline": cmdline,
                "beacon_interval": interval,
            }

    finished = []

    for key, s in list(active_sessions.items()):
        if key not in seen:
            duration = int(now - s["start"])
            lifetime = int(now - s["proc_start"])

            if duration > MIN_DURATION:
                host = resolve_ip(s["ip"])
                if host == "Unknown":
                    s["flags"].add("RAW IP (no DNS)")

                severity, score = calc_severity(s["flags"])

                log = (
                    f"SEVERITY: {severity} (score={score})\n"
                    f"APP: {s['app']}\n"
                    f"PARENT: {s['parent']}\n"
                    f"CMDLINE: {s['cmdline']}\n"
                    f"PATH: {s['path']}\n"
                    f"DEST: {s['ip']}:{s['port']}\n"
                    f"HOST: {host}\n"
                    f"LIFETIME: {lifetime}s\n"
                )

                if s["beacon_interval"]:
                    log += f"BEACON INTERVAL: ~{s['beacon_interval']}s\n"

                log += "FLAGS:\n"
                for f in sorted(s["flags"]):
                    log += f" - {f}\n"

                log += (
                    f"START: {datetime.fromtimestamp(s['start'])}\n"
                    f"END:   {datetime.fromtimestamp(now)}\n"
                    f"DURATION: {duration}s\n"
                    f"{'-'*50}\n"
                )

                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(log)

            finished.append(key)

    for k in finished:
        del active_sessions[k]

    time.sleep(CHECK_INTERVAL)
