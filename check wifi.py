import psutil
import time
import socket
from datetime import datetime
from collections import defaultdict

# ===== CONFIG =====
CHECK_INTERVAL = 1
MIN_DURATION = 4
LOG_FILE = "suspicious_sessions.log"

SAFE_PORTS = {443, 53, 80, 123, 5228, 3478, 8080, 8443}
C2_PORTS = {4444, 5555, 1337, 9001, 9002, 6667, 31337}

SUSPICIOUS_PATHS = ["appdata", "temp", "downloads"]
FAKE_NAMES = ["svch0st", "expl0rer", "winlogin", "chrome_update"]

active_sessions = {}
dns_cache = {}

# 🔥 beaconing theo IP + PORT (global, không phụ thuộc process)
beacon_stats = defaultdict(list)

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

def classify_flags(port):
    flags = set()
    if port in C2_PORTS:
        flags.add("C2 / BACKDOOR PORT")
    if port > 40000:
        flags.add("HIGH RANDOM PORT")
    if port not in SAFE_PORTS:
        flags.add("PORT LẠ")
    return flags

def calc_severity(flags):
    score = 0

    for f in flags:
        if "C2 / BACKDOOR" in f:
            score += 3
        elif "BEACONING" in f:
            score += 3
        elif "RAW IP" in f:
            score += 2
        elif "SUSPICIOUS PATH" in f:
            score += 2
        elif "FAKE SYSTEM" in f:
            score += 3
        else:
            score += 1

    # 🔥 Ưu tiên C2 giống EDR thật
    if "C2 / BACKDOOR PORT" in flags and "PORT LẠ" in flags:
        score += 2

    if score >= 6:
        return "HIGH", score
    if score >= 3:
        return "MEDIUM", score
    return "LOW", score

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
            except:
                app = "Unknown"
                path = "Unknown"

            # 🔥 BEACONING (nhạy hơn, thực tế hơn)
            beacon_key = (remote_ip, remote_port)
            beacon_stats[beacon_key].append(now)
            times = beacon_stats[beacon_key]

            if len(times) >= 2 and (times[-1] - times[-2]) < 60:
                flags.add("BEACONING (periodic C2)")

            if any(p in path.lower() for p in SUSPICIOUS_PATHS):
                flags.add("SUSPICIOUS PATH")

            if any(f in app.lower() for f in FAKE_NAMES):
                flags.add("FAKE SYSTEM NAME")

            active_sessions[key] = {
                "app": app,
                "path": path,
                "ip": remote_ip,
                "port": remote_port,
                "flags": flags,
                "start": now,
            }

    finished = []

    for key, s in list(active_sessions.items()):
        if key not in seen:
            duration = int(now - s["start"])
            if duration > MIN_DURATION:
                host = resolve_ip(s["ip"])
                if host == "Unknown":
                    s["flags"].add("RAW IP (no DNS)")

                severity, score = calc_severity(s["flags"])

                log = (
                    f"SEVERITY: {severity} (score={score})\n"
                    f"APP: {s['app']}\n"
                    f"PATH: {s['path']}\n"
                    f"DEST: {s['ip']}:{s['port']}\n"
                    f"HOST: {host}\n"
                    f"FLAGS:\n"
                )

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
