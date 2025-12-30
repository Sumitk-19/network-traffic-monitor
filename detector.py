from collections import defaultdict
import time

# -----------------------------
# Global Alert Store
# -----------------------------
alerts = []

# -----------------------------
# Thresholds (Tunable)
# -----------------------------
SYN_FLOOD_THRESHOLD = 50
FAILED_HANDSHAKE_THRESHOLD = 20
UNUSUAL_PROTOCOL_THRESHOLD = 10
ALERT_COOLDOWN = 30  # seconds per IP per alert type

# -----------------------------
# Tracking Structures
# -----------------------------
packet_count = defaultdict(int)

syn_count = defaultdict(int)
ack_count = defaultdict(int)

failed_handshakes = defaultdict(int)

protocol_usage = defaultdict(lambda: defaultdict(int))

last_alert_time = defaultdict(dict)

# -----------------------------
# Blacklisted IPs (Example)
# -----------------------------
BLACKLISTED_IPS = {
    "192.168.1.100",
    "10.10.10.10"
}

# -----------------------------
# Utility: Alert Deduplication
# -----------------------------
def should_alert(ip, alert_type):
    now = time.time()
    last_time = last_alert_time[ip].get(alert_type, 0)

    if now - last_time > ALERT_COOLDOWN:
        last_alert_time[ip][alert_type] = now
        return True
    return False

# -----------------------------
# Core Packet Analysis
# -----------------------------
def analyze_packet(packet):
    src = packet.get("src")
    proto = packet.get("protocol")
    flags = packet.get("flags")

    packet_count[src] += 1

    # ------------------------------------------------
    # 1. Blacklisted IP Detection
    # ------------------------------------------------
    if src in BLACKLISTED_IPS and should_alert(src, "BLACKLIST"):
        alerts.append({
            "type": "Blacklisted IP Detected",
            "ip": src,
            "time": time.ctime()
        })

    # ------------------------------------------------
    # 2. SYN Flood Detection
    # ------------------------------------------------
    if proto == "TCP":
        if flags == "S":
            syn_count[src] += 1
        elif flags == "A":
            ack_count[src] += 1

        if (
            syn_count[src] > SYN_FLOOD_THRESHOLD
            and ack_count[src] < 5
            and should_alert(src, "SYN_FLOOD")
        ):
            alerts.append({
                "type": "SYN Flood Attack",
                "ip": src,
                "syn_packets": syn_count[src],
                "time": time.ctime()
            })

    # ------------------------------------------------
    # 3. Repeated Failed TCP Handshakes
    # ------------------------------------------------
    if proto == "TCP":
        if flags == "S":
            failed_handshakes[src] += 1
        elif flags == "A":
            failed_handshakes[src] = max(0, failed_handshakes[src] - 1)

        if (
            failed_handshakes[src] > FAILED_HANDSHAKE_THRESHOLD
            and should_alert(src, "FAILED_HANDSHAKE")
        ):
            alerts.append({
                "type": "Repeated Failed TCP Handshakes",
                "ip": src,
                "attempts": failed_handshakes[src],
                "time": time.ctime()
            })

    # ------------------------------------------------
    # 4. Unusual Protocol Usage
    # ------------------------------------------------
    protocol_usage[src][proto] += 1

    if (
        proto not in ["TCP", "UDP"]
        and protocol_usage[src][proto] > UNUSUAL_PROTOCOL_THRESHOLD
        and should_alert(src, "UNUSUAL_PROTOCOL")
    ):
        alerts.append({
            "type": "Unusual Protocol Usage",
            "ip": src,
            "protocol": proto,
            "count": protocol_usage[src][proto],
            "time": time.ctime()
        })

# -----------------------------
# API Helper
# -----------------------------
def get_alerts():
    return alerts
