from scapy.all import sniff, IP, TCP, UDP
from detector import analyze_packet

# -----------------------------
# Packet Processing Callback
# -----------------------------
def packet_callback(packet):
    try:
        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "OTHER"
        src_port = None
        dst_port = None
        flags = None

        # TCP Packet
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Extract TCP flags (S, A, F, R, etc.)
            flags = packet[TCP].flags
            flags = flags if isinstance(flags, str) else flags.__repr__()

        # UDP Packet
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Build normalized packet object
        packet_data = {
            "src": src_ip,
            "dst": dst_ip,
            "protocol": protocol,
            "sport": src_port,
            "dport": dst_port,
            "flags": flags
        }

        analyze_packet(packet_data)

    except Exception as e:
        # Silent fail to keep sniffer running
        pass

# -----------------------------
# Start Packet Sniffing
# -----------------------------
def start_sniffing(interface=None):
    sniff(
        iface=interface,
        prn=packet_callback,
        store=False
    )

# -----------------------------
# Entry Point
# -----------------------------
if __name__ == "__main__":
    print("[*] Starting Network Traffic Monitor...")
    start_sniffing()
