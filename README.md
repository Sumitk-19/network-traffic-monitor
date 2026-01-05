Network Traffic Monitor – Mini Intrusion Detection System (IDS)

A Python-based network traffic monitoring and intrusion detection dashboard that captures live packets, analyzes TCP/IP behavior, detects common attack patterns, and visualizes security alerts through a web interface.
This project is designed as an intermediate-level cybersecurity portfolio project, demonstrating real-world packet analysis, rule-based detection logic, and backend visualization.

🔐 Key Features

Live network packet capture using Scapy
TCP/IP traffic analysis
Rule-based intrusion detection

Detection of:
SYN Flood attacks
Repeated failed TCP handshakes
Unusual protocol usage
Blacklisted IP traffic
Alert deduplication with configurable thresholds
Web-based dashboard using Flask
Clean, modular architecture

🛠️ Tech Stack
Component	Technology
Language	Python
Packet Capture	Scapy
Backend	Flask
Visualization	Chart.js
Platform	Linux / Kali Linux
🧠 Detection Logic Overview

1. SYN Flood Detection
Identifies excessive TCP SYN packets without corresponding ACKs, indicating a possible denial-of-service attempt.

2. Repeated Failed TCP Handshakes
Detects repeated incomplete TCP handshakes commonly associated with scanning or brute-force activity.

3. Unusual Protocol Usage
Flags abnormal protocol behavior outside standard TCP/UDP traffic patterns.

4. Blacklisted IP Detection
Immediately raises alerts for traffic originating from known malicious IP addresses.

🗂️ Project Structure
network-traffic-monitor/
│
├── app.py                 # Flask dashboard server
├── packet_sniffer.py      # Live packet capture module
├── detector.py            # IDS detection engine
│
├── templates/
│   └── dashboard.html     # Web dashboard UI
│
├── static/
│   └── charts.js          # Chart.js visualizations
│
└── README.md

⚙️ Installation & Setup (Kali Linux)

⚠️ Packet sniffing requires root privileges and a Linux environment.

1. Install System Dependencies
sudo apt update
sudo apt install -y python3-pip libpcap-dev tcpdump

2. Install Python Dependencies
pip3 install flask scapy pyshark

3. Verify Scapy Installation
python3 -c "from scapy.all import sniff"


(No warnings = ready)

▶️ Running the Application
Start the Dashboard & Sniffer
sudo python3 app.py

Access the Dashboard

Open a browser inside Kali:
http://127.0.0.1:5000

🧪 Testing Traffic Detection
Generate traffic in another terminal:

ping google.com

Alerts will appear when suspicious thresholds are crossed.
