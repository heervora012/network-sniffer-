🔍 Enhanced Network Sniffer
A powerful Python-based network packet sniffer built with Scapy. Captures, parses, and analyzes live network traffic across multiple protocol layers — with real-time statistics and optional JSON export.
⚠️ For educational and authorized use only. Always ensure you have permission before sniffing network traffic.
✨ Features
• Multi-layer packet parsing — Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS
• BPF filter support — target specific traffic (e.g., tcp port 80, dns, icmp)
• Real-time statistics — packet counts, byte totals, top IPs, top ports
• JSON export — save full capture data to a structured file
• Interface selection — specify a NIC or let it auto-detect
• Payload preview — shows first 100 bytes of TCP/UDP payloads
• Graceful interrupt — Ctrl+C stops capture and still prints stats
📋 Requirements
• Python 3.x
• Scapy
• Root / Administrator privileges (required for raw packet capture)
Install dependencies
pip install scapy
🚀 Usage
sudo python3 server.py [OPTIONS]
Options
Flag
Long Form
Description
Default
-n
--count
Number of packets to capture
10
-i
--interface
Network interface to sniff on
auto
-f
--filter
BPF filter string
none
-o
--output
Output file path (JSON format)
none
💡 Examples
Capture 50 packets:
sudo python3 server.py -n 50
Sniff on a specific interface with HTTP filter:
sudo python3 server.py -i eth0 -f "tcp port 80"
Capture 100 packets and save to JSON:
sudo python3 server.py -n 100 -o packets.json
Capture DNS traffic only:
sudo python3 server.py -f "dns"
Capture ICMP (ping) traffic:
sudo python3 server.py -f "icmp"
📊 Sample Output
######################################################################
# Network Sniffer Started
# Capturing 10 packets...
# Press Ctrl+C to stop
######################################################################

======================================================================
Packet #1 - 2025-10-30 14:22:01
Packet Size: 74 bytes
======================================================================

[Ethernet Layer]
  Source MAC: aa:bb:cc:dd:ee:ff
  Destination MAC: 11:22:33:44:55:66
  Type: 2048

[IP Layer (IPv4)]
  Source IP: 192.168.1.5
  Destination IP: 8.8.8.8
  Protocol: 17
  TTL: 64
  ...

######################################################################
# NETWORK STATISTICS
######################################################################

Total Packets: 10
Total Bytes: 820 bytes
Average Packet Size: 82.00 bytes

Packet Types:
  ARP:  0
  IPv4: 9
  IPv6: 1
  TCP:  5
  UDP:  3
  ICMP: 1
  DNS:  2

Top Source IPs:
  192.168.1.5: 7 packets
  192.168.1.1: 2 packets
🗂 JSON Output Format
When -o is specified, packet data is saved in this structure:
{
  "capture_time": "2025-10-30T14:22:01.123456",
  "statistics": {
    "total_packets": 10,
    "total_bytes": 820,
    "tcp_packets": 5,
    "udp_packets": 3,
    "src_ips": { "192.168.1.5": 7 },
    "dst_ports": { "443": 4 }
  },
  "packets": [
    {
      "packet_num": 1,
      "timestamp": "2025-10-30T14:22:01.123456",
      "size": 74,
      "layers": [
        { "type": "Ethernet", "src_mac": "...", "dst_mac": "..." },
        { "type": "IPv4", "src_ip": "...", "dst_ip": "...", "ttl": 64 },
        { "type": "TCP", "src_port": 54321, "dst_port": 443, "flags": "SYN" }
      ]
    }
  ]
}
🛡️ Supported Protocols
Layer
Protocols
Layer 2
Ethernet, ARP
Layer 3
IPv4, IPv6
Layer 4
TCP, UDP, ICMP
Application
DNS
⚙️ How It Works
1. Scapy opens a raw socket on the specified (or auto-detected) interface.
2. Each captured packet is passed to parse_packet(), which walks through its layers.
3. Layer-specific parsers extract fields and update running statistics.
4. After capture ends (by count or Ctrl+C), statistics are printed and optionally saved to JSON.
⚠️ Legal & Ethical Notice
Packet sniffing may be illegal without authorization. Only use this tool on:
• Your own network
• Networks you have explicit permission to test
• Controlled lab environments
This tool is intended for educational purposes, network diagnostics, and authorized security research.
📄 License
MIT License — feel free to use and modify with attribution.
