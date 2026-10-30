#!/usr/bin/env python3
"""
Enhanced Network Sniffer
Captures, analyzes, and logs network packets with advanced filtering and statistics
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, IPv6, Ether
from datetime import datetime
from collections import defaultdict
import sys
import json
import argparse

class NetworkSniffer:
    def __init__(self, packet_count=10, iface=None, filter_str="", output_file=None):
        """
        Initialize the sniffer
        packet_count: number of packets to capture
        iface: network interface (None = auto-select)
        filter_str: BPF filter string (e.g., "tcp port 80")
        output_file: optional file to save packet data
        """
        self.packet_count = packet_count
        self.iface = iface
        self.filter_str = filter_str
        self.output_file = output_file
        self.packet_num = 0
        
        # Statistics tracking
        self.stats = {
            'total_packets': 0,
            'arp_packets': 0,
            'ipv4_packets': 0,
            'ipv6_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'dns_packets': 0,
            'total_bytes': 0,
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'src_ports': defaultdict(int),
            'dst_ports': defaultdict(int),
            'protocols': defaultdict(int)
        }
        
        self.packet_data = []
    
    def parse_packet(self, packet):
        """Parse and display packet information"""
        self.packet_num += 1
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += len(packet)
        
        print(f"\n{'='*70}")
        print(f"Packet #{self.packet_num} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Packet Size: {len(packet)} bytes")
        print(f"{'='*70}")
        
        packet_info = {
            'packet_num': self.packet_num,
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'layers': []
        }
        
        # Layer 2 - Ethernet
        if packet.haslayer(Ether):
            self.parse_ethernet(packet, packet_info)
        
        # Layer 2 - ARP
        if packet.haslayer(ARP):
            self.parse_arp(packet, packet_info)
            self.stats['arp_packets'] += 1
        
        # Layer 3 - IP
        if packet.haslayer(IP):
            self.parse_ip(packet, packet_info)
            self.stats['ipv4_packets'] += 1
            
            # Track source and destination IPs
            ip_layer = packet[IP]
            self.stats['src_ips'][ip_layer.src] += 1
            self.stats['dst_ips'][ip_layer.dst] += 1
            self.stats['protocols'][ip_layer.proto] += 1
            
            # Layer 4 - Transport
            if packet.haslayer(TCP):
                self.parse_tcp(packet, packet_info)
                self.stats['tcp_packets'] += 1
            elif packet.haslayer(UDP):
                self.parse_udp(packet, packet_info)
                self.stats['udp_packets'] += 1
            elif packet.haslayer(ICMP):
                self.parse_icmp(packet, packet_info)
                self.stats['icmp_packets'] += 1
        
        # Layer 3 - IPv6
        if packet.haslayer(IPv6):
            self.parse_ipv6(packet, packet_info)
            self.stats['ipv6_packets'] += 1
        
        # Display raw packet summary
        print(f"\nPacket Summary: {packet.summary()}")
        
        self.packet_data.append(packet_info)
    
    def parse_ethernet(self, packet, packet_info):
        """Parse Ethernet frame information"""
        eth = packet[Ether]
        print(f"\n[Ethernet Layer]")
        print(f"  Source MAC: {eth.src}")
        print(f"  Destination MAC: {eth.dst}")
        print(f"  Type: {eth.type}")
        
        packet_info['layers'].append({
            'type': 'Ethernet',
            'src_mac': eth.src,
            'dst_mac': eth.dst,
            'eth_type': eth.type
        })
    
    def parse_arp(self, packet, packet_info):
        """Parse ARP (Address Resolution Protocol) packets"""
        arp_layer = packet[ARP]
        operation = 'Request' if arp_layer.op == 1 else 'Reply' if arp_layer.op == 2 else 'Other'
        
        print(f"\n[ARP Layer]")
        print(f"  Operation: {arp_layer.op} ({operation})")
        print(f"  Source MAC: {arp_layer.hwsrc}")
        print(f"  Source IP: {arp_layer.psrc}")
        print(f"  Dest MAC: {arp_layer.hwdst}")
        print(f"  Dest IP: {arp_layer.pdst}")
        
        packet_info['layers'].append({
            'type': 'ARP',
            'operation': operation,
            'src_mac': arp_layer.hwsrc,
            'src_ip': arp_layer.psrc,
            'dst_mac': arp_layer.hwdst,
            'dst_ip': arp_layer.pdst
        })
    
    def parse_ip(self, packet, packet_info):
        """Parse IP layer information"""
        ip_layer = packet[IP]
        print(f"\n[IP Layer (IPv4)]")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Protocol: {ip_layer.proto}")
        print(f"  TTL: {ip_layer.ttl}")
        print(f"  Total Length: {ip_layer.len} bytes")
        print(f"  Fragment Offset: {ip_layer.frag}")
        print(f"  Flags: {ip_layer.flags}")
        
        packet_info['layers'].append({
            'type': 'IPv4',
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': ip_layer.proto,
            'ttl': ip_layer.ttl,
            'length': ip_layer.len
        })
    
    def parse_ipv6(self, packet, packet_info):
        """Parse IPv6 layer information"""
        ipv6_layer = packet[IPv6]
        print(f"\n[IP Layer (IPv6)]")
        print(f"  Source IP: {ipv6_layer.src}")
        print(f"  Destination IP: {ipv6_layer.dst}")
        print(f"  Next Header: {ipv6_layer.nxt}")
        print(f"  Hop Limit: {ipv6_layer.hlim}")
        print(f"  Payload Length: {ipv6_layer.plen} bytes")
        
        packet_info['layers'].append({
            'type': 'IPv6',
            'src_ip': ipv6_layer.src,
            'dst_ip': ipv6_layer.dst,
            'next_header': ipv6_layer.nxt,
            'hop_limit': ipv6_layer.hlim
        })
    
    def parse_tcp(self, packet, packet_info):
        """Parse TCP layer information"""
        tcp_layer = packet[TCP]
        flags_str = self.get_tcp_flags(tcp_layer.flags)
        
        print(f"\n[TCP Layer]")
        print(f"  Source Port: {tcp_layer.sport}")
        print(f"  Destination Port: {tcp_layer.dport}")
        print(f"  Sequence Number: {tcp_layer.seq}")
        print(f"  Acknowledgment: {tcp_layer.ack}")
        print(f"  Flags: {flags_str}")
        print(f"  Window Size: {tcp_layer.window}")
        
        # Track ports
        self.stats['src_ports'][tcp_layer.sport] += 1
        self.stats['dst_ports'][tcp_layer.dport] += 1
        
        packet_info['layers'].append({
            'type': 'TCP',
            'src_port': tcp_layer.sport,
            'dst_port': tcp_layer.dport,
            'seq': tcp_layer.seq,
            'ack': tcp_layer.ack,
            'flags': flags_str
        })
        
        # Check for DNS (port 53)
        if tcp_layer.dport == 53 or tcp_layer.sport == 53:
            self.parse_dns(packet, packet_info)
        
        # Display payload if present
        if packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
            if payload:
                print(f"  Payload Size: {len(payload)} bytes")
                print(f"  Payload (first 100 bytes): {payload[:100]}")
    
    def parse_udp(self, packet, packet_info):
        """Parse UDP layer information"""
        udp_layer = packet[UDP]
        print(f"\n[UDP Layer]")
        print(f"  Source Port: {udp_layer.sport}")
        print(f"  Destination Port: {udp_layer.dport}")
        print(f"  Length: {udp_layer.len} bytes")
        
        # Track ports
        self.stats['src_ports'][udp_layer.sport] += 1
        self.stats['dst_ports'][udp_layer.dport] += 1
        
        packet_info['layers'].append({
            'type': 'UDP',
            'src_port': udp_layer.sport,
            'dst_port': udp_layer.dport,
            'length': udp_layer.len
        })
        
        # Check for DNS (port 53)
        if udp_layer.dport == 53 or udp_layer.sport == 53:
            self.parse_dns(packet, packet_info)
            self.stats['dns_packets'] += 1
        
        # Display payload if present
        if packet[UDP].payload:
            payload = bytes(packet[UDP].payload)
            if payload:
                print(f"  Payload Size: {len(payload)} bytes")
                print(f"  Payload (first 100 bytes): {payload[:100]}")
    
    def parse_icmp(self, packet, packet_info):
        """Parse ICMP layer information (ping)"""
        icmp_layer = packet[ICMP]
        icmp_type_str = self.get_icmp_type(icmp_layer.type)
        
        print(f"\n[ICMP Layer]")
        print(f"  Type: {icmp_layer.type} ({icmp_type_str})")
        print(f"  Code: {icmp_layer.code}")
        print(f"  Checksum: {icmp_layer.chksum}")
        
        packet_info['layers'].append({
            'type': 'ICMP',
            'icmp_type': icmp_type_str,
            'code': icmp_layer.code,
            'checksum': icmp_layer.chksum
        })
    
    def parse_dns(self, packet, packet_info):
        """Parse DNS queries and responses"""
        try:
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                print(f"\n[DNS Layer]")
                print(f"  Transaction ID: {dns_layer.id}")
                print(f"  Is Response: {dns_layer.qr}")
                
                dns_info = {
                    'type': 'DNS',
                    'id': dns_layer.id,
                    'is_response': bool(dns_layer.qr),
                    'questions': [],
                    'answers': []
                }
                
                if dns_layer.qr == 0:  # Query
                    if dns_layer.qdcount > 0:
                        print(f"  Queries:")
                        for question in dns_layer.questions:
                            qname = question.qname.decode('utf-8', errors='ignore')
                            print(f"    - {qname}")
                            dns_info['questions'].append(qname)
                else:  # Response
                    print(f"  Answer Count: {dns_layer.ancount}")
                    if hasattr(dns_layer, 'an') and dns_layer.an:
                        for answer in dns_layer.an:
                            if hasattr(answer, 'rrname') and hasattr(answer, 'rdata'):
                                dns_info['answers'].append(str(answer.rdata))
                
                packet_info['layers'].append(dns_info)
        except Exception as e:
            print(f"  DNS parsing error: {e}")
    
    def get_tcp_flags(self, flags):
        """Convert TCP flags to readable format"""
        flag_names = []
        if flags & 0x20:
            flag_names.append('ACK')
        if flags & 0x10:
            flag_names.append('PSH')
        if flags & 0x08:
            flag_names.append('RST')
        if flags & 0x04:
            flag_names.append('SYN')
        if flags & 0x02:
            flag_names.append('FIN')
        if flags & 0x01:
            flag_names.append('URG')
        
        return ' | '.join(flag_names) if flag_names else 'NONE'
    
    def get_icmp_type(self, icmp_type):
        """Convert ICMP type to readable format"""
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            12: 'Parameter Problem',
            13: 'Timestamp',
            14: 'Timestamp Reply',
            15: 'Information Request',
            16: 'Information Reply'
        }
        return icmp_types.get(icmp_type, f'Unknown ({icmp_type})')
    
    def print_statistics(self):
        """Print network traffic statistics"""
        print(f"\n\n{'#'*70}")
        print(f"# NETWORK STATISTICS")
        print(f"{'#'*70}\n")
        
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"Total Bytes: {self.stats['total_bytes']} bytes")
        print(f"Average Packet Size: {self.stats['total_bytes'] / max(1, self.stats['total_packets']):.2f} bytes\n")
        
        print("Packet Types:")
        print(f"  ARP: {self.stats['arp_packets']}")
        print(f"  IPv4: {self.stats['ipv4_packets']}")
        print(f"  IPv6: {self.stats['ipv6_packets']}")
        print(f"  TCP: {self.stats['tcp_packets']}")
        print(f"  UDP: {self.stats['udp_packets']}")
        print(f"  ICMP: {self.stats['icmp_packets']}")
        print(f"  DNS: {self.stats['dns_packets']}\n")
        
        if self.stats['src_ips']:
            print("Top Source IPs:")
            for ip, count in sorted(self.stats['src_ips'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {ip}: {count} packets")
            print()
        
        if self.stats['dst_ips']:
            print("Top Destination IPs:")
            for ip, count in sorted(self.stats['dst_ips'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {ip}: {count} packets")
            print()
        
        if self.stats['src_ports']:
            print("Top Source Ports:")
            for port, count in sorted(self.stats['src_ports'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  Port {port}: {count} packets")
            print()
        
        if self.stats['dst_ports']:
            print("Top Destination Ports:")
            for port, count in sorted(self.stats['dst_ports'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  Port {port}: {count} packets")
    
    def save_to_file(self):
        """Save packet data to JSON file"""
        if self.output_file:
            try:
                # Convert defaultdict to regular dict for JSON serialization
                stats_copy = dict(self.stats)
                stats_copy['src_ips'] = dict(stats_copy['src_ips'])
                stats_copy['dst_ips'] = dict(stats_copy['dst_ips'])
                stats_copy['src_ports'] = dict(stats_copy['src_ports'])
                stats_copy['dst_ports'] = dict(stats_copy['dst_ports'])
                stats_copy['protocols'] = dict(stats_copy['protocols'])
                
                output_data = {
                    'capture_time': datetime.now().isoformat(),
                    'statistics': stats_copy,
                    'packets': self.packet_data
                }
                
                with open(self.output_file, 'w') as f:
                    json.dump(output_data, f, indent=2)
                
                print(f"\n[INFO] Packet data saved to: {self.output_file}")
            except Exception as e:
                print(f"\n[ERROR] Failed to save file: {e}")
    
    def start(self):
        """Start packet sniffing"""
        print(f"\n{'#'*70}")
        print(f"# Network Sniffer Started")
        print(f"# Capturing {self.packet_count} packets...")
        if self.filter_str:
            print(f"# Filter: {self.filter_str}")
        print(f"# Press Ctrl+C to stop")
        print(f"{'#'*70}\n")
        
        try:
            sniff(
                prn=self.parse_packet,
                iface=self.iface,
                store=False,
                count=self.packet_count,
                filter=self.filter_str if self.filter_str else None
            )
            print(f"\n{'#'*70}")
            print(f"# Capture Complete - {self.packet_num} packets captured")
            print(f"{'#'*70}\n")
        except PermissionError:
            print("\n[ERROR] This program requires root/Administrator privileges!")
            print("Run with: sudo python3 network_sniffer_enhanced.py")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n\n{'#'*70}")
            print(f"# Capture Stopped - {self.packet_num} packets captured")
            print(f"{'#'*70}\n")
        finally:
            self.print_statistics()
            self.save_to_file()


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Network Packet Sniffer with Statistics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 network_sniffer_enhanced.py -n 50
  sudo python3 network_sniffer_enhanced.py -i eth0 -f "tcp port 80"
  sudo python3 network_sniffer_enhanced.py -n 100 -o packets.json
  sudo python3 network_sniffer_enhanced.py -f "dns"
        """
    )
    
    parser.add_argument('-n', '--count', type=int, default=10, 
                        help='Number of packets to capture (default: 10)')
    parser.add_argument('-i', '--interface', type=str, default=None, 
                        help='Network interface to sniff on (optional)')
    parser.add_argument('-f', '--filter', type=str, default='', 
                        help='BPF filter string (e.g., "tcp port 80", "dns", "icmp")')
    parser.add_argument('-o', '--output', type=str, default=None, 
                        help='Output file for packet data (JSON format)')
    
    args = parser.parse_args()
    
    sniffer = NetworkSniffer(
        packet_count=args.count,
        iface=args.interface,
        filter_str=args.filter,
        output_file=args.output
    )
    sniffer.start()


if __name__ == '__main__':
    main()
