from scapy.all import *
import time
import argparse

from scapy.layers.inet import TCP, IP

# Global variables
data = {}  # Stores (src_ip, dst_ip) -> [(timestamp, dst_port), ...]
last_cleanup_time = time.time()
cleanup_interval = 5  # Seconds between cleanups

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Simple Intrusion Detection Tool for Kali Linux")
parser.add_argument("-i", "--interface", help="Network interface to sniff (e.g., eth0)", default=None)
parser.add_argument("-t", "--time-window", type=int, help="Time window for detection (seconds)", default=10)
parser.add_argument("-p", "--port-threshold", type=int, help="Max unique ports before alert", default=10)
args = parser.parse_args()

time_window = args.time_window
port_threshold = args.port_threshold


def cleanup_and_check():
    """Clean up old entries and check for port scans."""
    current_time = time.time()
    for key in list(data.keys()):
        # Keep only recent entries within time_window
        data[key] = [entry for entry in data[key] if current_time - entry[0] < time_window]
        if not data[key]:
            del data[key]  # Remove empty entries
            continue
        # Count unique ports in the recent time window
        recent_ports = set(entry[1] for entry in data[key])
        if len(recent_ports) > port_threshold:
            print(f"Possible port scan from {key[0]} to {key[1]}: "
                  f"{len(recent_ports)} ports in last {time_window} seconds")


def packet_handler(packet):
    """Process each captured packet."""
    global last_cleanup_time
    if packet.haslayer(TCP) and packet.haslayer(IP) and packet[TCP].flags & 0x02:  # TCP SYN flag
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        current_time = time.time()
        key = (src_ip, dst_ip)

        # Initialize list for new source-destination pairs
        if key not in data:
            data[key] = []
        data[key].append((current_time, dst_port))

        # Check if it's time to clean up and analyze
        if current_time - last_cleanup_time > cleanup_interval:
            cleanup_and_check()
            last_cleanup_time = current_time


# Start the tool
print("Starting intrusion detection...")
sniff(iface=args.interface, prn=packet_handler, filter="tcp", store=0)