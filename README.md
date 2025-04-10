Usage Instructions

Prerequisites:

Run on Kali Linux with Scapy installed (typically pre-installed).

Execute with root privileges (sudo) due to raw packet access.



Running the Tool:

sudo python3 intrusion_detector.py -i eth0 -t 10 -p 10

-i eth0: Sniff on interface eth0 (replace with your interface).

-t 10: Set time window to 10 seconds.

-p 10: Alert if more than 10 unique ports are scanned.



Example Output:

If a port scan occurs (e.g., via nmap -sS <target_ip> from another system):

Starting intrusion detection...

Possible port scan from 192.168.1.100 to 192.168.1.101: 15 ports in last 10 seconds



Features and Limitations

Key Features:

Simple and Lightweight: Easy to deploy and understand, ideal for educational use or small networks.

Configurable: Adjustable interface, time window, and port threshold.

Real-Time Detection: Processes packets as they arrive, providing immediate alerts.



Limitations:

Scope: Only detects TCP SYN-based port scans; other intrusions (e.g., SQL injection) require additional rules.

Performance: Python and Scapy may struggle with high-speed networks; a C-based tool (e.g., using libpcap directly) would be faster.

False Positives: Legitimate multi-port activity might trigger alerts if thresholds are too low.

Directionality: Doesn’t distinguish between incoming and outgoing scans.



Testing the Tool


To verify functionality:

Run the tool on Kali Linux:

sudo python3 intrusion_detector.py -i eth0

From another machine, perform a port scan:

nmap -sS <kali_ip>

Check the console for alerts indicating detected port scans.
