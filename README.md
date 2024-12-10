# Packet Sniffer in Python
### This is a simple packet sniffer written in Python that captures and analyzes network traffic on a local machine. It uses the socket library to create raw sockets and parses Ethernet frames, IPv4 packets, ICMP messages, TCP segments, and UDP segments to extract and display relevant information.

## 🛠️ Features
- **Captures raw packets from the network interface.**
- **Parses Ethernet frames to extract:**
  - Destination MAC address
  - Source MAC address
  - Protocol
- **Decodes IPv4 packets to show:**
  - Version
  - Header length
  - Time-to-Live (TTL)
  - Protocol
  - Source and destination IP addresses
- **Supports common protocols:**
  - ICMP (type, code, checksum, and payload)
  - TCP (source/destination ports, sequence number, flags, and payload)
  - UDP (source/destination ports, packet size, and payload)
  - Displays data in a user-friendly, multi-line format.

## ⚙️ Prerequisites
- Python 3.6+ is required.
- The script must be run with administrator/root privileges because raw sockets require elevated permissions.
- Ensure the appropriate network interface is available for packet capture.

## 📥 Installation
Clone the repository:

```bash
git clone https://github.com/Heaven229-c/Packet-Sniffer---Simple-Tool.git
cd Packet-Sniffer---Simple-Tool
```
Run the script:

```bash
sudo python3 packet_sniffer.py
```

## 🚀 Usage
- The script starts capturing packets immediately upon execution.
- An example of output for captured packets:
  Ethernet Frame:

  ```yaml
  Destination: 00:0C:29:69:D7:17, Source: 00:50:56:E5:32:56, Protocol: 8
       - IPv4 Packet:
               - Version: 4, Header Length: 20, TTL: 128
               - Protocol: 6, Source: 152.195.38.76, Target: 192.168.209.141
       - TCP Segment:
               - Source Port: 80, Destination Port: 41108
               - Sequence: 925970678, Acknowledgment: 1235688912
               - Flags:
                       - URG: 0, ACK: 1, PSH: 0, RST: 0, SYN: 0, FIN: 0
  ```
## 📜 License
This project is licensed under the MIT License.



