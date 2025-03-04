# NETWORK PACKET ANALYZER

## DESCRIPTION
This is a simple Network Packet Analyzer built using Python and the scapy library. It captures and analyzes network packets, displaying key details such as source and destination IP addresses, protocols, and payload data. This tool is designed strictly for educational and ethical use to help users understand network traffic and security concepts. Unauthorized packet sniffing is illegal and against ethical guidelines.

---
## Ethical Considerations
- Packet sniffing is illegal without proper authorization. Always obtain explicit permission before capturing network traffic.
- Use this tool strictly for educational, testing, and security auditing purposes.
- Avoid capturing personal information (e.g., login credentials, emails, financial details).
- Do not exploit network weaknesses for malicious intent.
- Perform packet analysis on a private, controlled network (e.g., a lab setup or authorized company network).
- Use it in a Safe, Controlled Environment (e.g., personal system, ethical hacking labs).
---

## Requirement

1. Installation of `scapy` library

```
pip install scapy
```

2. Installation of npcap: https://npcap.com/

    During installation:
    - Check "Install Npcap in WinPcap API-compatible Mode"
    - Check "Support raw 802.11 traffic"

    *After installation: Run the following command in cmd/powershell*

    ```
    python your_script.py -i "Wi-Fi" -c 10
    ```
3. *After verification: Run the final python script*
---

## How Does It Work?

**1. Capturing Network Packets**
   - The script uses `scapy.sniff()` to listen for incoming and outgoing network packets.

**2. Extracting Packet Information**
   - When a packet is detected, the `packet_callback()` function is triggered.
   - The script extracts:
       - Source IP Address – The sender of the packet.
       - Destination IP Address – The receiver of the packet.
       - Protocol – Identifies whether it's TCP, UDP, or other protocols.
       - Payload Data – Displays the first 50 bytes of the packet payload for analysis.

**3. Displaying Captured Data**
   - Each captured packet is printed in the format:
```
[+] Packet Captured: TCP | Src: 192.168.1.10 -> Dst: 192.168.1.20
    Payload: b'GET /index.html HTTP/1.1\\r\\nHost: example.com...'
```
   - The payload (if available) helps analyze HTTP requests, DNS queries, and other traffic types.

**4. Running the Sniffer**
   - The script starts sniffing upon execution.
   - It displays available network interfaces before capturing traffic.
   - Press Ctrl + C to stop the sniffer safely.

---

## Example Output
```
[*] Available network interfaces:
['Ethernet', 'Wi-Fi', 'Loopback Pseudo-Interface 1']

[*] Starting Packet Sniffer... Press Ctrl+C to stop.

[+] Packet Captured: TCP | Src: 192.168.1.100 -> Dst: 192.168.1.200
    Payload: b'GET /index.html HTTP/1.1\\r\\nHost: example.com...'

[+] Packet Captured: UDP | Src: 192.168.1.150 -> Dst: 8.8.8.8
    Payload: b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00...'

[+] Packet Captured: TCP | Src: 10.0.0.5 -> Dst: 192.168.1.1
    Payload: b'POST /login HTTP/1.1\\r\\nHost: securebank.com\\r\\nUser-Age...'

[+] Packet Captured: ICMP | Src: 192.168.1.50 -> Dst: 192.168.1.1
    Payload: b'\\x08\\x00\\xf7\\xfb\\x12\\x34\\x56\\x78...'

[+] Packet Captured: TCP | Src: 192.168.1.75 -> Dst: 93.184.216.34
    Payload: b'HTTP/1.1 200 OK\\r\\nContent-Type: text/html...'
```

