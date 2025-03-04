from scapy.all import sniff, IP, TCP, UDP, Raw

def analyze(packet):
    if not IP in packet: return
    
    ip = packet[IP]
    proto = {6: 'TCP', 17: 'UDP'}.get(ip.proto, 'Other')
    payload = bytes(packet[Raw].load).decode('utf-8', 'ignore') if Raw in packet else ''
    
    print(f"Source IP: {ip.src} | Destination IP: {ip.dst} | Protocol: {proto}")
    if payload: print(f"Payload: {payload[:100]}{'...' if len(payload)>100 else ''}")
    print('-' * 80)

if __name__ == "__main__":
    print("This tool is for educational purposes only.\nDo not use it on networks you don't own or have permission to monitor.")
    sniff(prn=analyze, count=10, store=0)