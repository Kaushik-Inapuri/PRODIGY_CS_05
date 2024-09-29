pip install scapy
from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    """
    Analyze captured packet and extract information.
    """
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Identify protocol
        if protocol == 6:  # TCP
            proto_name = "TCP"
            payload = packet[TCP].payload
        elif protocol == 17:  # UDP
            proto_name = "UDP"
            payload = packet[UDP].payload
        elif protocol == 1:  # ICMP
            proto_name = "ICMP"
            payload = packet[ICMP].payload
        else:
            proto_name = "OTHER"
            payload = None

        print(f"Packet: {src_ip} --> {dst_ip} | Protocol: {proto_name}")
        if payload:
            print(f"Payload: {bytes(payload)}")
        print("-" * 80)

def packet_sniffer(interface=None):
    """
    Capture network packets on the specified interface.
    """
    print("Starting packet sniffer... (Press Ctrl+C to stop)")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    # Interface to capture packets from, e.g., 'eth0', 'wlan0' on Linux, or None for default
    interface = None
    try:
        packet_sniffer(interface)
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")
    except PermissionError:
        print("Permission denied. Please run with elevated privileges (e.g., sudo).")
