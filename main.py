#!/usr/bin/env python3


from scapy.packet import Packet
from docopt import docopt
from scapy.all import (
    rdpcap, sendp, Ether,
    IP, TCP, UDP, Raw, conf
); conf.iface = 'lo'


def reconstruct_packet(pkt: Packet):
    """
    Reconstruct a packet by creating new layer objects with the same attributes as the original.

    This function extracts the relevant layers (Ethernet, IP, TCP, UDP, Raw) from the original packet
    and creates new instances of these layers with the same attributes. This ensures that fresh objects
    are used for sending, which helps avoid issues with old checksums or other artifacts.

    Parameters:
        pkt (scapy.packet.Packet): The original packet to reconstruct.

    Returns:
        scapy.packet.Packet or None: A new packet object constructed from the original layers. 
                                 Returns None if the Ethernet layer is missing.
   """
    if Ether not in pkt:
        # print("[-] Skipping packet with missing Ethernet layer.")
        raise ValueError("Packet missing Ethernet layer.")

    layers = [Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)]

    if IP in pkt:
        ip = IP(src=pkt[IP].src, dst=pkt[IP].dst, proto=pkt[IP].proto, tos=pkt[IP].tos,
                len=pkt[IP].len, id=pkt[IP].id, flags=pkt[IP].flags, frag=pkt[IP].frag,
                ttl=pkt[IP].ttl, options=pkt[IP].options)
        layers.append(ip)

    if TCP in pkt:
        tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, seq=pkt[TCP].seq,
                  ack=pkt[TCP].ack, dataofs=pkt[TCP].dataofs, reserved=pkt[TCP].reserved,
                  flags=pkt[TCP].flags, window=pkt[TCP].window, urgptr=pkt[TCP].urgptr,
                  options=pkt[TCP].options)
        layers.append(tcp)

    if UDP in pkt:
        udp = UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport, len=pkt[UDP].len)
        layers.append(udp)

    if Raw in pkt:
        payload = Raw(pkt[Raw].load)
        layers.append(payload)

    new_pkt = layers[0]
    for layer in layers[1:]:
        new_pkt = new_pkt / layer

    return new_pkt


def main(pcap_file_path: str = ''):
    '''replay

Simple python script that uses Scapy for replaying intercepted network traffic from a pcap file.

Usage:
    main.py <pcap_file_path>
    main.py (-h | --help)
    main.py (-v | --version)

Options:
  -h --help     Show this screen.
  -v --version     Show version.

    '''
    if pcap_file_path:
        packets = rdpcap(pcap_file_path)
        print(f"[+] Loaded {len(packets)} packets from {pcap_file_path}")
        for pkt in packets:
            try:
                new_pkt = reconstruct_packet(pkt)
                if new_pkt is None:
                    print("[-] Skipping packet with missing Ethernet layer")
                    continue
                print(f"[!] Sending pkt on {conf.iface}: {new_pkt.summary()}")
                sendp(new_pkt, verbose=0)  # Use sendp for layer 2 packets (Ethernet)
                print("[+] Above packet sent.")
            except Exception as e:
                print(f"Failed to send packet: {e}")
        print("[+] Replay complete.")


if __name__ == '__main__':
    args = docopt(main.__doc__, version='0.0.1')
    if '<pcap_file_path>' in tuple(args.keys()):
        main(args['<pcap_file_path>'])
