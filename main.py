#!/usr/bin/env python3

from scapy.packet import Packet
from scapy.all import (
    rdpcap, sendp, Ether,
    IP, TCP, UDP, Raw, conf,
    RandInt, RandShort
); __version__ = '0.1.0'


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
TSA = 0x18
URG = 0x20
ECE = 0x40
CWR = 0x80


def reconstruct_packet(pkt: Packet):
    """
    Reconstruct a packet by creating new layer objects with the same attributes as the original.
    This function extracts the relevant layers (Ethernet, IP, TCP, UDP, Raw) from the original packet
    and creates new instances of these layers with updated attributes to make it appear as a fresh packet.

    Parameters:
        pkt (scapy.packet.Packet): The original packet to reconstruct.

    Returns:
        scapy.packet.Packet or None: A new packet object constructed from the original layers.
                                     Returns None if the Ethernet layer is missing.
    """
    if Ether not in pkt:
        raise ValueError("[-] Packet missing Ethernet layer.")

    layers = [Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)]

    if IP in pkt:
        ip = IP(src=pkt[IP].src, dst=pkt[IP].dst, proto=pkt[IP].proto, tos=pkt[IP].tos,
                len=pkt[IP].len, id=RandShort(), flags=pkt[IP].flags, frag=pkt[IP].frag,
                ttl=64, options=pkt[IP].options)  # Use a random IP ID and reset TTL
        layers.append(ip)

    if TCP in pkt:
        # Preserve the original flags and adjust sequence/ack numbers
        tcp_flags = pkt[TCP].flags
        seq = RandInt() if tcp_flags & SYN else pkt[TCP].seq
        ack = 0 if tcp_flags & SYN else pkt[TCP].ack
        
        tcp = TCP(sport=RandShort(), dport=pkt[TCP].dport, seq=seq,
                  ack=ack, dataofs=pkt[TCP].dataofs, reserved=pkt[TCP].reserved,
                  flags=tcp_flags, window=pkt[TCP].window, urgptr=pkt[TCP].urgptr,
                  options=pkt[TCP].options)  # Set random source port and sequence number
        layers.append(tcp)

    if UDP in pkt:
        udp = UDP(sport=RandShort(), dport=pkt[UDP].dport, len=pkt[UDP].len)
        layers.append(udp)

    if Raw in pkt:
        raw = Raw(load=pkt[Raw].load)
        layers.append(raw)

    return layers[0] / layers[1] / layers[2] if len(layers) > 2 else layers[0] / layers[1]


def main(iface: str = '', pcap_file_path: str = ''):
    '''replay

Simple python script that uses Scapy for replaying intercepted network traffic from a pcap file.

Usage:
    main.py <pcap_file_path>
    main.py [--iface=<iface>|-i=<iface>] <pcap_file_path>
    main.py (-h | --help)
    main.py (-v | --version)

Options:
  -i=<iface> --iface=<iface>    Specify an interface to reply the packets on.
  -h --help     Show this screen.
  -v --version     Show version.
    '''
    if iface:
        conf.iface = iface
    if pcap_file_path:
        packets = rdpcap(pcap_file_path)
        print(f"[+] Loaded {len(packets)} packets from {pcap_file_path}")

        # Sort packets by timestamp (if available)
        packets = sorted(packets, key=lambda pkt: pkt.time)

        for pkt in packets:
            try:
                # Filter out TCP packets with the ACK flag set
                if TCP in pkt and pkt[TCP].flags & SYN:
                    pass
                if TCP in pkt and pkt[TCP].flags & TSA:
                    pass
                elif TCP in pkt and pkt[TCP].flags & ACK:
                    print(f"[!] Ignoring pkt: {pkt.summary()} with ACK TCP flag.")
                    continue

                new_pkt = reconstruct_packet(pkt)
                if new_pkt is None:
                    print("[-] Skipping packet with missing Ethernet layer")
                    continue

                print(f"[!] Modified pkt info: {pkt.summary()}")
                print(pkt.show(dump=True), end='\n'*2)
                # Print detailed packet info
                print(f"[!] Sending pkt on {conf.iface}: {new_pkt.summary()}")
                print(new_pkt.show(dump=True))

                sendp(new_pkt, verbose=1)  # Use sendp for layer 2 packets (Ethernet)
                print("[+] Above packet sent.")
            except Exception as e:
                print(f"[-] Failed to send packet: {e}")
        print("[+] Replay complete.")


if __name__ == '__main__':
    args = __import__('docopt').docopt(main.__doc__, version=__version__)
    _keys = tuple(args.keys())
    if '<pcap_file_path>' in _keys and '--iface' in _keys:
        main(args['--iface'], args['<pcap_file_path>'])
    elif '<pcap_file_path>' in _keys and '--iface' not in _keys:
        main(args['<pcap_file_path>'])
    else:
        print(main.__doc__)
        exit(1)
