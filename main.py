#!/usr/bin/env python3


from scapy.packet import Packet
from docopt import docopt
from scapy.all import (
    rdpcap, sendp, Ether,
    IP, TCP, UDP, Raw, conf
); __version__ = '0.1.1'


def reconstruct_packet(pkt: Packet, spoofed_ip: str = ''):
    """
    Reconstruct a packet by creating new layer objects with the same attributes as the original.
    Optionally spoof the source IP address.

    Parameters:
        pkt (scapy.packet.Packet): The original packet to reconstruct.
        spoofed_ip (str): The IP address to spoof as the source. If None, use the original source IP.

    Returns:
        scapy.packet.Packet or None: A new packet object constructed from the original layers. 
                                     Returns None if the Ethernet layer is missing.
    """
    if Ether not in pkt:
        raise ValueError("Packet missing Ethernet layer.")

    layers = [Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)]

    if IP in pkt:
        src_ip = spoofed_ip if spoofed_ip else pkt[IP].src
        ip = IP(src=src_ip, dst=pkt[IP].dst, proto=pkt[IP].proto, tos=pkt[IP].tos,
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


def main(iface: str = '', pcap_file_path: str = '', spoofed_ip: str = ''):
    '''replay

Simple python script that uses Scapy for replaying intercepted network traffic from a pcap file.

Usage:
    main.py <pcap_file_path>
    main.py [--iface=<iface>|-i=<iface>] [--spoofed_ip=<spoofed_ip>|-s=<spoofed_ip>] <pcap_file_path>
    main.py (-h | --help)
    main.py (-v | --version)

Options:
  -i=<iface> --iface=<iface>    Specify an interface to replay the packets on.
  -s=<spoofed_ip> --spoofed_ip=<spoofed_ip>    Specify a source IP address to spoof.
  -h --help     Show this screen.
  -v --version     Show version.

    '''
    if iface:
        conf.iface = iface
    if pcap_file_path:
        packets = rdpcap(pcap_file_path)
        print(f"[+] Loaded {len(packets)} packets from {pcap_file_path}")
        for pkt in packets:
            try:
                # Filter out TCP packets with the ACK flag set
                if TCP in pkt and pkt[TCP].flags & 0x10:
                    continue

                new_pkt = reconstruct_packet(pkt, spoofed_ip)
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
    args = docopt(main.__doc__, version=__version__)
    _keys = tuple(args.keys())
    if '<pcap_file_path>' in _keys and '--iface' in _keys and '--spoofed_ip' in _keys:
        main(args['--iface'], args['<pcap_file_path>'], args['--spoofed_ip'])
    elif '<pcap_file_path>' in _keys and '--iface' not in _keys and '--spoofed_ip' in _keys:
        main(args['<pcap_file_path>'], spoofed_ip=args['--spoofed_ip'])
    elif '<pcap_file_path>' in _keys and '--iface' in _keys and '--spoofed_ip' not in _keys:
        main(args['--iface'], args['<pcap_file_path>'])
    elif '<pcap_file_path>' in _keys and '--iface' not in _keys and '--spoofed_ip' not in _keys:
        main(args['<pcap_file_path>'])
    else:
        print(main.__doc__)
        exit(1)
