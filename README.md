# replay

Simple python script that uses Scapy for replaying intercepted network traffic from a pcap file.

### Just install scapy, then provide a pcap file to the script while running it as argument!
```py
$ git clone https://github.com/profxadke/reply && cd replay
$ virtualenv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
$ python3 ./main.py traffic_dump.pcapng
$ deactivate
```

---

```
replay

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
```
