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
