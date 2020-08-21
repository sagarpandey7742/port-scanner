from logging import getLogger, ERROR
from scapy.all import *
import sys

getLogger("scapy.runtime").setLevel(ERROR)

SYN_ACK = 0x12
RST_ACK = 0x14

verbose = 0

if len(sys.argv) > 1 and sys.argv[1] == 'v':
    verbose = 1


def exit(n):
    print("\n[!] Exiting gracefully...")
    sys.exit(n)


def host_up(ip="127.0.0.1"):
    conf.verb = verbose
    conf.L3socket = L3RawSocket
    try:
        ping = sr1(IP(dst=ip) / ICMP())
        print("[*] Target is UP")
        return True
    except Exception:
        print("[*] Couldn't resolve host.")
        return False


def scan_port(port, target="127.0.0.1"):
    src_port = RandShort()
    try:
        conf.verb = verbose
        conf.L3socket = L3RawSocket
        SYN_ACK_packet = sr1(IP(dst=target) / TCP(sport=src_port, dport=port, flags='S'))
        pkt_flags = SYN_ACK_packet.getlayer(TCP).flags
        if pkt_flags == SYN_ACK:
            return True
        return False
    except KeyboardInterrupt:
        RST_pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="R")  # Built RST packet
        send(RST_pkt)
        return False
    # RST sent by default


def sniff_port(port, count, timeout=1):
    return sniff(filter='port {}'.format(port), count=count, timeout=timeout)
