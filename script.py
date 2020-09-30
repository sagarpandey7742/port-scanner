from logging import getLogger, ERROR
from scapy.all import *
import sys
from datetime import datetime
from time import strftime
from flask import Flask, render_template, request, jsonify


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


def sniff_port(port, count, timeout=1):     # Return dest ip
    
    def print_summary(pkt):
        if IP in pkt:
            ip_src=pkt[IP].src
            ip_dst=pkt[IP].dst
        if TCP in pkt:
            tcp_sport=pkt[TCP].sport
            tcp_dport=pkt[TCP].dport

            print(" IP src " + str(ip_src) + " TCP sport " + str(tcp_sport)) 
            print(" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))

            return [ip_src,tcp_sport, ip_dst, tcp_dport]
        return []

    lst = sniff(filter='port {}'.format(port), count=count, timeout=timeout, prn=print_summary)

    if not lst:
        return jsonify({"Error": "Invalid"})
    else:
        return jsonify(lst)

    # return sniff(filter='port {}'.format(port), count=count, timeout=timeout)

#
# try:
#     target = "127.0.0.1"
#     min_port = input("[*] Enter Minimum Port Number: ")
#     max_port = input("[*] Enter Maximum Port Number: ")
#
#     try:
#         if not (0 <= int(min_port) <= int(max_port) and int(max_port) >= 0):
#             print("\n[!] Invalid Range")
#             exit(1)
#
#     except Exception:
#         print("\n[!] Invalid Range")
#         exit(1)
#
#     ports = range(int(min_port), int(max_port) + 1)
#     start_clk = datetime.now()
#
#     host_up()
#
#     print("\n[*] Scanning started at {}\n".format(strftime("%H:%M:%S")))
#     for p in ports:
#         status = scan_port(target, p)
#         if status:
#             pkts = sniff(filter='port {}'.format(p), count=5, timeout=1)
#             print('Port {}:  Open'.format(p))
#             print(pkts)
#
#     stop_clk = datetime.now()
#     total_time = stop_clk - start_clk
#
#     print("\n[*] Finished Scanning.")
#     print("\n[*] Scanned {} ports in {}".format(len(ports), total_time))
#
# except KeyboardInterrupt:
#     print("\n[*] Shutdown requested.")
#     exit(1)
