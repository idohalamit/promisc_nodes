from scapy.all import *

__author__ = 'Ido Halamit'

"""
Premise:

1. for every node in the subnet:
       sendp an ARP frame with the wrong MAC, correct IP.
2.    sniff:
           if a node responds, it is currently sniffing too.
"""

WRONG_MAC = '11:22:33:44:55:66'
# in order to bypass a software filter on some systems, specific MACs (usually multicast)
# are needed. For detecting windows 10 nodes, this will do.
SUBNET_MASK = '255.255.255.0'   # idk how to get it


g_default_gateway = conf.route.route("0.0.0.0")[2]


def subnet_filter(pkt):
    """ Checks if a packet was sent from this subnet, by comparing IP bytes with DG IP bytes."""
    if IP not in pkt:
        return False
    dfgateway_bytes = g_default_gateway.split('.')
    mask_bytes = SUBNET_MASK.split('.')
    addr_bytes = pkt[IP].src.split('.')
    for b1,b2,b3 in zip(dfgateway_bytes, mask_bytes, addr_bytes):
        if not int(b1) & int(b2) == int(b3) & int(b2):
            return False
    return True


ip_addresses = set()
sniff(timeout=20, store=False, lfilter=subnet_filter, prn=lambda p:ip_addresses.add(p[IP].src))

def check_promisc(ip):
    frame = Ether(dst=WRONG_MAC)/ARP(pdst=ip)
    sendp(frame)
    response = sniff(count=1, timeout=1, lfilter=lambda p:ARP in p
        and p[ARP].op == 2                                          # is a reply?
        and p[ARP].hwdst == Ether().src )                             # is it targeted at me?

    # sniffs for an ARP reply packet
    if len(response) != 0:
        print(response[0][ARP].psrc)
    # if promiscuous, print IP source

for ip in ip_addresses:
    check_promisc(ip)
