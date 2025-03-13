from scapy.all import ARP, Ether, IP, ICMP, Raw, sendp, sniff, sys
import netifaces as ni
import logging

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

interface = "eth0"
local_ip = None
local_mac = None

def get_interface_ip_mac(interface):
    global local_ip, local_mac
    try:
        addrs = ni.ifaddresses(interface)
        if ni.InterfaceType.AF_PACKET in addrs:
            local_mac = addrs[ni.InterfaceType.AF_PACKET][0]['addr']
        if ni.InterfaceType.AF_INET in addrs:
            local_ip = addrs[ni.InterfaceType.AF_INET][0]["addr"]
    except (KeyError, IndexError):
        logger.error("Can't get interface %s IP or MAC address.", interface)
    
def arp_reply(pkt):
    if ARP in pkt and pkt[ARP].op == 1:
        arp_response = ARP(
            op=2,
            hwsrc=local_mac,
            psrc=pkt[ARP].pdst,
            hwdst=pkt[ARP].hwsrc,
            pdst=pkt[ARP].psrc
        )
        ether_response = Ether(
            src=local_mac,
            dst=pkt[Ether].src
        ) / arp_response

        sendp(ether_response, iface=interface, verbose=0)
        logger.info("Sent ARP reply to %s (%s)", pkt[ARP].psrc, pkt[Ether].src)

def icmp_reply(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        icmp = ICMP(type=0, code=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        icmp_response = ip/icmp/data
        ether_response = Ether(
            src=local_mac,
            dst=pkt[Ether].src
        ) / icmp_response
        sendp(ether_response, iface=interface, verbose=0)
        logger.info("Sent ICMP reply to %s", pkt[IP].src)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.info("Use default interface name eth0, or you can pass the interface name you want.")
    else:
        interface =sys.argv[1]

    get_interface_ip_mac(interface)
    logger.info("Starting ARP/ICMP responder on %s (IP: %s, MAC: %s...)", interface, local_ip, local_mac)
    sniff(filter="arp or icmp", prn=lambda x: arp_reply(x) or icmp_reply(x), iface=interface, store=0)