# arp_poison_beta
Very roughly written arp poisoning script with scapy for my own knowledge 

Wanted to try to improve on my own scapy, python and knowledge of networking, so I tried to implement a version of arp poisoning without using the scapy in built function of arpcachepoison

this script (in theory!) is supposed to:
1. use ARP ping to get a list of all devices on the network as well as their IP address and MAC address pairs
2. Asks user to select a device/IP address to poison (target to poison)
3. Then asks a user to select a device/IP on the netowrk to spoof as

It currently runs for a fixed duration, then runs a function to restore the ARP cache with the original MAC address. This can be improved!
