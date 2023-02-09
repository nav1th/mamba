#!/usr/bin/python3.10
import msg as m # custom messages
import args # arguments in program
import scapy.all as s
import scapy.layers.l2 as layer2
import scapy.layers.inet as ipv4
import scapy.layers.inet6 as ipv6
import scapy.layers.http
import json



def callback(pkt):
    if pkt.haslayer(layer2.ARP):
        if pkt.haslayer(layer2.Ether):
            print(f"ETHER_SRC: {pkt[layer2.Ether].src} | ETHER_DST: {pkt[layer2.Ether].dst}",end=" ")
            print(f"ARP: {pkt[layer2.ARP].mysummary()}")
    if pkt.haslayer(scapy.layers.http.HTTPRequest):
        if pkt.haslayer(scapy.layers.http)
        print("http")


if __name__ == "__main__":
    args = args.grab_args()

    if args.interface:
        interface = args.interface
    else:
        interface = s.conf.iface

    colour = not args.colourless

    try: 
        handle = s.sniff(prn=callback,iface=args.interface,filter=args.filter,count=0)
    except (PermissionError, OSError) as e:
       m.err(f"could not sniff on {interface} due to '{e.strerror.lower()}'",colour)
    except KeyboardInterrupt: 
        m.info("Program shutdown requested.",colour)
        m.info("Quitting...",colour)
        exit(0)
