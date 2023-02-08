#!/usr/bin/python3.10
from os import wait
import msg as m # custom messages
import args # arguments in program
import scapy.all as s
import scapy.layers.l2 as l2
import scapy.layers.inet as ipv4



def callback(pkt):
    tcpip = pkt.layers()
  #print(tcpip)
    layer2 = tcpip[0] 
    try: #ordinary packet structure
        net = tcpip[1]
        tran = tcpip[2]
        app = tcpip[3]
        print(f"SRC: {layer2.src.i2h(pkt,None)} | DST: {layer2.dst.i2h(pkt,None)}")
        print(f"IP_SRC: {net.src} | IP_DST: {net.dst}")
    except: #likely arp
        arp = tcpip[1]
        if arp == l2.ARP:
            pass


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
        m.info("Shutdown requested.",colour)
        m.info("Quitting...",colour)
        exit(0)
