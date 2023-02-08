#!/usr/bin/python3.10
from os import wait
import msg as m # custom messages
import args # arguments in program
import scapy.all as s
import scapy.layers.l2 as l2
import scapy.layers.inet as ipv4

def get_p_layers(pkt):
    cnt = 0
    while True:
        layer = pkt.getlayer(cnt)
        if layer is None:
            break
        yield layer
        cnt += 1

def callback(pkt):
    tcpip = pkt.layers()
    match tcpip[0]: # layer 2 traffic
        case l2.Ether: #if l2 is 802.3
            print(tcpip[0])
        case l2.ARP: #if l2
            pass
    
    

    


if __name__ == "__main__":
    args = args.grab_args()

    if args.interface:
        interface = args.interface
    else:
        interface = s.conf.iface

    colour = not args.colourless

    try: 
        handle = s.sniff(prn=callback,iface=args.interface,filter=args.filter,count=1)
    except (PermissionError, OSError) as e:
       m.err(f"could not sniff on {interface} due to '{e.strerror.lower()}'",colour)
    except KeyboardInterrupt: 
        m.info("Shutdown requested.",colour)
        m.info("Quitting...",colour)
        exit(0)
