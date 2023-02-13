#!/usr/bin/python3.10
import msg as m # custom messages
import args # arguments in program
import scapy.all as s
import scapy.layers.l2 as layer2
import scapy.layers.inet as ipv4
import scapy.layers.inet6 as ipv6
import scapy.layers.http
from collections import Counter


def proc_pkt(pkt): #handles sniffed packets
    num : int = 0
    if pkt.haslayer(layer2.ARP):
        ether_src = pkt[layer2.Ether].src
        ether_dst = pkt[layer2.Ether].dst
        arp = pkt[layer2.ARP]

        key = tuple(sorted([ether_src, ether_dst])) #bundles ether src and dst together
         
        packet_count.update(key) #updates packet count
        print(f"#{int(sum(packet_count.values()) /2)} | {ether_src} ==> {ether_dst}",
        end=" | ")
        if arp.op == 1:  #ARP who-has da MAC
            print(f"ARP: {arp.psrc} is asking who has MAC for {arp.pdst}")
        elif arp.op == 2: #ARP I'm your man here's your MAC
            print(f"ARP: {arp.hwsrc} is at {arp.psrc}")

''' #HTTP Request
    if pkt.haslayer(scapy.layers.http.HTTPRequest): 
        req = pkt[scapy.layers.http.HTTPRequest]
        ip_src = pkt[ipv4.IP].src
        ip_dst = pkt[ipv4.IP].dst
        url = (req.Host+req.Path).decode()
        method = req.Method
        version = req.Version
        key = tuple(sorted([ip_src, ip_dst])) #bundles ip src and dst together
        packet_count.update(key) #updates packet count
        print(f"PKT: {num} | IP_SRC: {pkt[ipv4.IP].src} | IP_DST: {pkt[ipv4.IP].dst}",
        end=" | ")
        print(f"VERSION: {version} | METHOD: {method} URL: |{url}")
        packet_count.update([key])
'''

if __name__ == "__main__":
    args = args.grab_args()
    filter = args.filter # BPF option, filters packets according to user pref
    colour = args.colourless # Determines if output is coloured
    proto_col = False

    packet_count = Counter()

    if args.interface:
        interface = args.interface # Interface specified by user
    else:
        interface = s.conf.iface # First interface detected by Scapy

    if colour: 
        try: 
            proto_col = open("../colour2.json", "r")
        except:
            pass

    try: 
        capture = s.sniff(prn=proc_pkt,iface=interface,filter=args.filter,count=0) #sends packets to callback function 'proc_pkt' to be processed
        if args.write:
            s.wrpcap(args.output,capture)
    except (PermissionError, OSError) as e:
       m.err(f"could not sniff on {interface} due to '{e.strerror.lower()}'",colour)
    finally:
       if proto_col:
           proto_col.close()
