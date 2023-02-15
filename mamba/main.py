#!/usr/bin/python3.10
import msg as m # custom messages
import args # arguments in program
import scapy.all as s
import scapy.layers.l2 as layer2
import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.http
import errno
from collections import Counter
import os.path


def proc_pkt(pkt): #handles packets depending on protocol
    if layer2.ARP in pkt:
        ether_src = pkt[layer2.Ether].src #
        ether_dst = pkt[layer2.Ether].dst # 
        arp = pkt[layer2.ARP] # 

        key = tuple(sorted([ether_src, ether_dst])) #bundles ether src and dst together
         
        packet_count.update(key) #updates packet count
        print(f"{int(sum(packet_count.values()) /2):6} | {ether_src} ==> {ether_dst}",
        end=" | ")
        if arp.op == 1:  #ARP who-has da MAC
            print(f"ARP: {arp.psrc} is asking who has MAC for {arp.pdst}")
        elif arp.op == 2: #ARP I'm your man here's your MAC
            print(f"ARP: {arp.hwsrc} is at {arp.psrc}")


#TODO HTTP Request
''' 
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
    args = args.grab_args() #grab arguments from CLI input

    filter = args.filter # BPF option, filters packets according to user pref
    colour = args.colourless # Determines if output is coloured, (stored as False when selected)
    proto_colour = False
    write_pcap = args.write
    read_pcap = args.read
    interface = args.interface
    if not interface:
        interface = s.conf.iface


    if colour: 
        try: 
            proto_col = open("../colour.json", "r")
        except:
            m.warn("user defined colour rules could not be opened using default scheme",colour)

    if write_pcap:
        try:
            f = open(write_pcap,"x") # try to create new file that doesn't exist 
        except OSError as e_file_create: #if failed to create new file
            if e.errno == errno.EEXIST: #if file already exists
                try: 
                    pass
                except OSError as e_file_write:
                    pass
            else: #some other error
                m.err(f"could not write '{write_pcap}' due to '{e_file_create.strerror.lower()}'",colour)
                exit(e_file_create.errno)
        else:
            f.close()

    packet_count = Counter()
    try: 
        capture = s.sniff(prn=proc_pkt,iface=interface,filter=args.filter,count=args.count) #sends packets to callback function 'proc_pkt' to be processed
        if args.write:
            s.wrpcap(args.write,capture)
    except (PermissionError, OSError) as e:
       m.err(f"could not sniff on {interface} due to '{e.strerror.lower()}'",colour)
       exit(e.errno)
    finally:
        pass
