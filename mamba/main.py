#!/usr/bin/python3.10
import msg as m # custom messages
import args # arguments in program
import scapy.all as s
import scapy.layers.l2 as layer2
import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.http
import argparse
from collections import Counter
import os.path


def proc_pkt(pkt): #handles packets depending on protocol
    if layer2.ARP in pkt:
        ether_src = pkt[layer2.Ether].src 
        ether_dst = pkt[layer2.Ether].dst  
        arp = pkt[layer2.ARP] 

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
    write_pcap = args.write
    read_pcap = args.read
    interface = args.interface
    count = args.count
    if not interface:
        interface = s.conf.iface


    proto_colour = False

    if colour: #TODO colour will be last thing to worry about
        try: 
            colour_file = open("../colour.json", "r")
            # proto_colour = magic json colours
        except:
            m.warn("user defined colour rules could not be opened using default scheme",colour)
        else:
            colour_file.close()


    if write_pcap: #checks beforehand to avoid packet capture and discovering at the end you can't write the file
        if os.path.exists(write_pcap) and  \
        (not m.warn_confirm(f"'{write_pcap}' exists, it will be overwritten.",colour)): #in case user accidently overwrites file
            m.info("understood, exiting...",colour)
            exit(0)
        else: #try to write capture
            try: 
                f = open(write_pcap,"w") #tests to see if pcap can be written
            except OSError as e:
                m.err(f"could not write '{write_pcap}' due to '{e.strerror.lower()}'",colour)
                exit(e.errno) # no point doing anything else if the user can't write a 'pcap' like they wanted
            else:
                f.close() # close file, so nothing messes up


    packet_count = Counter() # count the number of packets captured

    if read_pcap:
        try: 
            capture = s.sniff(prn=proc_pkt,offline=read_pcap,filter=args.filter,count=args.count)
        except OSError as e:
           m.err(f"failed to read from '{write_pcap}' due to '{e.strerror.lower()}'",colour)
        else:
            if write_pcap: 
                s.wrpcap(write_pcap,capture)
    else: #must be interface being activated then
        try: 
            capture = s.sniff(prn=proc_pkt,iface=interface,filter=args.filter,count=args.count)
        except OSError as e:
           m.err(f"failed to sniff on {interface} due to '{e.strerror.lower()}'",colour)
           exit(e.errno)
        else:
            if write_pcap: 
                s.wrpcap(write_pcap,capture)

