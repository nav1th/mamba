#!/usr/bin/python3.10
import msg as m # custom messages
import args # arguments in program
import scapy.all as s
import scapy.layers.l2 as layer2
import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.http
from collections import Counter
import os.path



def proc_pkt(pkt): #handles packets depending on protocol
    if layer2.ARP in pkt:
        ether_src = pkt[layer2.Ether].src 
        ether_dst = pkt[layer2.Ether].dst  
        arp = pkt[layer2.ARP] 

        key = tuple(sorted([ether_src, ether_dst])) #bundles ether src and dst together
        packet_count.update(key) #updates packet count
        num_of_pkts = int(sum(packet_count.values()) / 2)
        if colour:
            if colour_file:
                ARP_col = "json magic"
            else: 
                ARP_col = "YELLOW"

            m.cprint(f"{num_of_pkts:6} | {ether_src} ==> {ether_dst}",
            colour,ARP_col)

            if arp.op == 1:  #ARP who has da MAC?
                m.cprint(f"ARP: {arp.psrc} is asking who has MAC for {arp.pdst}",colour,ARP_col)
            elif arp.op == 2: #ARP im your man here's your MAC
                m.cprint(f"ARP: {arp.hwsrc} is at {arp.psrc}",colour,ARP_col)
        else:
            print(f"{num_of_pkts:6} | {ether_src} ==> {ether_dst}",
            end=" | ")
            if arp.op == 1:  #ARP who-has da MAC
                print(f"ARP: {arp.psrc} is asking who has MAC for {arp.pdst}")
            elif arp.op == 2: #ARP I'm your man here's your MAC
                print(f"ARP: {arp.hwsrc} is at {arp.psrc}")
    
#TODO HTTP Request
    if pkt.haslayer(scapy.layers.http.HTTPRequest): 
        req = pkt[scapy.layers.http.HTTPRequest]
        ip_src = pkt[inet.IP].src
        ip_dst = pkt[inet.IP].dst
        url = (req.Host+req.Path).decode()
        method = req.Method.decode()
        version = req.Http_Version.decode()
        key = tuple(sorted([ip_src, ip_dst])) #bundles ip src and dst together
        packet_count.update(key) #updates packet count
        print(f"{int(sum(packet_count.values()) /2):6} | {ip_src} ==> {ip_dst}",
        end="        | ")
        print(f"HTTP_VERSION: {version} | METHOD: {method} | URL: {url}")
        packet_count.update([key])
#TODO HTTP Response
#TODO TCP HANDSHAKE (SYN, SYN-ACK, ACK)
#TODO SSH
#TODO TELNET
#TODO MANY MANY OTHER PROTOCOLS


        
if __name__ == "__main__":
    args = args.grab_args() #grab arguments from CLI input

    filter = args.filter # BPF option, filters packets according to user pref
    colour = args.colourless # determines if output is coloured, (stored as False when selected)
    write_pcap = args.write #if user wishes to write their packet capture to a file
    read_pcap = args.read #if user wishes to perform offline capture by reading 'pcap' file
    interface = args.interface #if user desires to select interface, otherwise first available will be selected for them
    count = args.count
    no_confirm = args.no_confirm
    if not interface:
        interface = s.conf.iface


    colour_file = False

    if colour: #TODO colour will be last thing to worry about
        try: 
            colour_file = open("../colour.json", "r")
            # proto_colour = magic json colours
        except:
            m.warn("user defined colour rules could not be opened. using default scheme",colour)
        else:
            colour_file.close()


    if write_pcap: #checks beforehand to avoid packet capture and discovering at the end you can't write the file
        if os.path.exists(write_pcap):
            if no_confirm: #user doesn't want to be prompted
                m.warn("'{write_pcap}' exists, will be overwritten",colour)
            else:
                if not m.warn_confirmed(f"'{write_pcap}' exists, it will be overwritten.",colour): #in case user accidently overwrites file
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
    else: #must be interface being used then
        try: 
            capture = s.sniff(prn=proc_pkt,iface=interface,filter=args.filter,count=args.count)
        except OSError as e:
           m.err(f"failed to sniff on {interface} due to '{e.strerror.lower()}'",colour)
           exit(e.errno)
        else:
            if write_pcap: 
                s.wrpcap(write_pcap,capture)
