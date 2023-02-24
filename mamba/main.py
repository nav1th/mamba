#!/usr/bin/python3.10
import msg as m # custom messages
import args # arguments in program
from colorama import Fore, Back, Style
import scapy.all as s
import scapy.layers.l2 as layer2
import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.http
import json

from collections import Counter
import os.path


def good_colour_file(json) -> bool: 
    acceptable_colours = ["YELLOW", "RED", "BLUE", "CYAN", "MAGENTA", "GREEN", "WHITE", "BLACK"]
    for i in json['protocols']:
        if i['FG'] not in acceptable_colours:
            return False
        if i['BG'] != None and i['BG'] not in acceptable_colours:
            return False
    return True 

def insert_src_dst_pairs(src, dst, counter):
    key = tuple(sorted([src,dst])) #bundles src and dst together
    counter.update(key) #updates amount of pairs 

def proc_pkt(pkt): #handles packets depending on protocol
    ##possible address types
    ether_src = None
    ether_dst = None  
    ip_src = None
    ip_dst = None
    ipv6_src = None
    ipv6_dst = None
  


    if layer2.Ether in pkt:  ## grab ethernet info if any
        ether_src = pkt[layer2.Ether].src 
        ether_dst = pkt[layer2.Ether].dst  
        insert_src_dst_pairs(ether_src,ether_dst,pairs_ether)
        
    if inet.IP in pkt: # grab ipv4 info if any
        ip_src = pkt[inet.IP].src
        ip_dst = pkt[inet.IP].dst
        insert_src_dst_pairs(ip_src,ip_dst,pairs_ipv4)
       
    if inet6.IPv6 in pkt: # grab ipv6 info if any
        ipv6_src = pkt[inet6.IPv6].src
        ipv6_dst = pkt[inet6.IPv6].dst
        insert_src_dst_pairs(ip_src,ip_dst,pairs_ipv6)

    if layer2.ARP in pkt: #ARP       
        arp = pkt[layer2.ARP] 
        if colour:
            if colour_json:
                ARP_fg = "json magic fg"
                ARP_bg = "json magic bg"
            else:  #default colours
                ARP_fg = Fore.YELLOW
                ARP_bg = None
            print(f"{ARP_fg}{packet_count:6} | {ether_src} ==> {ether_dst}",end=" | ")
            if arp.op == 1:  #ARP who-has da MAC for this IP
                print(f"ARP: {arp.psrc} is asking who has MAC for {arp.pdst}")
            elif arp.op == 2: #ARP here's your MAC
                print(f"ARP: {arp.hwsrc} is at {arp.psrc}{Style.RESET_ALL}")
        else:
            print(f"{packet_count:6} | {ether_src} ==> {ether_dst}",end=" | ")
            if arp.op == 1:  #ARP who-has da MAC
                print(f"ARP: {arp.psrc} is asking who has MAC for {arp.pdst}")
            elif arp.op == 2: #ARP I'm your man here's your MAC
                print(f"ARP: {arp.hwsrc} is at {arp.psrc}")
                
    if inet6.ICMPv6ND_RS in pkt: #discover routers on Ipv6 network with all routers multicast ff02::2
        rs = pkt[inet6.ICMPv6ND_RS]
        print(f"{packet_count} | {ipv6_src} ==> {ipv6_dst}", end=" | ")
    if scapy.layers.http.HTTPRequest in pkt: # HTTP Request
        req = pkt[scapy.layers.http.HTTPRequest]
        sport = pkt[inet.TCP].sport
        dport = pkt[inet.TCP].dport

        url = (req.Host+req.Path).decode()
        method = req.Method.decode()
        version = req.Http_Version.decode()
        key = tuple(sorted([ip_src, ip_dst])) #bundles ip src and dst together
        packet_count.update(key) #updates packet count
        print(f"{int(sum(packet_count.values()) /2):6} | {ip_src}:{sport} ==> {ip_dst}:{dport}",
        end="        | ")
        print(f"HTTP_VERSION: {version} | METHOD: {method} | URL: {url}")
        if show_raw and scapy.has_layer(s.Raw):
            print(f"\tRAW Data: {pkt[s.Raw]}")
        
#TODO HTTP Response
#TODO TCP HANDSHAKE (SYN, SYN-ACK, ACK)
#TODO SSH
#TODO TELNET
#TODO FTP
#TODO OTHER PROTOCOLS ALONG DE WAY
    packet_count+=1
        
if __name__ == "__main__":
    args = args.grab_args() #grab arguments from CLI input
    
    ##args from cli
    filter = args.filter # BPF option, filters packets according to user pref
    colour = args.colourless # determines if output is coloured, (stored as False when selected)
    write_pcap = args.write #if user wishes to write their packet capture to a file
    read_pcap = args.read #if user wishes to perform offline capture by reading 'pcap' file
    interface = args.interface #if user desires to select interface, otherwise first available will be selected for them
    count = args.count
    no_confirm = args.no_confirm
    show_raw = args.show_raw
    if not interface:
        interface = s.conf.iface
    ##


    if colour: #TODO colour will be last thing to worry about
       try: 
           f = open("colour.json")
           colour_json = json.load(f)
           good_colour_file(colour_json)
       except:
           m.warn("user defined colour rules could not be opened. using default scheme",colour)
           colour_json = False # colour.json file, if false it either can't be read or doesn't exist
       else:
           f.close()


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


    packet_count = 1 #count the number of packets captured
    pairs_ipv4 = Counter() 
    pairs_ipv6 = Counter()
    pairs_ether = Counter()

    if read_pcap:
        try: 
            capture = s.sniff(prn=proc_pkt,offline=read_pcap,filter=args.filter,count=args.count) 
            #TODO print better output if filter is wrong
        except OSError as e:
           m.err(f"failed to read from '{write_pcap}' due to '{e.strerror.lower()}'",colour)
        else:
            if write_pcap: 
                s.wrpcap(write_pcap,capture)
    else: #must be interface being used then
        try: 
            capture = s.sniff(prn=proc_pkt,iface=interface,filter=args.filter,count=args.count)
            #TODO print better output if filter is wrong
        except OSError as e:
           m.err(f"failed to sniff on {interface} due to '{e.strerror.lower()}'",colour)
           exit(e.errno)
        else:
            if write_pcap: 
                s.wrpcap(write_pcap,capture)

