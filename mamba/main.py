#!/usr/bin/env python3
from scapy.main import load_layer
import msg as m # custom messages
import args # arguments in program
from colorama import Fore, Back, Style
from scapy.all import sniff, Raw,wrpcap,conf
from scapy.layers.l2 import ARP, Ether
from  scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import  \
        IPv6, \
        ICMPv6ND_NA as NDP_NA, \
        ICMPv6ND_RA as NDP_RA, \
        ICMPv6ND_NS as NDP_NS, \
        ICMPv6ND_RS as NDP_RS
from scapy.layers.http import HTTP,HTTPRequest as HTTPReq,HTTPResponse as HTTPRes
from scapy.layers.tls.record import TLS
from scapy.layers.dns import DNS
import json

load_layer("tls")
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
    tcp_sport = None
    tcp_dport = None
    udp_sport = None
    udp_dport = None
    num_of_pkts: int = 0

    if Ether in pkt:  ## grab ethernet info if any
        ether_src = pkt[Ether].src 
        ether_dst = pkt[Ether].dst  
        insert_src_dst_pairs(ether_src,ether_dst,pairs_ether)
        
    if IP in pkt: # grab ipv4 info if any
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        insert_src_dst_pairs(ip_src,ip_dst,pairs_ipv4)
       
    if IPv6 in pkt: # grab ipv6 info if any
        ipv6_src = pkt[IPv6].src
        ipv6_dst = pkt[IPv6].dst
        insert_src_dst_pairs(ipv6_src,ipv6_dst,pairs_ipv6)
        if NDP_RS in pkt: #discover routers on Ipv6 network with all routers multicast ff02::2
            print(f"{num_of_pkts} | Router solication message: {ipv6_src} ==> {ipv6_dst}")
        if NDP_NA in pkt: #neighbour advertisement
            pass
        if NDP_RA in pkt: #router advertisement 
            pass
        if NDP_NS in pkt: #neighbour solicitation
            pass

    if TCP in pkt:
        tcp_sport = pkt[TCP].sport
        tcp_dport = pkt[TCP].dport

    if UDP in pkt:
        udp_sport = pkt[UDP].sport
        udp_dport = pkt[UDP].dport
        
    if ARP in pkt: #ARP       
        arp = pkt[ARP] 
        arp_fg = None
        arp_bg = None
        if colour:
            if colour_json:
                arp_fg = "json magic fg"
                arp_bg = "json magic bg"
            else:  #default colours
                arp_fg = Fore.MAGENTA
        if arp_fg:
            print(f"{arp_fg}",end="")
        if arp_bg:
            print(f"{arp_bg}",end="")
            
        print(f"ARP - {ether_src} ==> {ether_dst}",end="  | ")
        if arp.op == 1:  #ARP who has the MAC for this IP
            print(f"{arp.psrc} is asking who has MAC for {arp.pdst}")
        elif arp.op == 2: #ARP here's your MAC
            print(f"{arp.hwsrc} is at {arp.psrc}")
                
        if colour:
            print(f"{Style.RESET_ALL}",end="")
        

    
    if HTTP in pkt: 
        http_fg = None
        http_bg = None
        if colour:
            if colour_json:
                http_fg = "json magic fg"
                http_bg = "json magic bg"
            else:  #default colours
                http_fg = Fore.YELLOW
                http_bg = None
                
            if http_fg: #Adds foreground colours if desired
                print(f"{http_fg}",end="") #adds colouring here
            if http_bg: #Adds background colours if desired
                print(f"{http_bg}",end="")   

        if HTTPReq in pkt: # decode HTTP requests 
            req = pkt[HTTPReq]
            host = req.Host.decode()
            path = req.Host.decode()
            url = host+path# the location of website e.g. 'http://hello.com/register/login'
            method = req.Method.decode() #e.g method used in request e.g. 'GET' or 'POST'
            version = req.Http_Version.decode() # http version of request 'HTTP/1.1'
            print(f"HTTP - {ip_src}:{tcp_sport} ==> {ip_dst}:{tcp_dport}",
            end=" | ")
            print(f"VERSION: {version} | URL: {url} | METHOD: {method}")
            if Raw in pkt and verbose:
                print(f"\tRAW Data: {pkt[Raw].load}")
            print(Style.RESET_ALL,end="") # clears formatting if any regardless of show_raw
            
        if HTTPRes in pkt:
            res = pkt[HTTPRes]
            status = res.Status_Code.decode()
            reason = res.Reason_Phrase.decode()
            version = res.Http_Version.decode()
            status_code = f"{status}: '{reason}'" #Status code e.g '404: Not found'

            print(f"HTTP | {ip_src}:{tcp_sport} ==> {ip_dst}:{tcp_dport}",
            end=" | ")
            print(f"VERSION: {version} | STATUS: {status_code}")
            if Raw in pkt and verbose:
                print(f"\tRAW Data: {pkt[Raw].load}")

    if TLS in pkt:
        tls = pkt[TLS]
        version = tls.version
        if colour: 
            if colour_json:
                TLS_fg = "json_magic"
                TLS_bg = "json_magic"
            else:
                TLS_fg = Fore.GREEN
                TLS_bg = None
            if TLS_fg:
                print(f"{TLS_fg}",end="")
            if TLS_bg:
                print(f"{TLS_bg}",end="")
            
            #print("HTTPS")
             
            if colour: 
                print(f"{Style.RESET_ALL}",end="")
                
        elif tcp_sport == 22 or tcp_dport == 22: #Traffic is likely to be SSH
            pass
    if DNS in pkt:
        dns = pkt[DNS]
        #print(f"DNS | {ip_src}:{udp_sport} ==> {ip_dst}:{udp_dport}",end=" | ")
        
    if TCP in pkt and Raw in pkt:
        raw = pkt[Raw]
            #print(bytes(pkt))
        

        
        
#TODO HTTP Response
#TODO TCP HANDSHAKE (SYN, SYN-ACK, ACK)
#TODO SSH
#TODO TELNET
#TODO FTP
#TODO DNS
#TODO OTHER PROTOCOLS ALONG DE WAY
        
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
    verbose = args.verbose 
    if not interface:
        interface = conf.iface
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
            capture = sniff(prn=proc_pkt,offline=read_pcap,filter=args.filter,count=args.count) 
            #TODO print better output if filter is wrong
        except OSError as e:
           m.err(f"failed to read from '{write_pcap}' due to '{e.strerror.lower()}'",colour)
        else:
            if write_pcap: 
                wrpcap(write_pcap,capture)
    else: #must be interface being used then
        try: 
            capture = sniff(prn=proc_pkt,iface=interface,filter=args.filter,count=args.count)
            #TODO print better output if filter is wrong
        except OSError as e:
           m.err(f"failed to sniff on {interface} due to '{e.strerror.lower()}'",colour)
           exit(e.errno)
        else:
            if write_pcap: 
                wrpcap(write_pcap,capture)

