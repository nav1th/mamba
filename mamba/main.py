#!/usr/bin/env python3
from socket import getservbyport,getservbyname
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
    src_port = None
    dst_port = None

    if Ether in pkt:  ## grab ethernet info if any
        ether_src = pkt[Ether].src 
        ether_dst = pkt[Ether].dst  
        insert_src_dst_pairs(ether_src,ether_dst,pairs_ether)
        
    if IP in pkt: # grab ipv4 info if any
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        insert_src_dst_pairs(ip_src,ip_dst,pairs_ipv4)
       
    if IPv6 in pkt: # grab ipv6 info if any
        ip_src = pkt[IPv6].src
        ip_dst = pkt[IPv6].dst
        insert_src_dst_pairs(ip_src,ip_dst,pairs_ipv6)
        if NDP_RS in pkt: #discover routers on Ipv6 network with all routers multicast ff02::2
            print(f"NDP - Router solication message | {ip_src} ==> {ip_dst}")
        if NDP_NA in pkt: #neighbour advertisement
            print(f"NDP - Neighbour advertisement | {ip_src} ==> {ip_dst}")
        if NDP_RA in pkt: #router advertisement 
            print(f"NDP - Router advertisement | {ip_src} ==> {ip_dst}")
        if NDP_NS in pkt: #neighbour solicitation
            print(f"NDP - Neighbour solicitation | {ip_src} ==> {ip_dst}")

    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        src_serv = src_port
        dst_serv = dst_port
        if guess_service: # if user wishes for service to be detected by port
            try: 
                src_serv = getservbyport(src_port)
            except:
                pass
            try:
                dst_serv = getservbyport(dst_port)
            except:
                pass
        if Raw not in pkt:
            flags = pkt[TCP].flags
            print(f"TCP - {ip_src}:{src_serv} ==> {ip_dst}:{dst_serv}",end=" | ")
            flags_map = {
                "SYN" : 0x02,
                "ACK" : 0x10,
                "RST" : 0x04,
                "PSH" : 0x08,
                "URG" : 0x20,
                "CWR" : 0x80,
                "ECE" : 0x40
            }
            flag_str = ""
            flag_num = 0
            for f in ["SYN","ACK" ,"RST" ,"PSH" ,"URG" ,"CWR" ,"ECE"]: 
                if flags & flags_map[f]: #if certain flag is detected
                    flag_num +=  1 
                    flag_str +=  f #add it to the string
                    flag_str += ', '
            flag_str = flag_str[0:-2] #get rid of comma at the end
            if flag_num > 1:
                flag_str = f"[{flag_str}]" #group of flags, else single flag
            print(f"FLAGS: {flag_str}")
        if Raw in pkt and \
           not HTTP in pkt and \
           not TLS in pkt: #try to 
            if src_port == 23:
                print(f"TELNET - {ip_src}:{src_serv} ==> {ip_dst}:{dst_serv}")
        
           

    if UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        src_serv = src_port
        dst_serv = dst_port 
        if guess_service:
            try: 
                src_serv = getservbyport(src_port)
            except:
                pass
            try:
                dst_serv = getservbyport(dst_port)
            except:
                pass
        if Raw not in pkt and DNS not in pkt:
            print(f"UDP - {ip_src}:{src_serv} ==> {ip_dst}:{dst_serv}")

        
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
            print(f"HTTP - {ip_src}:{src_port} ==> {ip_dst}:{dst_port} | VERSION: {version} | URL: {url} | METHOD: {method}")
            
        if HTTPRes in pkt:
            res = pkt[HTTPRes]
            status = res.Status_Code.decode()
            reason = res.Reason_Phrase.decode()
            version = res.Http_Version.decode()
            status_code = f"{status}: '{reason}'" #Status code e.g '404: Not found'
            print(f"HTTP - {ip_src}:{src_port} ==> {ip_dst}:{dst_port} | VERSION: {version} | STATUS: {status_code}")

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
        if src_port != None or dst_port != None:
            print(f"TLS - {ip_src}:{src_port} ==> {ip_dst}:{dst_port}")
        print(f"TLS - {ip_src} ==> {ip_dst}")
             
                
    if DNS in pkt:
        dns = pkt[DNS]
        if dst_port == 5353 and src_port == 5353:
            print(f"MDNS - {ip_src} ==> {ip_dst}",end=" | ")
        else:
            print(f"DNS - {ip_src}:{src_port} ==> {ip_dst}:{dst_port}",end=" | ")
        print(dns.mysummary())
        
    if Raw in pkt and verbose:
        print(f"    Data: {pkt[Raw].load}")
    if colour:
        print(Style.RESET_ALL,end="") # clears formatting if any regardless of show_raw

        
#TODO TCP HANDSHAKE (SYN, SYN-ACK, ACK)
        
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
    guess_service = False
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

