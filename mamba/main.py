#!/usr/bin/env python3

#Imports
import msg as m # custom messages
import args # arguments in program

#Python imports
from socket import getservbyport
from datetime import datetime
from collections import Counter
from typing import Tuple
from sys import platform
import os.path
import string

#Colorama
from colorama import Fore, Back, Style

#Scapy 
from scapy.main  import load_layer
from scapy.all   import sniff, Raw,wrpcap,conf,get_working_ifaces
from scapy.error import Scapy_Exception

#Scapy Ethernet & ARP
from scapy.layers.l2    import ARP, Ether

#Scapy IPv4, ICMP, TCP & UDP
from scapy.layers.inet  import \
    IP, \
    TCP, \
    UDP, \
    ICMP

#Scapy IPv6 & NDP
from scapy.layers.inet6 import  \
    IPv6, \
    ICMPv6ND_NA as NDP_NA, \
    ICMPv6ND_RA as NDP_RA, \
    ICMPv6ND_NS as NDP_NS, \
    ICMPv6ND_RS as NDP_RS 

#Scapy RIP
from scapy.layers.rip import \
    RIP, \
    RIPEntry 

#Scapy HTTP
from scapy.layers.http import \
    HTTP, \
    HTTPRequest as HTTPReq,\
    HTTPResponse as HTTPRes

#Scaoy Netbios
from scapy.layers.netbios import \
    NBNSHeader, \
    NBNSQueryRequest, \
    NBNSQueryResponse

#Scapy TLS & SSL
from scapy.layers.tls.handshake import \
    TLSClientHello, \
    TLSServerHello

from scapy.layers.tls.record import  \
    TLS, \
    _TLSEncryptedContent, \
    TLSAlert, \
    TLSApplicationData, \
    TLSChangeCipherSpec

from scapy.layers.tls.record_sslv2 import SSLv2 as SSL

#Scapy DNS
from scapy.layers.dns import DNS

#Scapy DHCP
from scapy.layers.dhcp import DHCP

#Scapy NTP
from scapy.layers.ntp import NTP

#Scapy TFTP
from scapy.layers.tftp import TFTP

#Scapy IGMP
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3


load_layer("tls")


printable = string.ascii_letters + string.digits + string.punctuation + ' '
def hex_escape(s): #for reading reading encrypting 
    return ''.join(c if c in printable else r'\x{0:02x}'.format(ord(c)) for c in s)

def check_write_ok(path) -> Tuple[bool,int,str]: #checks if writing to pcap is okay
    #returns bool, error number, error string
    #if int is > 0 and str is not empty error has occured
        if os.path.exists(path): 
            if confirm: #user doesn't want to be prompted
                if not m.warn_confirmed(f"'{path}' exists, it will be overwritten.",colour): #if user doesn't want to overwrite file
                    m.info("understood, exiting...",colour)
                    return (False, 0,"") 
            else:
                m.warn(f"'{path}' exists, will be overwritten",colour)
        try: 
            f = open(path,"w") #tests to see if pcap can be written
        except OSError as e:
            m.err(f"could not write '{path}' due to '{e.strerror.lower()}'",colour)
            return (False, e.errno,e.strerror)
        else:
            f.close() # close file, so nothing messes up
            return (True, 0,"")

def insert_src_dst_pairs(src, dst, counter):
    key = tuple(sorted([src,dst])) #bundles src and dst together
    counter.update(key) #updates amount of pairs 

def proc_pkt(pkt): #handles packets depending on protocol
    ##possible address types
    time =  int(pkt[0].time)
    date = datetime.utcfromtimestamp(time).strftime('%d-%m-%Y %H:%M:%S')
    ether_src = None
    ether_dst = None
    ip_src = None
    ip_dst = None
    sport =  None
    dport = None
    # variables below allow for guessing the TCP/UDP protocol used if user wishes, 
    #otherwise they will be the same as the TCP/UDP port numbers
    sserv = None
    dserv = None
    pcolours = "" #colours for printing 
    protocol = "" #protocol type along with its attributes
    payload = "" #application data payload
    
    if Ether in pkt:  # grab ethernet info if any
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
            protocol += f"NDP - Router solication message | {ip_src} ==> {ip_dst}"
        if NDP_NA in pkt: #neighbour advertisement
           protocol += f"NDP - Neighbour advertisement | {ip_src} ==> {ip_dst}"
        if NDP_RA in pkt: #router advertisement 
           protocol += f"NDP - Router advertisement | {ip_src} ==> {ip_dst}"
        if NDP_NS in pkt: #neighbour solicitation
           protocol += f"NDP - Neighbour solicitation | {ip_src} ==> {ip_dst}"

    if TCP in pkt: #any TCP data in packet
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        sserv = sport
        dserv = dport
        flags = pkt[TCP].flags
        seq = pkt[TCP].seq #sequence number 
        ack = pkt[TCP].ack #acknowledgement number
        flags_found = []
        flag_num = 0
        flag_pairs = [ #the flags which are handled 
        ("FIN",  0x1), 
        ("SYN" , 0x2),
        ("RST" , 0x4),
        ("PSH" , 0x8),
        ("ACK" , 0x10),
        ("URG" , 0x20),
        ("ECE" , 0x40),
        ("CWR" , 0x80),
        ]
        for f in flag_pairs: #checks flags, ands them to see if they are present
            if flags & f[1]: #if certain flag is detected
                flag_num +=  1 
                flags_found.append(f[0])  #add it to list of flags found
        alt_proto = [HTTP,TLS,SSL,_TLSEncryptedContent] # these protocols are handled elsewhere in the program
        if guess_service: # if user wishes for service to be detected by port
            try: 
                sserv = getservbyport(sport)
            except:
                pass
            try:
                dserv = getservbyport(dport)
            except:
                pass
        if not Raw in pkt and \
        not any(i in pkt for i in alt_proto): #Raw TCP packet wihh no app data 
            if colour:
                if "RST" in flags_found:
                    pcolours+=Back.BLACK
                    pcolours+=Fore.RED
                if  "SYN" in flags_found:
                    pcolours+=Fore.GREEN
                if "ACK" in flags_found:
                    pcolours+=Fore.YELLOW
                if "SYN" in flags_found and "ACK" in flags_found:
                    pcolours+=Fore.CYAN
                
            protocol +=  f"TCP - {ip_src}:{sserv} ==> {ip_dst}:{dserv} | "
            if verbose: #if user wants more information
                protocol += f"FLAGS: {flags_found} " #group of flags, else single flag
                protocol += f"SEQ: {seq} ACK: {ack}"
            else:
                protocol +=  f"FLAGS: {flags_found}" #group of flags, else single flag
        elif Raw in pkt and \
        not any(i in pkt for i in alt_proto):
            if 20 in (sport,dport) or 21 in (sport,dport):
                protocol+=f"FTP - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
            elif 23 in (sport,dport):
                protocol+=f"TELNET - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
            elif 25 in (sport,dport):
                protocol+=f"SMTP - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
            elif 43 in (sport,dport):
                protocol+=f"WHOIS - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
            elif 110 in (sport,dport):
                protocol+=f"POP - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
            elif 143 in (sport,dport):
                protocol+=f"IMAP - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
            else: #handles other TCP protocols and guesses the service
                proto = None
                if sport > dport: # lower port numbers are prioritised 
                    try: 
                        proto = getservbyport(sport) #guesses src port service
                    except:
                        try:
                            proto = getservbyport(dport) #guesses dst port service
                        except: pass
                elif sport < dport:
                    try: 
                        proto = getservbyport(dport) #guesses dst port service
                    except:
                        try:
                            proto = getservbyport(sport) #guesses src port service
                        except: pass
                else:
                    try:
                        proto = getservbyport(sport) #order doesn't matter as src and dst ports are the same
                    except: pass                       
                if proto: #if there's a guess
                    protocol+=f"{proto.upper()} - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
                else: #if it still has no idea, it just displays its a TCP protocol
                    protocol+=f"TCP - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"

    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        sserv = sport
        dserv = dport 
        alt_proto = [DHCP,DNS,TFTP,NBNSHeader,NTP,TLS,SSL,_TLSEncryptedContent] # these protocols are handled elsewhere in the program
        if guess_service:
            try: 
                sserv = getservbyport(sport)
            except: pass
            try:
                dserv = getservbyport(dport)
            except: pass
        if not Raw in pkt and \
        not any(i in pkt for i in alt_proto): #raw UDP packets with no app data 
            protocol += f"UDP - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
        elif Raw in pkt and \
        not any(i in pkt for i in alt_proto): #handles other UDP protocols and guesses the service
            if 443 in (sport,dport):
                if colour:
                    pcolours += Fore.GREEN
                protocol += f"HTTPS-UDP - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
            else:
                proto = None
                if sport > dport:
                    try: 
                        proto = getservbyport(sport) #guesses src port service
                    except:
                        try:
                            proto = getservbyport(dport) #guesses dst port service
                        except: pass
                elif sport < dport:
                    try: 
                        proto = getservbyport(dport) #guesses dst port service
                    except:
                        try:
                            proto = getservbyport(sport) #guesses src port service
                        except: pass
                else:
                    try:
                        proto = getservbyport(sport) #order doesn't matter as src and dst ports are the same
                    except: pass                       
                if proto: #if there's a guess
                    protocol+=f"{proto.upper()} - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
                else: #if it still has no idea, it just displays its a UDP protocol
                    protocol+=f"UDP - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"

        
    if ARP in pkt: #ARP       
        arp = pkt[ARP] 
        if colour:
            pcolours += f"{Fore.LIGHTMAGENTA_EX}"
            
        protocol += f"ARP - {ether_src} ==> {ether_dst} | "
        if arp.op == 1:  #ARP who has the MAC for this IP
            protocol += f"{arp.psrc} is asking who has MAC for {arp.pdst}"
        elif arp.op == 2: #ARP here's your MAC
            protocol += f"{arp.hwsrc} is at {arp.psrc}"
    
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        protocol += f"ICMP - {ip_src} ==> {ip_dst} | {icmp.mysummary()}"

    elif IGMP in pkt or IGMPv3 in pkt:
        if IGMP in pkt:
            igmp = pkt[IGMP]
        else:
            igmp = pkt[IGMPv3]
            protocol += f"IGMPv3 - {ip_src} ==> {ip_dst} | {igmp.igmpv3types[igmp.type]}"

    
    elif TLS in pkt:
        if colour: 
            pcolours += f"{Fore.GREEN}"
        protocol+=f"TLSv13 - {ip_src}:{sserv} ==> {ip_dst}:{dserv} | "
        if TLSAlert in pkt:
            protocol += pkt[TLSAlert].name
            if verbose:
                protocol += f" {pkt[TLSAlert].level}"
                protocol += f" {pkt[TLSAlert].desc}"
        elif TLSClientHello in pkt:
            protocol += pkt[TLSClientHello].name
        elif TLSApplicationData in pkt: 
            protocol += pkt[TLSApplicationData].name
            payload += pkt[TLSApplicationData].data.decode('iso-8859-1')
        elif TLSServerHello in pkt:
            protocol += pkt[TLSServerHello].name
        elif TLSChangeCipherSpec in pkt:
            protocol += pkt[TLSChangeCipherSpec].name
    elif _TLSEncryptedContent in pkt:
        if colour: 
            pcolours += f"{Fore.GREEN}"
        protocol+=f"TLSv13 - {ip_src}:{sserv} ==> {ip_dst}:{dserv} | TLS Application Data"
    elif SSL in pkt:
        if colour: 
            pcolours += f"{Fore.GREEN}"
        protocol+=f"SSLv2 - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"

    elif HTTP in pkt: 
        if colour:
            pcolours += f"{Fore.YELLOW}" 
            pcolours += f"{Back.BLACK}"

        if HTTPReq in pkt: # decode HTTP requests 
            req = pkt[HTTPReq]
            host = req.Host.decode()
            path = req.Host.decode()
            url = host+path# the location of website e.g. 'http://hello.com/register/login'
            method = req.Method.decode() #e.g method used in request e.g. 'GET' or 'POST'
            version = req.Http_Version.decode() # http version of request 'HTTP/1.1'
            protocol += f"HTTP - {ip_src}:{sport} ==> {ip_dst}:{dport} | VERSION: {version} | URL: {url} | METHOD: {method}"
        elif HTTPRes in pkt:
            res = pkt[HTTPRes]
            status = res.Status_Code.decode()
            reason = res.Reason_Phrase.decode()
            version = res.Http_Version.decode()
            status_code = f"{status}: '{reason}'" #Status code e.g '404: Not found'
            protocol += f"HTTP - {ip_src}:{sport} ==> {ip_dst}:{dport} | VERSION: {version} | STATUS: {status_code}"
        else:
            protocol += f"HTTP - {ip_src}:{sport} ==> {ip_dst}:{dport}"
             
                
    elif DNS in pkt:
        if colour:
            pcolours += Fore.BLUE

        dns = pkt[DNS]
        if dport == 5353 and sport == 5353:
            protocol += f"MDNS - {ip_src} ==> {ip_dst} | "
        else:
            protocol += f"DNS - {ip_src}:{sport} ==> {ip_dst}:{dport} | "
        protocol += dns.mysummary()
        
    elif TFTP in pkt:
        tftp = pkt[TFTP]
        protocol += f"TFTP - {ip_src}:{sserv} => {ip_dst}:{dserv} | {tftp.mysummary()}"

        
    elif DHCP in pkt:
        dhcp = pkt[DHCP]
        protocol += f"DHCP - {ip_src} ==> {ip_dst} | {dhcp.mysummary()}"
    
    elif NTP in pkt: 
        ntp = pkt[NTP]
        protocol += f"NTP - {ip_src}:{sserv} ==> {ip_dst}:{dserv} | {ntp.mysummary()}"
        
    elif NBNSHeader in pkt:
        protocol += f"NBNS - {ip_src}:{sserv} ==> {ip_dst}:{dserv}"
        if NBNSQueryRequest in pkt:
            protocol += f" | {pkt[NBNSQueryRequest].mysummary()}"
        elif NBNSQueryResponse in pkt:
            protocol += f" | {pkt[NBNSQueryResponse].mysummary()}"

    elif RIP in pkt:
        protocol += f"RIP - {ip_src} ==> {ip_dst}"
        if RIPEntry in pkt:
            entry = pkt[RIPEntry]
            mask = entry.mask
            addr = entry.addr
            next = entry.nextHop
            protocol += f" | addr: {addr} mask: {mask} next: {next}"

    if protocol == "":
        protocol += f"UNKNOWN"
        if IP in pkt or IPv6 in pkt:
            protocol += f" - {ip_src} ==> {ip_dst}"
        elif Ether in pkt:
            protocol += f" - {ether_src} ==> {ether_dst}"
    if pcolours != "":
        print(f"{pcolours}",end="")
    print(f"{date} {protocol}")

    if verbose:
        if Raw in pkt:
            try: 
                payload += pkt[Raw].load.decode()
            except:
                payload += pkt[Raw].load.decode('iso-8859-1')
        if payload != "":
            print(f"\t{hex_escape(payload)}")
    if colour:
        print(Style.RESET_ALL,end="") # clears formatting if any regardless of show_raw

        
if __name__ == "__main__":
    args = args.grab_args() #grab arguments from CLI input
    
    ##args from cli
    filter = args.filter # BPF option, filters packets according to user pref
    colour = args.colour # determines if output is coloured, (stored as False when selected)
    write_pcap = args.write #if user wishes to write their packet capture to a file
    read_pcap = args.read #if user wishes to perform offline capture by reading 'pcap' file
    interface = args.interface #if user desires to select interface, otherwise first available will be selected for them
    count = args.count #how many packets will be captured from live/pcap file, e.g. if count is 10, only 10 packets will be captured, then program ends
    confirm = args.confirm
    verbose = args.verbose 
    list_interfaces = args.list_interfaces
    plot = True
    if not interface:
        interface = conf.iface
    guess_service = args.guess_service
    ##

    if list_interfaces: #lists interfaces and trys to guess their type
        for iface, col in zip(get_working_ifaces(),[Fore.GREEN,Fore.YELLOW,Fore.BLUE,Fore.RED,Fore.MAGENTA,Fore.CYAN]):
            iface = str(iface)
            if colour: 
                print(f"{col}{iface}",end=" - ")
            else:
                print(f"{iface}",end=" - ")
            if platform == "linux" or platform == "linux2":
                if iface[0:2] == "lo":
                    print("loopback")
                elif iface[0:2] == "en" or iface[0:3] == "eth":
                    print("802.3 (ethernet)")
                elif iface[0:2] == "wl":
                    print("802.11 (wifi)")
                elif iface[0:3] == "tun":
                    print("tunnel")
                elif iface[0:3] == "ppp":
                    print("point-to-point")
                elif iface[0:8] == "vboxnet" or iface[0:5] == "vmnet":
                    print("virtual machine interface")
                elif iface[0:5] == "virbr":
                    print("bridge")
                else:
                    print()
            elif platform == "win32":
                pass
            else:
                print()
        exit(0) #exit after

    if write_pcap: #checks beforehand to avoid packet capture and discovering at the end you can't write the file
        match check_write_ok(write_pcap):
            case (False, x,_):
                exit(x)

    packet_count = 1 #count the number of packets captured
    pairs_ipv4 = Counter() 
    pairs_ipv6 = Counter()
    pairs_ether = Counter()

    if read_pcap:
        try: 
            capture = sniff(prn=proc_pkt,offline=read_pcap,filter=args.filter,count=args.count) 
        except OSError as e:
           m.err(f"failed to read from '{write_pcap}' due to '{e.strerror.lower()}'",colour)
        except Scapy_Exception as e:
            m.err(f"failed to sniff pcap file: {e}",colour)
        except KeyboardInterrupt:
            pass
        else:
            if write_pcap: 
                wrpcap(write_pcap,capture)
    else: #must be interface being used then
        try: 
            capture = sniff(prn=proc_pkt,iface=interface,filter=args.filter,count=args.count)
        except OSError as e:
           m.err(f"failed to sniff on {interface} due to '{e.strerror.lower()}'",colour)
           exit(e.errno)
        except Scapy_Exception as e:
            m.err(f"failed to sniff live capture: {e}",colour)
        except KeyboardInterrupt:
            pass
        else:
            if write_pcap: 
                wrpcap(write_pcap,capture)
            else: #this is if the user wants to save the packet capture at the end
                print() #get rid of the Ctrl-C
                if m.prompt("Do you wish to save the pcap?",colour):
                    write_pcap =  input("Save it as: ")
                    match check_write_ok(write_pcap):
                        case (True, _, _):
                            wrpcap(write_pcap,capture)
                        case (False, x , errstr) if x > 0:
                            m.warn(f"Unable to save pcap file '{write_pcap}' due to {errstr}",colour)
