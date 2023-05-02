#!/usr/bin/env python3

# Imports
import msg as m  # custom messages
import args  # arguments in program

# Python imports
from socket import getservbyport
from datetime import datetime
from collections import Counter
from typing import Tuple
from itertools import cycle
from sys import platform
import os.path
import string

# Colorama
from colorama import Fore, Back, Style

# Scapy
from scapy.main import load_layer
from scapy.all import sniff, Raw, wrpcap, conf, get_working_ifaces
from scapy.error import Scapy_Exception

# Scapy Ethernet & ARP
from scapy.layers.l2 import ARP, Ether

# Scapy IPv4, ICMP, TCP & UDP
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Scapy IPv6 & NDP
from scapy.layers.inet6 import (
    ICMPv6MLReport,
    ICMPv6MLReport2,
    IPv6,
    ICMPv6ND_NA as NDP_NA,
    ICMPv6ND_RA as NDP_RA,
    ICMPv6ND_NS as NDP_NS,
    ICMPv6ND_RS as NDP_RS,
)

# Scapy RIP
from scapy.layers.rip import RIP, RIPEntry

# Scapy HTTP
from scapy.layers.http import HTTP, HTTPRequest as HTTPReq, HTTPResponse as HTTPRes

# Scaoy Netbios
from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest, NBNSQueryResponse

# Scapy TLS & SSL
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello

from scapy.layers.tls.record import (
    TLS,
    _TLSEncryptedContent,
    TLSAlert,
    TLSApplicationData,
    TLSChangeCipherSpec,
)

from scapy.layers.tls.record_sslv2 import SSLv2 as SSL

# Scapy Kerberos
from scapy.layers.kerberos import Kerberos

# Scapy DNS
from scapy.layers.dns import DNS

# Scapy DHCP
from scapy.layers.dhcp import DHCP

# Scapy DHCPv6
from scapy.layers.dhcp6 import (
    DHCP6_Solicit,
    DHCP6_Advertise,
    DHCP6_Request,
    DHCP6_Confirm,
    DHCP6_Renew,
    DHCP6_Rebind,
    DHCP6_Reply,
    DHCP6_Release,
    DHCP6_Decline,
    DHCP6_Reconf,
    DHCP6_InfoRequest,
    DHCP6_RelayForward,
    DHCP6_RelayReply,
    dhcp6types
)
DHCP6_TYPES = [
    DHCP6_Reply,
    DHCP6_Renew,
    DHCP6_Solicit,
    DHCP6_Request,
    DHCP6_Advertise,
    DHCP6_Rebind,
    DHCP6_Reconf,
    DHCP6_Confirm,
    DHCP6_Release,
    DHCP6_Decline,
    DHCP6_InfoRequest,
    DHCP6_RelayForward,
    DHCP6_RelayReply,
]


# Scapy NTP
from scapy.layers.ntp import NTP

# Scapy TFTP
from scapy.layers.tftp import TFTP

# Scapy IGMP
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3


load_layer("tls")


def hex_escape(s):  # for reading bytes, usually from encrypted content
    printable = string.ascii_letters + string.digits + string.punctuation + " "
    print_str = ""
    for c in s:
        match c:
            case c if c in printable:
                print_str += c
            case "\x00":
                print_str += "<NUL>"
            case "\x01":
                print_str += "<SOH>"
            case "\x02":
                print_str += "<STX>"
            case "\x03":
                print_str += "<ETX>"
            case "\x04":
                print_str += "<EOT>"
            case "\x05":
                print_str += "<ENQ>"
            case "\x06":
                print_str += "<ACK>"
            case "\x07":
                print_str += "<BEL>"
            case "\x08":
                print_str += "<BS>"
            case "\x09":
                print_str += "<TAB>"
            case "\x0a":
                print_str += "<LF>"
            case "\x0b":
                print_str += "<VT>"
            case "\x0c":
                print_str += "<FF>"
            case "\x0d":
                print_str += "<CR>"
            case "\x0e":
                print_str += "<SO>"
            case "\x0f":
                print_str += "<SI>"
            case "\x10":
                print_str += "<DLE>"
            case "\x11":
                print_str += "<DC1>"
            case "\x12":
                print_str += "<DC2>"
            case "\x13":
                print_str += "<DC3>"
            case "\x14":
                print_str += "<DC4>"
            case "\x15":
                print_str += "<NAK>"
            case "\x16":
                print_str += "<SYN>"
            case "\x17":
                print_str += "<ETB>"
            case "\x18":
                print_str += "<CAN>"
            case "\x19":
                print_str += "<EM>"
            case "\x1a":
                print_str += "<SUB>"
            case "\x1b":
                print_str += "<ESC>"
            case "\x1c":
                print_str += "<FS>"
            case "\x1d":
                print_str += "<GS>"
            case "\x1e":
                print_str += "<RS>"
            case "\x1f":
                print_str += "<US>"
            case _:
                print_str += r"\x{0:02x}".format(ord(c))

    return print_str


def check_write_ok(path) -> Tuple[bool, int, str]:  # checks if writing to pcap is okay
    # returns bool, error number, error string
    # if int is > 0 and str is not empty error has occured
    if os.path.exists(path):
        if confirm:  # user doesn't want to be prompted
            if not m.warn_confirmed(
                f"'{path}' exists, it will be overwritten.", colour
            ):  # if user doesn't want to overwrite file
                m.info("understood, exiting...", colour)
                return (False, 0, "")
        else:
            m.warn(f"'{path}' exists, will be overwritten", colour)
    try:
        f = open(path, "w")  # tests to see if pcap can be written
    except OSError as e:
        m.err(f"could not write '{path}' due to '{e.strerror.lower()}'", colour)
        return (False, e.errno, e.strerror)
    else:
        f.close()  # close file, so nothing messes up
        return (True, 0, "")


def proc_pkt(pkt):  # handles packets depending on protocol
    ##possible address types
    ether_src = None
    ether_dst = None
    ip_src = None
    ip_dst = None
    sport = None
    dport = None

    l1conversation = None # conversation on layer 1 such as 'ff:ff:ff:ff:ff:ff ==> de:ad:be:ee:ee:ef' 
    l2conversation = None # conversation on layer 2 such as '192.168.20.3 ==> 192.168.20.53'
    l3conversation = None # conversation on layer 3 such as '192.168.20.3:80 ==> 192.168.20.53:53261'
   
    pcolours = ""  # colours for printing
    protocol = ""  # protocol type along with its attributes
    payload = ""  # application data payload
    print_str = ""
    number: int
    key = tuple(sorted([pkt[0].src, pkt[0].dst]))  # sorts layer 2 conversations
    pairs_l2.update([key])  # stores sorted layer 2 conversations
    number = sum(pairs_l2.values())  # updates packet count

    if Ether in pkt:  # grab ethernet info if any
        ether_src = pkt[Ether].src
        ether_dst = pkt[Ether].dst
        l1conversation = f"{ether_src} ==> {ether_dst}"

    if IP in pkt:  # grab ipv4 info if any
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        l2conversation = f"{ip_src} ==> {ip_dst}"
        if TCP in pkt or UDP in pkt:
            sserv = pkt[2].sport
            dserv = pkt[2].dport
            if guess_service:  # if user wishes for service to be detected by port
                try:
                    sserv = getservbyport(sserv)
                except:
                    pass
                try:
                    dserv = getservbyport(dserv)
                except:
                    pass
            l3conversation = f"{ip_src}:{sserv} ==> {ip_dst}:{dserv}"

        if ls_convos and TCP not in pkt and UDP not in pkt:
            key = tuple(sorted([ip_src, ip_dst]))
            pairs_ipv4.update([key])

    if IPv6 in pkt:  # grab ipv6 info if any
        ip_src = pkt[IPv6].src
        ip_dst = pkt[IPv6].dst
        l2conversation = f"{ip_src} ==> {ip_dst}"
        if TCP in pkt or UDP in pkt:
            sserv = pkt[2].sport
            dserv = pkt[2].dport
            if guess_service:  # if user wishes for service to be detected by port
                try:
                    sserv = getservbyport(sserv)
                except:
                    pass
                try:
                    dserv = getservbyport(dserv)
                except:
                    pass
            l3conversation = f"[{ip_src}]:{sserv} ==> [{ip_dst}]:{dserv}"

        if ls_convos and TCP not in pkt and UDP not in pkt:
            key = tuple(sorted([ip_src, ip_dst]))
            pairs_ipv6.update([key])
        if any(
            i in pkt for i in [NDP_RS, NDP_NA, NDP_RA, NDP_NS]
        ):  # checks if pkt is NDP
            pcolours += Fore.BLACK
            pcolours += Back.WHITE
            if NDP_RS in pkt:  # router soliciation
                protocol += f"NDP - {l2conversation} | Router solication"
            if NDP_NA in pkt:  # neighbour advertisement
                protocol += f"NDP - {l2conversation} | Neighbour advertisement"
            if NDP_RA in pkt:  # router advertisement
                protocol += f"NDP - {l2conversation} | Router advertisement"
            if NDP_NS in pkt:  # neighbour solicitation
                protocol += f"NDP - {l2conversation} | Neighbour solicitation"
        if ICMPv6MLReport in pkt:
            protocol += f"IPv6 - {l2conversation} | Multicast Listener Report v1"
        if ICMPv6MLReport2 in pkt:
            protocol += f"IPv6 - {l2conversation} | Multicast Listener Report v2"

    if TCP in pkt:  # any TCP data in packet
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        rec_proto = None
        if ls_convos:
            if IP in pkt:
                key = tuple(sorted([f"{ip_src}:{sport}/tcp", f"{ip_dst}:{dport}/tcp"]))
            else:
                key = tuple(
                    sorted([f"[{ip_src}]:{sport}/tcp", f"[{ip_dst}]:{dport}/tcp"])
                )
            pairs_tcp.update([key])

        sserv = sport
        dserv = dport
        flags = pkt[TCP].flags
        seq = pkt[TCP].seq  # sequence number
        ack = pkt[TCP].ack  # acknowledgement number
        flags_found = []
        flag_num = 0
        flag_pairs = [  # the flags which are handled
            ("FIN", 0x1),
            ("SYN", 0x2),
            ("RST", 0x4),
            ("PSH", 0x8),
            ("ACK", 0x10),
            ("URG", 0x20),
            ("ECE", 0x40),
            ("CWR", 0x80),
        ]

        for f in flag_pairs:  # checks flags, ands them to see if they are present
            if flags & f[1]:  # if certain flag is detected
                flag_num += 1
                flags_found.append(f[0])  # add it to list of flags found

        handled_tcp_proto = [
            HTTP,
            TLS,
            SSL,
            _TLSEncryptedContent,
        ]  # these protocols are handled elsewhere in the program
        if IP in pkt:
            pass
        else:
            l3conversation = f"[{ip_src}]:{sserv} ==> [{ip_dst}]:{dserv}"

        if Raw not in pkt and not any(
            i in pkt for i in handled_tcp_proto
        ):  # Raw TCP packet wihh no app data
            if colour:
                if "RST" in flags_found:
                    pcolours += Back.BLACK
                    pcolours += Fore.RED
                elif "SYN" in flags_found:
                    pcolours += Fore.GREEN
                elif "ACK" in flags_found:
                    pcolours += Fore.YELLOW
                elif "SYN" in flags_found and "ACK" in flags_found:
                    pcolours += Fore.CYAN

            ### adds brackets and commas to flags which have more than one bit
            if len(flags_found) > 1:
                flags_found = f"[{', '.join(flags_found)}]"
            else:
                flags_found = f"{flags_found[0]}"
            ###

            protocol += f"TCP - {l3conversation} | FLAGS: {flags_found}"  # group of flags, else single flag
            if verbose:  # if user wants more information
                protocol += f" | SEQ: {seq} | ACK: {ack}"
        elif Raw in pkt and not any(i in pkt for i in handled_tcp_proto):
            if sport > dport:  # lower port numbers are prioritised
                try:
                    rec_proto = getservbyport(dport)  # guesses dst port service
                except:
                    try:
                        rec_proto = getservbyport(sport)  # guesses src port service
                    except:
                        pass
            elif sport < dport:
                try:
                    rec_proto = getservbyport(sport)  # guesses dst port service
                except:
                    try:
                        rec_proto = getservbyport(dport)  # guesses src port service
                    except:
                        pass
            else:
                try:
                    rec_proto = getservbyport(
                        sport
                    )  # order doesn't matter as src and dst ports are the same
                except:
                    pass
            if rec_proto:  # if there's a guess
                protocol += rec_proto.upper()
            else:  # if it still has no idea, it just displays its a TCP protocol
                protocol += "TCP"
            protocol += f" - {l3conversation}"
    elif UDP in pkt:  # if its not TCP must be UDP
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if IP in pkt:
            key = tuple(
                sorted([f"{ip_src}:{sport}/udp", f"{ip_dst}:{dport}/udp"])
            )
        else:
            key = tuple(
                sorted(
                    [f"[{ip_src}]:{sport}/udp", f"[{ip_dst}]:{dport}/udp"]
                )
            )
        pairs_tcp.update([key])
        sserv = sport
        dserv = dport
        handled_udp_proto = [
            DHCP,
            DNS,
            TFTP,
            NBNSHeader,
            NTP,
            TLS,
            SSL,
            _TLSEncryptedContent,
        ]  # these protocols are handled elsewhere in the program
        if guess_service:
            try:
                sserv = getservbyport(sport)
            except:
                pass
            try:
                dserv = getservbyport(dport)
            except:
                pass
        if not any(i in pkt for i in handled_udp_proto) and not any(i in pkt for i in DHCP6_TYPES):  # raw UDP packets with no app data
            if colour:
                pcolours += Fore.BLUE
            protocol += f"UDP - {l3conversation}"

    if ARP in pkt:  # ARP
        arp = pkt[ARP]
        if colour:
            pcolours += f"{Fore.LIGHTMAGENTA_EX}"

        protocol += f"ARP - {l1conversation} | "
        if arp.op == 1:  # ARP who has the MAC for this IP
            protocol += f"{arp.psrc} is asking who has MAC for {arp.pdst}"
        elif arp.op == 2:  # ARP here's your MAC
            protocol += f"{arp.hwsrc} is at {arp.psrc}"

    elif ICMP in pkt:
        icmp = pkt[ICMP]
        protocol += f"ICMP - {l2conversation} | {icmp.sprintf('%ICMP.type%')}"

    elif IGMP in pkt or IGMPv3 in pkt:
        if IGMP in pkt:
            igmp = pkt[IGMP]
        else:
            igmp = pkt[IGMPv3]
            protocol += f"IGMPv3 - {l2conversation} | {igmp.igmpv3types[igmp.type]}"

    elif TLS in pkt:  # handles TLS
        if colour:
            pcolours += f"{Fore.GREEN}"
        protocol += f"TLSv13 - {l3conversation} | "
        # decides what kind of TLS version the packet is
        if TLSAlert in pkt:
            protocol += pkt[TLSAlert].name
            if verbose:
                protocol += f" {pkt[TLSAlert].level}"
                protocol += f" {pkt[TLSAlert].desc}"
        elif TLSClientHello in pkt:
            protocol += pkt[TLSClientHello].name
        elif TLSApplicationData in pkt:
            protocol += pkt[TLSApplicationData].name
            payload += pkt[TLSApplicationData].data.decode("iso-8859-1")
        elif TLSServerHello in pkt:
            protocol += pkt[TLSServerHello].name
        elif TLSChangeCipherSpec in pkt:
            protocol += pkt[TLSChangeCipherSpec].name
    elif _TLSEncryptedContent in pkt:
        if colour:
            pcolours += f"{Fore.GREEN}"
        protocol += f"TLSv13 - {l3conversation} | TLS Application Data"
    elif SSL in pkt:  # handles SSL
        if colour:
            pcolours += f"{Fore.GREEN}"
        protocol += f"SSLv2 - {l3conversation}"
    elif Kerberos in pkt:  # handles kerneros
        protocol += f"Kerberos - {l3conversation} | {pkt[Kerberos].mysummary()}"

    elif HTTP in pkt:  # handles HTTP
        if colour:
            pcolours += f"{Fore.YELLOW}"
            pcolours += f"{Back.BLACK}"

        if HTTPReq in pkt:  # decode HTTP requests
            req = pkt[HTTPReq]
            host = req.Host.decode()
            path = req.Path.decode()
            url = (
                host + path
            )  # the location of website e.g. 'http://hello.com/register/login'
            method = (
                req.Method.decode()
            )  # e.g method used in request e.g. 'GET' or 'POST'
            version = req.Http_Version.decode()  # http version of request 'HTTP/1.1'
            protocol += f"HTTP - {l3conversation} | VERSION: {version} | URL: {url} | METHOD: {method}"
        elif HTTPRes in pkt:
            res = pkt[HTTPRes]
            status = res.Status_Code.decode()
            reason = res.Reason_Phrase.decode()
            version = res.Http_Version.decode()
            status_code = f"{status}: '{reason}'"  # Status code e.g '404: Not found'
            protocol += f"HTTP - {l3conversation} | VERSION: {version} | STATUS: '{status_code}'"
        else:
            http = pkt[HTTP]
            content = http.Content.decode()
            protocol += f"HTTP - {l3conversation} | CONTENT: {content}"

    elif DNS in pkt:  # handles DNS
        if colour:
            pcolours += Fore.BLUE

        dns = pkt[DNS]
        if dport == 5353 and sport == 5353:
            protocol += f"MDNS - {l2conversation} | "
        else:
            protocol += f"DNS - {l3conversation} | "
        protocol += dns.mysummary()

    elif TFTP in pkt:  # handles TFTP
        tftp = pkt[TFTP]
        protocol += f"TFTP - {l3conversation} | {tftp.mysummary()}"

    elif DHCP in pkt:  # handles DHCP
        if colour:
            pcolours += Fore.BLACK
            pcolours += Back.BLUE
        dhcp = pkt[DHCP]
        protocol += f"DHCP - {l3conversation} | {dhcp.mysummary()}"

    elif any(i in pkt for i in DHCP6_TYPES):  # handles DHCPv6
        if colour:
            pcolours += Fore.BLACK
            pcolours += Back.BLUE
        protocol += f"DHCPv6 - {l3conversation}"
        protocol += f" | {dhcp6types[pkt[3].msgtype].capitalize()}"

    elif NTP in pkt:
        ntp = pkt[NTP]
        protocol += f"NTP - {l3conversation} | {ntp.mysummary()}"

    elif NBNSHeader in pkt:
        protocol += f"NBNS - {l3conversation}"
        if NBNSQueryRequest in pkt:
            protocol += f" | {pkt[NBNSQueryRequest].mysummary()}"
        elif NBNSQueryResponse in pkt:
            protocol += f" | {pkt[NBNSQueryResponse].mysummary()}"

    elif RIP in pkt:  # handles RIP
        protocol += f"RIP - {l2conversation}"
        if RIPEntry in pkt:
            entry = pkt[RIPEntry]
            mask = entry.mask
            addr = entry.addr
            next = entry.nextHop
            protocol += f" | addr: {addr} mask: {mask} next: {next}"

    if protocol == "":
        if IP in pkt or IPv6 in pkt:
            if IP in pkt:
                protocol += "IPv4"
            elif IPv6 in pkt:
                protocol += "IPv6"
            protocol += f" - {l2conversation}"
        elif Ether in pkt:
            protocol += "Ethernet"
            protocol += f" - {l1conversation}"
        else:
            protocol += f"UNKNOWN"
    if pcolours != "":
        print_str += pcolours
    if count_enabled:
        print_str += f"#{number} "
    if date_enabled:
        time = int(pkt[0].time)
        date = datetime.utcfromtimestamp(time).strftime("%d-%m-%Y %H:%M:%S")
        print_str += f"{date} "
    print_str += protocol

    if verbose:
        if Raw in pkt:
            try:
                payload += pkt[Raw].load.decode()
            except:
                payload += pkt[Raw].load.decode("iso-8859-1")
        if payload != "":
            print_str += f"\n\tData: {hex_escape(payload)}"

    if colour:
        print_str += Style.RESET_ALL  # clears colour formating if there's any

    print(print_str)


if __name__ == "__main__":



    args = args.grab_args()  # grab arguments from CLI input

    ##args from cli
    filter = args.filter  # BPF option, filters packets according to user pref
    colour = (
        args.colour
    )  # determines if output is coloured, (stored as False when selected)
    wpcap = args.write  # if user wishes to write their packet capture to a file
    rpcap = (
        args.read
    )  # if user wishes to perform offline capture by reading 'pcap' file
    iface = (
        args.iface
    )  # if user desires to select interface, otherwise first available will be selected for them
    confirm = args.confirm
    amount = args.amount
    verbose = args.verbose
    ls_ifaces = args.ls_ifaces
    ls_convos = args.ls_convos
    guess_service = args.guess_service
    count_enabled = args.count
    date_enabled = args.date
    if args.minimal:
        count_enabled = False
        date_enabled = False
        colour = False

    col_ls = [
        Fore.GREEN,
        Fore.YELLOW,
        Fore.BLUE,
        Fore.LIGHTRED_EX,
        Fore.MAGENTA,
        Fore.CYAN,
    ]
    cy_col_ls = cycle(col_ls)  # this is to cycle over the different colours
    ##
    if ls_ifaces:  # lists interfaces and trys to guess their type
        for iface in map(str, get_working_ifaces()):
            if (
                platform == "linux"
                or platform == "linux2"
                or platform == "openbsd"
                or platform == "freebsd"
            ):  # if it is linux/unix (non-Mac)
                if iface[0:2] == "lo":
                    iface += " - loopback"
                elif iface[0:2] == "en" or iface[0:3] == "eth":
                    iface += " - 802.3 (ethernet)"
                elif iface[0:2] == "wl":
                    iface += " - 802.11 (wifi)"
                elif iface[0:3] == "tun":
                    iface += " - tunnel"
                elif iface[0:3] == "ppp":
                    iface += " - point-to-point"
                elif iface[0:8] == "vboxnet" or iface[0:5] == "vmnet":
                    iface += " - virtual machine interface"
                elif iface[0:5] == "virbr":
                    iface += " - bridge"
            elif (
                platform == "darwin"
            ):  # i dont have a Mac, so unfortunately i can't test this
                if iface == "lo0":
                    iface += " - loopback"
                elif iface == "en0":
                    iface += " - 802.11 (wifi)"
                elif iface == "en1" or iface == "en2":
                    iface += " - thunderbolt"
                elif iface == "fw":
                    iface += " - firewire"
                elif iface == "stf0":
                    iface += " - 6to4 tun"
                elif iface == "gif0":
                    iface += " - tun"
                elif iface == "awdl0":
                    iface += " - apple wireless direct link"
            if colour:
                print(f"{next(cy_col_ls)}{iface}{Style.RESET_ALL}")
            else:
                print(f"{iface}")
        exit(0)

    if (
        wpcap
    ):  # checks beforehand to avoid packet capture and discovering at the end you can't write the file
        match check_write_ok(wpcap):
            case (False, retval, _):
                exit(retval)

    pairs_l2 = Counter()  # this is to count packets and print L2 conversations
    # the rest are purely for printing conversations
    pairs_ipv4 = Counter()
    pairs_ipv6 = Counter()
    pairs_tcp = Counter()
    pairs_udp = Counter()
    try:
        if rpcap:
            capture = sniff(prn=proc_pkt, offline=rpcap, filter=filter, count=amount)
        else:  # must be listening on interface
            capture = sniff(
                prn=proc_pkt, iface=iface, filter=args.filter, count=args.amount
            )
    except (
        OSError
    ) as e:  # will mostly handle permission errors but good for handling others too
        if rpcap:
            m.err(
                f"failed to read from '{rpcap}' due to: '{e.strerror.lower()}'", colour
            )
        else:  # must be listening on interface
            m.err(f"failed to sniff on {iface} due to: '{e.strerror.lower()}'", colour)
        exit(e.errno)
    except Scapy_Exception as e:
        if rpcap:
            m.err(f"failed to read from '{rpcap}' due to: '{str(e).lower()}'", colour)
        else:  # must be listening on interface
            m.err(f"failed to sniff on {iface} due to: '{str(e).lower()}'", colour)
    except KeyboardInterrupt:  # no ugly keyboard exception output
        pass
    else:  # handles stuff after the packet capture
        if wpcap:
            wrpcap(wpcap, capture)
        elif not rpcap:
            print()  # get rid of the Ctrl-C
            if confirm and not m.prompt(
                "Do you wish to save the pcap?", colour
            ):  # wont prompt if user said no
                exit(0)
            wpcap = input("Save it as: ")
            match check_write_ok(wpcap):
                case (True, _, _):
                    wrpcap(wpcap, capture)
                case (
                    False,
                    retval,
                    errstr,
                ) if retval > 0:  # theres an error as return value more than 0
                    m.warn(
                        f"Unable to save pcap file '{wpcap}' due to {errstr}",
                        colour,
                    )
        if ls_convos:  ##list conversations between two different addresses at the end
            # first part is for layer 1 which will always be there
            convos = "\n###layer 1###\n"
            if colour:
                for addr, amount in pairs_l2.items():
                    convos += f"{next(cy_col_ls)}{addr[0]} <==> {addr[1]}': {amount}{Style.RESET_ALL}\n"
            else:
                for addr, amount in pairs_l2.items():
                    convos += f"{addr[0]} <==> {addr[1]}': {amount}\n"
            if (
                pairs_ipv4 or pairs_ipv6
            ):  # there may or may not be stuff going on no higher than layer 2
                convos += "\n\n\n###layer 2###\n"
                if pairs_ipv4:
                    if colour:
                        for addr, amount in pairs_ipv4.items():
                            convos += f"{next(cy_col_ls)}{addr[0]} <==> {addr[1]}': {amount}{Style.RESET_ALL}\n"
                    else:
                        for addr, amount in pairs_ipv4.items():
                            convos += f"{addr[0]} <==> {addr[1]}': {amount}\n"
                if pairs_ipv6:
                    if colour:
                        for addr, amount in pairs_ipv6.items():
                            convos += f"{next(cy_col_ls)}{addr[0]} <==> {addr[1]}': {amount}{Style.RESET_ALL}\n"
                    else:
                        for addr, amount in pairs_ipv6.items():
                            convos += f"{addr[0]} <==> {addr[1]}': {amount}\n"
            if (
                pairs_tcp or pairs_udp
            ):  # there may or may not be stuff going on at layer 3
                convos += "\n\n\n###layer 3###\n"
                if pairs_tcp:  # if theres tcp conversations
                    if colour:
                        for addr, amount in pairs_tcp.items():
                            convos += f"{next(cy_col_ls)}{addr[0]} <==> {addr[1]}: {amount}{Style.RESET_ALL}\n"
                    else:
                        for addr, amount in pairs_tcp.items():
                            convos += f"{addr[0]} <==> {addr[1]}: {amount}\n"
                if pairs_udp:  # if theres udp conversations
                    if colour:
                        for addr, amount in pairs_udp.items():
                            convos += f"{next(cy_col_ls)}{addr[0]} <==> {addr[1]}: {amount}{Style.RESET_ALL}\n"
                    else:
                        for addr, amount in pairs_udp.items():
                            convos += f"{addr[0]} <==> {addr[1]}: {amount}\n"
            print(convos)
