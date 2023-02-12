#!/usr/bin/python3.10
import msg as m # custom messages
import args # arguments in program
import scapy.all as s
import scapy.layers.l2 as layer2
import scapy.layers.inet as ipv4
import scapy.layers.inet6 as ipv6
import scapy.layers.http


def proc_pkt(pkt): #handles sniffed packets
    num : int = 0
    if pkt.haslayer(layer2.ARP):
        print(f"ETHER_SRC: {pkt[layer2.Ether].src} | ETHER_DST: {pkt[layer2.Ether].dst}",
        end=" | ")
        print(f"ARP: {pkt[layer2.ARP].mysummary()}")
    if pkt.haslayer(scapy.layers.http.HTTPRequest): 
        url = (pkt[scapy.layers.http.HTTPRequest].Host+pkt[scapy.layers.http.HTTPRequest].Path).decode()
        print(f"PKT: {num} | IP_SRC: {pkt[ipv4.IP].src} | IP_DST: {pkt[ipv4.IP].dst}",
        end=" | ")
        print(f"URL: {url}")


if __name__ == "__main__":
    args = args.grab_args()
    filter = args.filter # BPF option, filters packets according to user pref
    colour = args.colourless # Determines if output is coloured

    if args.interface:
        interface = args.interface # Interface specified by user
    else:
        interface = s.conf.iface # First interface detected by Scapy


    try: 
        capture = s.sniff(prn=proc_pkt,iface=interface,filter=args.filter,count=0)
        if args.output:
            s.wrpcap(args.output,capture)
    except (PermissionError, OSError) as e:
       m.err(f"could not sniff on {interface} due to '{e.strerror.lower()}'",colour)
    except KeyboardInterrupt: 
        m.info("Program shutdown requested.",colour)
        m.info("Quitting...",colour)
        exit(0)
