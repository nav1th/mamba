#!/bin/python3
from msg import emesg
from args import grab_args
import pcap
import struct





def handle_packets(timestamp,pkt,*args):

        format_ip_addr = lambda pkt, offset: '.'.join(str(pkt[i]) for i in range(offset, offset + 4))
        format_mac_addr = lambda bytes_addr: ':'.join(map('{:02x}'.format,bytes_addr)).upper()
        dmac,smac,proto = struct.unpack('!6s 6s H',pkt[:handle.dloff]) 
        srcip = struct.unpack("!4B",bytes(pkt[handle.dloff+12]))

        """ 
        unpack destination MAC & source MAC & length of ethernet frame 
        most devices will using this program will be using IEEE 802.3 (ethernet) frames
        """
        ##TODO
        #figure how the fuck to inspect other deets of  the ipv4 header

        #in most cases will be 14 bytes because most packet sniffer's will be using 802.3 (ethernet) frames
        print(pkt)
        exit()

        dmac = format_mac_addr(dmac)
        smac = format_mac_addr(smac)
        print(f"\tSRC_MAC: %-16s\tSRC_DMAC: %-16s" %(smac,dmac))

        byte_after_dl = "0{0:b}".format(pkt[handle.dloff]) #the first byte after Datalink usually tells if it's IPv4, IPv6 etc.
        



        if int(byte_after_dl[:4],2) == 4: #if it's IPv4 
            print(f'\tIP_SRC:  %-16s\tIP_DST:   %-16s' % (format_ip_addr(pkt, handle.dloff + 12), format_ip_addr(pkt, handle.dloff + 16)))
        if int(byte_after_dl[:4],2) == 6: #if it's IPv6:
            pass
        print("------------------------------------------------------------------------------------------------")
    

if __name__ == "__main__":
      
    args = grab_args()

    if args.interface and args.readpcap:
        emesg("can't read from pcap and open interface for reading at once")
        exit(1)

    if args.non_promiscous == None:
        promiscous = True
    else:
        promiscous = False
    
    try:
        handle = pcap.pcap(args.interface,promisc=bool(args.non_promiscous),timeout_ms=500,immediate=False)
    except OSError as e:
        error = str(e)
        emesg(f"can't open interface due to '{error[90:-1]}'")
        exit(2)
    print(handle.name)

    if args.filter: #set any bpf filters
        handle.setfilter(args.filter)


    if handle.dloff != 14:
        emesg("device can't handle ethernet frames, exiting...")

    packets = 0


    handle.loop(0,handle_packets,packets)



