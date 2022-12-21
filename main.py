#!/bin/python3
from msg import emesg
from args import grab_args
from libpcap import *
from ctypes import *

config(LIBPCAP=None)

def get_device_handle(device: str,file: str,promiscous: bool,errbuf: Array[c_char]):
    if args.file == None:
        handle: pcap_t =  open_live(device,PCAP_BUF_SIZE,c_int(promiscous), c_int(1000),errbuf) #open device for live capture
        return handle
    else:
        handle: pcap_t = open_dead(file.encode(),errbuf)
        return handle

if __name__ == "__main__":
    ERROR =  c_int32(-1)
    errbuf: Array[c_char] = create_string_buffer(PCAP_ERRBUF_SIZE) #for storing error messages
    bpf = bpf_program.in_dll
    net: bpf_u_int32 = bpf_u_int32(0)
    mask: bpf_u_int32 = bpf_u_int32(0)
  
    args = grab_args()

    if args.interface == None:
        devices = pointer(pcap_if_t.from_address(1000)) 
        findalldevs(byref(devices),errbuf) #get list of interfaces
        device = devices[0].name #first interface which shows
    else:
        device  = args.interface.encode() #interface which user specified

    if lookupnet(device,net,mask,errbuf) == c_int32(-1):
        net: bpf_u_int32 = bpf_u_int32(0)
        mask: bpf_u_int32 = bpf_u_int32(0)
        exit(1)

    if args.non_promiscous == None:
        promiscous = True
    else:
        promiscous = False

    handle = get_device_handle(device,args.file,promiscous,errbuf)

    if not handle:
        emesg(f"{errbuf.raw.decode()}")
        exit(1)

    if datalink(handle) != DLT_EN10MB: #check if device supports ethernet headers
        emesg(f"Device {device} doesn't provide Ethernet headers - not supported");
        exit(2)

    if args.filter != None:
        if compile(handle,bpf,args.filter,0,net) == ERROR:
            emesg(f"could not parse filter {args.filter}: {geterr(handle)}")
            exit(3)

        if setfilter(handle, bpf) == ERROR:
            emesg(f"could not install filter {args.filter}: {geterr(handle)}")
            exit(4)





    pass

