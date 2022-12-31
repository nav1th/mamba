#!/bin/python3
from msg import emesg
from args import grab_args
from libpcap import *
from ctypes import *
import signal

config(LIBPCAP=None)

def find_interface():
    devices = pointer(pcap_if.from_address(1000)) 
    findalldevs(byref(devices),errbuf) #get list of interfaces
    device = devices[0].name
    return device

def get_live_handle(device,file: str,promiscous: bool,errbuf: Array[c_char]):
    if args.file == None:
        handle: pcap_t =  open_live(device,PCAP_BUF_SIZE,c_int(promiscous), c_int(1000),errbuf) #open device for live capture
        return handle
    else:
        handle: pcap_t = open_offline(file.encode(),errbuf)
        return handle

def get_ll_hl(handle: pcap_t):
    ll_type = datalink(handle)
    if ll_type == PCAP_ERROR:
        return None;
    elif ll_type == DLT_EN10MB: ## ethernet is all im handling for now, may expand
        return 14

def stop_capture():
    pcap_stats = stats(pcap_handle)
    if pcap_stats >= c_int(0):
        print(f"{packets} packets captured")
    exit(0)

@CFUNCTYPE(None,POINTER(c_ubyte),POINTER(pkthdr),POINTER(c_ubyte))
def handle_packets(user,header,packet):
    pass
 
if __name__ == "__main__":
    errbuf: Array[c_char] = create_string_buffer(PCAP_ERRBUF_SIZE) #for storing error messages
    bpf = bpf_program.in_dll
    net: bpf_u_int32 = bpf_u_int32(0)
    mask: bpf_u_int32 = bpf_u_int32(0)
    packets = 0
    pcap_handle = POINTER(pcap_t)
    
    args = grab_args()

    
    if args.interface == None:
        device = find_interface()
    else:
        device  = args.interface.encode() #interface which user specified

    if args.non_promiscous == None:
        promiscous = True
    else:
        promiscous = False

    pcap_handle = get_live_handle(device,args.file,promiscous,errbuf)

    if not pcap_handle:
        emesg(f"{errbuf.raw.decode()}")
        exit(1)

    ll_hl = get_ll_hl(pcap_handle)
    if ll_hl == None: #check if device supports ethernet headers
        emesg(f"Device {device} doesn't provide Ethernet headers - not supported");
        exit(2)

    if args.filter != None:
        if compile(pcap_handle,bpf,args.filter,0,net) == PCAP_ERROR:
            emesg(f"could not parse filter {args.filter}: {geterr(pcap_handle)}")
            exit(3)

        if setfilter(pcap_handle, bpf) == PCAP_ERROR:
            emesg(f"could not install filter {args.filter}: {geterr(pcap_handle)}")
            exit(4)

    #signal.signal(signal.SIGINT,stop_capture)
    #signal.signal(signal.SIGTERM,stop_capture)
    #signal.signal(signal.SIGQUIT,stop_capture)

    #if loop(pcap_handle,c_int(args.count),handle_packets,c_ubyte(0)) < c_int(0):
    #    emesg(f"pcap_loop failed: {geterr(pcap_handle).raw.decode()}")
    #    exit(5)

    #stop_capture(0)


