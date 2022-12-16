#!/bin/python3
from msg import error
from libpcap import *
from ctypes import c_char_p, create_string_buffer, c_int
import argparse

config(LIBPCAP=None)


def grab_args():
    parser = argparse.ArgumentParser(
                        prog = 'mamba',
                        description = 'CLI packet sniffer written in python')
    parser.add_argument('-i','--interface',required=False,type=str,nargs=1)
    return parser.parse_args()

if __name__ == "__main__":
    args = grab_args()
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE) #for storing error messages

    if args.interface != None:
        args.interface.as_bytes()
        dev = c_char_p(args.interface)
    else:
        dev = lookupdev(errbuf) #automatically find network interface to sniff
        if dev == b"any": #did not detect suitable interface
            error(f"could not find default device") 
            exit(1)


    handle = open_live(dev,PCAP_BUF_SIZE,c_int(0), c_int(1000),errbuf)
    datalink_ext(handle)



    pass

