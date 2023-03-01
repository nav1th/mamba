import argparse
import msg as m
def grab_args():
    parser = argparse.ArgumentParser(
                        prog = "mamba",
                        description = "CLI packet sniffer written in python")
    parser.add_argument("-i","--interface",required=False,type=str,default=False,
                        help="Select network interface to listen on")
    parser.add_argument("-r","--read",required=False,default=False,
                        help="Select '.pcap' file to read packets from")
    parser.add_argument("-w","--write",required=False,default=False,
                        help="Writes packet capture to file")
    parser.add_argument("-n","--non-promiscous",dest="non_promiscous",required=False, action="store_false",
                        help="Listen in non-promiscous mode, e.g only get packets addressed to your network interface")
    parser.add_argument("-f","--filter",required=False,type=str,help="Uses BPF syntax to filter packets")
    parser.add_argument("-c","--count",required=False,type=int,default=0,help="Show only the first [COUNT] amount of packets")
    parser.add_argument("-v","--verbose", required=False, action="store_true")
    parser.add_argument("-cL","--colourless",required=False,action="store_false",help="Do not display coloured output")
    parser.add_argument("--no-confirm",dest="no_confirm",required=False,action="store_true",help="Do not ask for confirmation in (y/N) prompts, (automatic yes)")
    args = parser.parse_args()
    if args.interface and args.read:
        m.err("can't read from 'pcap' and listen on interface at the same time",args.colourless)
        exit(1)
    return args
