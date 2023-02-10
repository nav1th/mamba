import argparse
def grab_args():
    parser = argparse.ArgumentParser(
                        prog = "mamba",
                        description = "CLI packet sniffer written in python")
    parser.add_argument("-i","--interface",required=False,type=str,default=False,
                        help="Select network interface to listen on")
    parser.add_argument("-r","--readpcap",required=False,type=str,nargs="+",default=False,
                        help="Select '.pcap' file to read packets from")
    parser.add_argument("-n","--non_promiscous",required=False, action="store_true",
                        help="Listen in non-promiscous mode, e.g only get packets addressed to your network interface")
    parser.add_argument("-f","--filter",required=False,type=str,help="Uses BPF syntax to filter packets")
    parser.add_argument("-c","--count",required=False,type=int,default=0)
    parser.add_argument("-v","--verbose", required=False, action="store_true")
    parser.add_argument("-cL","--colourless",required=False,action="store_true")
    parser.add_argument("-o",required=False,action="store_true")
    return parser.parse_args()
