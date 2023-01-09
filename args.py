import argparse
def grab_args():
    parser = argparse.ArgumentParser(
                        prog = 'mamba',
                        description = 'CLI packet sniffer written in python')
    parser.add_argument('-i','--interface',required=False,type=str,default=False)
    parser.add_argument('-r','--readpcap',required=False,type=str,nargs='+',default=False)
    parser.add_argument('-n','--non_promiscous',required=False)
    parser.add_argument("-f","--filter",required=False,type=str)
    parser.add_argument("-c","--count",required=False,type=int,default=0)
    return parser.parse_args()
