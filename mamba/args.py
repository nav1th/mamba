import argparse
import msg as m


def grab_args():
    parser = argparse.ArgumentParser(
        prog="mamba", description="CLI packet sniffer written in python"
    )
    parser.add_argument(
        "-i",
        "--interface",
        dest="iface",
        required=False,
        type=str,
        default=False,
        help="Select network interface to listen on",
    )
    parser.add_argument(
        "-r",
        "--read",
        required=False,
        default=False,
        metavar="FILE",
        help="Select '.pcap' file to read packets from",
    )
    parser.add_argument(
        "-w",
        "--write",
        required=False,
        default=False,
        metavar="FILE",
        help="Writes packet capture to file",
    )
    parser.add_argument(
        "-n",
        "--non-promiscous",
        dest="non_promiscous",
        required=False,
        action="store_false",
        help="Listen in non-promiscous mode, e.g only get packets addressed to your network interface",
    )
    parser.add_argument(
        "-f",
        "--filter",
        required=False,
        type=str,
        help="Uses BPF syntax to filter packets",
    )
    parser.add_argument(
        "-a",
        "--amount",
        required=False,
        type=int,
        default=0,
        metavar="NUM",
        help="Show only the first [COUNT] amount of packets",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        action="store_true",
        help="Make output more verbose, (outputs raw data)",
    )
    parser.add_argument(
        "-ncL",
        "--no-colour",
        dest="colour",
        required=False,
        action="store_false",
        help="Do not display coloured output",
    )
    parser.add_argument(
        "-nc",
        "--no-confirm",
        dest="confirm",
        required=False,
        action="store_false",
        help="Do not ask for confirmation in (y/N) prompts, (automatic yes)",
    )
    parser.add_argument(
        "-g",
        "--guess-service",
        dest="guess_service",
        required=False,
        action="store_true",
        help="Try to guess which TCP/UDP service, replacing the port number",
    )
    parser.add_argument(
        "-li",
        "--list-interfaces",
        dest="ls_ifaces",
        required=False,
        action="store_true",
        help="List interfaces available to the user",
    )
    parser.add_argument(
        "-lc",
        "--list-conversations",
        dest="ls_convos",
        required=False,
        action="store_true",
        help="List conversations between different addresses",
    )
    parser.add_argument(
        "-ns",
        "--no-save",
        dest="save",
        required=False,
        action="store_false",
        help="Disable save prompt at the end of live capture",
    )
    parser.add_argument(
        "-nd",
        "--no-date",
        dest="date",
        required=False,
        action="store_false",
        help="Disable showing the dates of packets captured",
    )
    parser.add_argument(
        "-nC",
        "--no-count",
        dest="count",
        required=False,
        action="store_false",
        help="Disable showing the dates of packets captured",
    )
    parser.add_argument(
        "--minimal",
        dest="minimal",
        required=False,
        action="store_true",
        help="Disables colouring, removes packet count and, removes date from output",
    )
    args = parser.parse_args()

    # incompatible arguments
    if args.iface and args.read:
        m.err(
            "can't read from 'pcap' file and listen on interface at the same time",
            args.colour,
        )
        exit(1)
    if args.ls_ifaces and (args.iface or args.read or args.ls_convos):
        m.err(
            "can't capture from pcaps or interfaces, while listing interfaces",
            args.colour,
        )
        exit(1)
    return args
