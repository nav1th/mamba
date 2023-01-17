#!/usr/bin/python3.10
import msg as m # custom messages
import args # arguments in program
import scapy.all as s
if __name__ == "__main__":
    args = args.grab_args()
    if args.interface:
        interface = args.interface
    else:
        interface = s.conf.iface
    try: 
        handle = s.sniff(iface=interface,filter=args.filter,count=2)
    except (PermissionError, OSError) as e:
       m.emesg(f"could not sniff on {interface} due to '{e.strerror.lower()}'")


    pass
