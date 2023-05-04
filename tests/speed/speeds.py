from itertools import cycle
import sys
from d1 import D1
from d2 import D2


def mean(*nums: list[float]):
    means = []
    for x in nums:
        means.append(round(sum(x) / len(x), 2))
    if len(means) == 1:
        return means[0]
    return means

prog_index = ([
                ("mamba",0),
                ("tcpdump",1),
                ("tshark",2)],
                "572kb"),([("mamba",3),("tcpdump",4),("tshark",5)],"18mb")

for f_size_tests in prog_index:
    print(f_size_tests[1])
    for prog in f_size_tests:  
    means_572kb = mean(avrg)
    
means_18mb = mean(mamba_speeds_18mb, tcpdump_speeds_18mb, tshark_speeds_18mb)

for x, y in prog_index:
    print(f"{x}: {means_572kb[y]} secs")

print("\n18mb pcap\n")
for x, y in prog_index:
    print(f"{x}: {means_18mb[y]} secs")

if sys.platform == "win32":
    input("press enter to exit...")