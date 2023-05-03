from itertools import cycle
from d1 import D1
from d2 import D2


def mean(*nums: list[float]):
    means = []
    for x in nums:
        means.append(round(sum(x) / len(x), 2))
    if len(means) == 1:
        return means[0]
    return means


prog_index = cycle([("mamba", 0), ("tcpdump", 1), ("tshark", 2)])
for avrg in D1:
    print
    means_572kb = mean(avrg)
means_18mb = mean(mamba_speeds_18mb, tcpdump_speeds_18mb, tshark_speeds_18mb)
for x, y in prog_index:
    print(f"{x}: {means_572kb[y]} secs")

print("\n18mb pcap\n")
for x, y in prog_index:
    print(f"{x}: {means_18mb[y]} secs")
