mamba_speeds_500kb = [3.92, 4.12, 4.11, 3.97, 3.88]
tcpdump_speeds_500kb = [0.974, 0.223, 0.231, 0.245, 0.229]
tshark_speeds_500kb = [0.298, 0.169, 0.174, 0.176, 0.173]
mamba_speeds_18mb = [18.83, 17.82, 18.66, 18.44, 18.29]
tshark_speeds_18mb = [0.405, 0.393, 0.407, 0.388, 0.390]
tcpdump_speeds_18mb = [3.87, 1.38, 1.45, 1.76, 1.70]


def mean(*nums: list[float]):
    means = []
    for x in nums:
        means.append(round(sum(x) / len(x), 2))
    if len(means) == 1:
        return means[0]
    return means


prog_index = [("mamba", 0), ("tcpdump", 1), ("tshark", 2)]

means_500kb = mean(mamba_speeds_500kb, tcpdump_speeds_500kb, tshark_speeds_500kb)
means_18mb = mean(mamba_speeds_18mb, tcpdump_speeds_18mb, tshark_speeds_18mb)
print("500kb pcap\n")
for x, y in prog_index:
    print(f"{x}: {means_500kb[y]} secs")

print("\n18mb pcap\n")
for x, y in prog_index:
    print(f"{x}: {means_18mb[y]} secs")
