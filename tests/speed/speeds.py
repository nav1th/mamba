from itertools import cycle
import sys
from d1 import D1
from d2 import D2


def mean(nums: list[float]):
    return round(sum(nums) / len(nums), 2)


d_tests = (
    ([("mamba", 0), ("tcpdump", 1), ("tshark", 2)], "572kb"),
    ([("mamba", 3), ("tcpdump", 4), ("tshark", 5)], "18mb"),
)

print("D1 tests")
for f_size_tests in d_tests:
    print(f"\t\n###{f_size_tests[1]}###")  #  file size
    for program in f_size_tests[0]:  # each program and their index relative to D1
        print(f"\t{program[0]}: {mean(D1[program[1]])}")  # mean of d1 tests

print("\nD2 tests")
for f_size_tests in d_tests:
    print(f"\t\n###{f_size_tests[1]}###")  #  file size
    for program in f_size_tests[0]:  # each program and their index relative to D2
        print(f"\t{program[0]}: {mean(D2[program[1]])}")  # mean of d2/ tests

if sys.platform == "win32":
    input("press enter to exit...")
