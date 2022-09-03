#!/usr/bin/python3

import sys
import matplotlib.pyplot as plt


monitor = {'NUMERIC SORT': 0.45895, 'STRING SORT': 0.19964, 'BITFIELD': 1.7627e+05, 'FP EMULATION': 0.045961, 'FOURIER': 275.46, 'ASSIGNMENT': 0.0066335, 'IDEA': 1.8595, 'HUFFMAN': 0.93642, 'NEURAL NET': 0.027111, 'LU DECOMPOSITION': 0.62722 }


vanilla = {'NUMERIC SORT': 1335, 'STRING SORT': 43.382, 'BITFIELD': 5.5428e+08, 'FP EMULATION': 432.25, 'FOURIER': 1.1883e+05, 'ASSIGNMENT': 56.212, 'IDEA': 14801, 'HUFFMAN': 5951.4, 'NEURAL NET': 104.96, 'LU DECOMPOSITION': 2862.3 }

print(monitor)

print(vanilla)

overhead = {}

for (km, vm), (kv, vv) in zip(monitor.items(), vanilla.items()):
    if km != kv:
        print("{} - {}".format(km, kv))
        exit(0)
    # print({"{} = {}".format(km, vv/vm)})
    overhead[km] = vv/vm


x = []
y = []

for k, v in sorted(overhead.items(), key=lambda item: item[1]):
    x.append(k)
    y.append(v)


plt.plot(x, y, 'o-')
plt.xlabel('tests')
plt.ylabel('overhead')

plt.show()