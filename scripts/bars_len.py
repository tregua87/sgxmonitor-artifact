#!/usr/bin/python3

import statistics
import csv
import matplotlib.pyplot as plt
import sys
from matplotlib.pyplot import cm
from matplotlib import colors
import numpy as np
import math

fPath = sys.argv[1]

fLen = sys.argv[2]

stats = {}

val = {}
lens = {}

with open(fLen, 'r') as f:
    cc = csv.reader(f, delimiter='|')
    for c in cc:
        k = c[0]
        l = c[1]
        lens[k] = int(l)

with open(fPath, 'r') as f:
    cc = csv.reader(f, delimiter='|')
    for c in cc:

        k = c[1]
        m = c[0]

        tt = stats.get(k, {})

        s = tt.get(m, [])

        s.append(int(c[2]))

        tt[m] = s

        stats[k] = tt

for k, ms in stats.items():
    v = statistics.mean(ms['traced_batch'])
    val[k] = v

p = []
for k, x in lens.items():
    if k in val:
        y = val[k]
        p.append((x,y))
        print("{} : {}".format(k, y/x))

p.sort(key=lambda tup: tup[1])

val_x = [x for x,y in p]
val_y = [y for x,y in p]


ig, ax = plt.subplots()
plt.scatter(val_x, val_y, color='b')
plt.xticks(rotation=90)
plt.show()
