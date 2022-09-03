#!/usr/bin/python3

import os, sys

inf = sys.argv[1]

ids = set()

with open(inf, 'r') as f:
    for ll in f:
        l = ll.split(":")[1]
        for a in l.split("->"):
            ids.add(a[3:-1].split(",")[0])

for i in ids:
    print("{}".format(i))