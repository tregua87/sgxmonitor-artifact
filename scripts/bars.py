#!/usr/bin/python3

import statistics
import csv
import matplotlib.pyplot as plt
import sys
from matplotlib.pyplot import cm
from matplotlib import colors
from matplotlib.patches import Patch
import numpy as np
import math

def anonymFunc(fun):
    m = {'sgxsd_enclave_node_init - vanilla': 'SF0', 
         'sgxsd_enclave_node_init - traced_batch': '', 
         'sgxsd_enclave_set_current_quote - vanilla': 'SF1', 
         'sgxsd_enclave_set_current_quote - traced_batch': '',
         'sgxsd_enclave_negotiate_request - vanilla': 'SF2',
         'sgxsd_enclave_negotiate_request - traced_batch': '',
         'sgxsd_enclave_server_start - vanilla': 'SF3',
         'sgxsd_enclave_server_start - traced_batch': '',
         'sgxsd_enclave_server_call - vanilla': 'SF4',
         'sgxsd_enclave_server_call - traced_batch': '',
         'sgxsd_enclave_server_stop - vanilla': 'SF5',
         'sgxsd_enclave_server_stop - traced_batch': '',
         'hello1 - vanilla': 'SF6',
         'hello1 - traced_batch': '',
         'hello2 - vanilla': 'SF7',
         'hello2 - traced_batch': ''}
    
    return m[fun]

def beautify(mode):

    if mode == 'traced_batch':
        return "SgxMonitor"
    if mode == 'vanilla':
        return "Vanilla"

    return "<undef>"

fPath = sys.argv[1]

stats = {}

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

times = []
lbls = []

mode = []

for k, ms in stats.items():
    print("{}:".format(k))
    vanilla = None
    for m, v in ms.items():

        if not m in mode:
            mode.append(m)

        val_mean = statistics.mean(v)
        std_devt = statistics.stdev(v)

        if m == 'vanilla':
            vanilla = val_mean

        lbls.append("{} - {}".format(k,m))
        # lbls.append(m)

        times.append(val_mean)
        # err.append(std_devt)

    if vanilla:
        print("vanilla: {}us".format(vanilla))

        for m, v in ms.items():
            if m == 'vanilla':
                continue

            val_mean = statistics.mean(v)

            print("{}: {}us".format(m, val_mean))
            print("vanilla vs {}: {}X".format(m, val_mean/vanilla))
    else:
        print("Vanilla not found for {}".format(k))

    print()
    print()

# exit()

print("-"*30)

# from IPython import embed; embed()

cmap = cm.get_cmap('Spectral')

norm = colors.Normalize(vmin=0, vmax=len(mode))
colorMap = [ cmap(norm(i)) for i in range(len(mode)) ]

colors = []
for i, l in enumerate(lbls):
    colors.append(colorMap[ i % len(mode) ])

# print(lbls)

lbls_an = [ anonymFunc(l) for l in lbls]

# print(lbls_an)
# exit()

fig, ax = plt.subplots()
ax.set_yscale('log')
plt.bar(range(len(lbls)), times, color=colors)

plt.xticks([x+0.5 for x in range(len(lbls))], lbls_an)
plt.ylabel('Execution time [us]')
plt.xlabel('Secure functions')
# plt.title('Micro-benchmark')

legend_elements = [Patch(facecolor=c, label=beautify(m)) for c, m in zip(colors, mode)]

ax.legend(handles=legend_elements)

plt.tight_layout()
plt.yticks(fontsize=12)
plt.xticks(fontsize=12)
plt.savefig('overhead.png')
# plt.show()
