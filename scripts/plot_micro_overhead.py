#!/usr/bin/python3

import statistics
import csv
import matplotlib.pyplot as plt
import sys
from matplotlib.pyplot import cm
from matplotlib import colors
from matplotlib.patches import Patch
from matplotlib.lines import Line2D
from matplotlib.ticker import FormatStrFormatter
from matplotlib.ticker import StrMethodFormatter
import numpy as np
import math

def anonymFunc(fun):
    m = {'sgxsd_enclave_node_init': 'ct1', 
         'sgxsd_enclave_set_current_quote': 'ct2', 
         'sgxsd_enclave_negotiate_request': 'ct3',
         'sgxsd_enclave_server_start': 'ct4',
         'sgxsd_enclave_server_call': 'ct5',
         'sgxsd_enclave_server_stop': 'ct6',
         'sgxsd_enclave_get_next_report': 'SFX',
         'hello1': 'ut1',
         'hello2': 'ut2',
         'test_exception': 'ut3',
         'loadKeyEnclave': 'sd1',
         'generateKeyEnclave': 'sd2',
         'init_store': 'bx1', 
         'add_to_store': 'bx2', 
         'get_from_store': 'bx3', 
         'encrypt_store': 'bx4', 
         'decrypt_store': 'bx5', 
         'free_store': 'bx6',
         'store_to_bytes': 'bx7'}
    
    return m[fun]

bFile = sys.argv[1]

tags = ["traced_batch", "vanilla"]

stats = {}

with open(bFile) as f:
    for l in f:
        l_arr = l.strip().split("|")
        # print(l_arr)

        mode = l_arr[0]
        func = l_arr[1]
        time = l_arr[2]

        record = stats.get(func, {})

        acc_time = record.get(mode, 0)

        acc_time += float(time)

        record[mode] = acc_time

        stats[func] = record

d = {}

xs = []
for k, v in stats.items():
    x = v["traced_batch"]/v["vanilla"]
    v["ratio"] = x
    stats[k] = v
    # print("{} : {}".format(k, v))
    d[k] = x
    xs += [x]
    print(f"{k} = {x}")

median = statistics.median(xs)

print(f"median = {median}")

# print(stats)
# exit()

# d = {'sgxsd_enclave_node_init': 7.727545242589098,
#     'sgxsd_enclave_set_current_quote': 3.947206615074738,
#     'sgxsd_enclave_negotiate_request': 309.98861904351077,
#     'sgxsd_enclave_server_start': 9.939472861756434,
#     'sgxsd_enclave_server_call': 222.3604570978229,
#     'sgxsd_enclave_server_stop': 8.784381858083394,
#     'hello1': 4.617550515725728,
#     'hello2': 2.273466630640368}

d2 = [(anonymFunc(a),b) for a,b in d.items()]
d2.sort(key=lambda x: x[0])

lbl = [ k for k, v in d2 ]
val = [ v for k, v in d2 ]

# cmap = cm.get_cmap('Spectral')

fig, ax = plt.subplots(figsize=(10,4))
ax.set_yscale('log')
barlist = plt.bar(lbl, val, color=(0.2, 0.4, 0.6, 0.6))

# ax.yaxis.set_major_formatter(FormatStrFormatter('%sx'))
ax.yaxis.set_major_formatter(StrMethodFormatter('{x:.0f}x'))

bar_colors = []
bar_labels = []
bar_todo = ['bx', 'ct', 'sd', 'ut']

for i in range(len(barlist)):
    if lbl[i].startswith('bx'):
        barlist[i].set_color('#c40000')
        if 'bx' in bar_todo:
            bar_colors += [Line2D([0], [0], color='#c40000', lw=4)]
            bar_labels += ['SGX-Biniax2']
            bar_todo.remove('bx')
    elif lbl[i].startswith('ct'):
        barlist[i].set_color('#00a30e')
        if 'ct' in bar_todo:
            bar_colors += [Line2D([0], [0], color='#00a30e', lw=4)]
            bar_labels += ['Contact']
            bar_todo.remove('ct')
    elif lbl[i].startswith('sd'):
        barlist[i].set_color('#007da3')
        if 'sd' in bar_todo:
            bar_colors += [Line2D([0], [0], color='#007da3', lw=4)]
            bar_labels += ['StealthDB']
            bar_todo.remove('sd')
    elif lbl[i].startswith('ut'):
        barlist[i].set_color('#5100a3')
        if 'ut' in bar_todo:
            bar_colors += [Line2D([0], [0], color='#5100a3', lw=4)]
            bar_labels += ['unit-test']
            bar_todo.remove('ut')

plt.ylabel('slowdown', fontsize=18)
plt.xlabel('Secure function', fontsize=18)

plt.legend(bar_colors, bar_labels, loc='upper left', prop={'size': 14})

plt.yticks(fontsize=14)
plt.xticks(fontsize=14)
ax.plot([-0.5, 17.5], [median, median], "k--", color='red')
plt.tight_layout()
# plt.autoscale(True)  
# plt.savefig('multiply.eps', bbox_inches='tight', dpi=100, format='eps')
# plt.savefig('multiply.jpg', bbox_inches='tight', dpi=100, format='jpg')
plt.savefig('micro-overhead.jpg', bbox_inches='tight', dpi=100, format='jpg')
# plt.show()