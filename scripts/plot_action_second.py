#!/usr/bin/python3

import statistics
import csv
import matplotlib.pyplot as plt
import sys
from matplotlib.pyplot import cm
from matplotlib import colors
import numpy as np
from matplotlib.lines import Line2D
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

fPath = sys.argv[1]

fLen = sys.argv[2]

stats = {}

time = {}
lens = {}

with open(fLen, 'r') as f:
    cc = csv.reader(f, delimiter='|')
    for c in cc:
        if len(c) == 0:
            continue
        k = c[1]
        l = c[2]
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
    time[anonymFunc(k)] = v

p = []
for k1, l in lens.items():
    k = anonymFunc(k1)
    if k in time:
        t = time[k]
        # p.append((x,y))
        s = l/t*1000000
        p.append((k,s))
        print("{} : {}".format(k, s))

p.sort(key=lambda tup: tup[0])

val_x = [l for l,t in p]
val_y = [t for l,t in p]

print([t for l,t in p])

median = statistics.median([t for l,t in p])
print(f"median : {median}")

# print(val_x)

fig, ax = plt.subplots(figsize=(10,4))
plt.ylabel('#action/sec.', fontsize=18)
plt.xlabel('Secure function', fontsize=18)
# plt.title('Micro-benchmark')

# cmap = cm.get_cmap('Spectral')

ax.set_yscale('log')
barlist = plt.bar(val_x, val_y, color=(0.2, 0.4, 0.6, 0.6))

bar_colors = []
bar_labels = []
bar_todo = ['bx', 'ct', 'sd', 'ut']

for i in range(len(barlist)):
    if val_x[i].startswith('bx'):
        barlist[i].set_color('#c40000')
        if 'bx' in bar_todo:
            bar_colors += [Line2D([0], [0], color='#c40000', lw=4)]
            bar_labels += ['SGX-Biniax2']
            bar_todo.remove('bx')
    elif val_x[i].startswith('ct'):
        barlist[i].set_color('#00a30e')
        if 'ct' in bar_todo:
            bar_colors += [Line2D([0], [0], color='#00a30e', lw=4)]
            bar_labels += ['Contact']
            bar_todo.remove('ct')
    elif val_x[i].startswith('sd'):
        barlist[i].set_color('#007da3')
        if 'sd' in bar_todo:
            bar_colors += [Line2D([0], [0], color='#007da3', lw=4)]
            bar_labels += ['StealthDB']
            bar_todo.remove('sd')
    elif val_x[i].startswith('ut'):
        barlist[i].set_color('#5100a3')
        if 'ut' in bar_todo:
            bar_colors += [Line2D([0], [0], color='#5100a3', lw=4)]
            bar_labels += ['unit-test']
            bar_todo.remove('ut')
plt.legend(bar_colors, bar_labels, loc='upper left', prop={'size': 14})

plt.tight_layout()
plt.yticks(fontsize=14)
plt.xticks(fontsize=14)
ax.plot([-0.5, 17.5], [median, median], "k--", color='red')
plt.autoscale()  
# plt.savefig('action-second.eps', bbox_inches='tight', dpi=100, format='eps')
plt.savefig('action-second.jpg', bbox_inches='tight', dpi=100, format='jpg')
# plt.show()