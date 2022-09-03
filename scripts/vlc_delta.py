#!/usr/bin/python3

import statistics
import csv
import matplotlib.pyplot as plt
import sys
from matplotlib.pyplot import cm
from matplotlib import colors
from matplotlib.ticker import FormatStrFormatter
import numpy as np
import math

# ./vlc_performancec.py ../results/vlc_css.txt ../results/vlc_css_sgx.txt ../results/vlc_css_sgxmonitor.txt  ../src/monitor_batch/vlc_css_sgxmonitor2.txt ../src/monitor_batch/vlc_css_sgxmonitor3.txt ../src/monitor_batch/vlc_css_sgxmonitor4.txt

def load_log(fileName):

    values_y = []

    with open(fileName) as f:
        for l in f:
            if "CPU" in l:
                continue
                
            v = l.strip().split()
            # print(v)
            values_y += [ ( float(v[0]), float(v[1]), " ".join([v[2], v[3]]), int(v[4]) ) ]

    return values_y

fVlc = load_log(sys.argv[1])
fVlcSgx = load_log(sys.argv[2])
fVlcSgxMonitor = load_log(sys.argv[3])

# print(fVlc)
# print(fVlcSgx)
# print(fVlcSgxMonitor)

val_x = range( min( len(fVlc), len(fVlcSgx), len(fVlcSgxMonitor) ) )

print(len(val_x))

val_y = [t[0] for t in fVlc]
val_y_sgx = [t[0] for t in fVlcSgx]
val_y_sgxmonitor = [t[0] for t in fVlcSgxMonitor]

if len(val_x) < len(val_y):
    del val_y[-(len(val_y)-len(val_x)):]

if len(val_x) < len(val_y_sgx):
    del val_y_sgx[-(len(val_y_sgx)-len(val_x)):]

if len(val_x) < len(val_y_sgxmonitor):
    del val_y_sgxmonitor[-(len(val_y_sgxmonitor)-len(val_x)):]


plt.rcParams['xtick.labelsize']=14
plt.rcParams['ytick.labelsize']=14

fig, ax = plt.subplots(figsize=(10,4))

# plt.rcParams.update({'font.size': 12, 'lines.markersize': 12})
# plt.xticks(fontsize=12)
# plt.yticks(fontsize=12)

# plt.title("VLC performance (CPU usage)")
plt.ylabel('%CPU', fontsize=18)
plt.xlabel('seconds', fontsize=18)

# cmap = cm.get_cmap('Spectral')

lsn1 = plt.plot(val_x, val_y, label='VLC Vanilla')
lsn2 = plt.plot(val_x, val_y_sgx, label='VLC + SGX')
lsn3 = plt.plot(val_x, val_y_sgxmonitor, label='VLC + SgxMonitor')


delta = [abs(d1-d2)/min(d2,d2)*100 for d1, d2 in zip(val_y_sgx, val_y_sgxmonitor)]

ax2 = ax.twinx()
ax2.set_ylabel('overhead\nVanilla vs SgxMonitor', fontsize=18)
ax2.yaxis.set_major_formatter(FormatStrFormatter('%.0f%%'))
lsn4 = ax2.plot(val_x, delta, color = 'r')

lns = lsn1+lsn2+lsn3 #+lsn4
labs = [l.get_label() for l in lns]
plt.legend(lns, labs, loc='upper center', ncol=3, bbox_to_anchor=(0.5, 1.2), prop={'size': 14})
# plt.legend()

# plt.xticks(val_x)
plt.tight_layout()

plt.fill_between(val_x, delta, color = 'r', alpha=0.3)

# plt.yticks(fontsize=14)
# plt.xticks(fontsize=14)
plt.autoscale()  
# plt.savefig('vlc_performance.eps', bbox_inches='tight', dpi=100, format='eps')
plt.savefig('vlc_performance.pdf', bbox_inches='tight', dpi=100, format='pdf')
# plt.savefig('vlc_performance.jpg', bbox_inches='tight', dpi=100, format='jpg')
# plt.show()
