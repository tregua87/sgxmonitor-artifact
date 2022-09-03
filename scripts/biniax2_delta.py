#!/usr/bin/python3

import statistics
import csv
import matplotlib.pyplot as plt
import sys
from matplotlib.pyplot import cm
from matplotlib.ticker import FormatStrFormatter
from matplotlib import colors
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
            values_y += [ ( float(v[0]), float(v[1]), v[2], int(v[3]) ) ]

    return values_y

# fVlc = load_log(sys.argv[1])
fBiniaxSgx = load_log(sys.argv[1])
fBiniaxSgxMonitor = load_log(sys.argv[2])

# print(fVlc)
# print(fVlcSgx)
# print(fVlcSgxMonitor)

val_x = range( min( len(fBiniaxSgx), len(fBiniaxSgxMonitor) ) )

print(len(val_x))

val_y_sgx = [t[0] for t in fBiniaxSgx]
val_y_sgxmonitor = [t[0] for t in fBiniaxSgxMonitor]

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

# plt.title("SGX-Biniax2 performance (CPU usage)")
plt.ylabel('%CPU', fontsize=18)
plt.xlabel('seconds', fontsize=18)

plt.rcParams['xtick.labelsize']=14
plt.rcParams['ytick.labelsize']=14

# cmap = cm.get_cmap('Spectral')

lsn2 = plt.plot(val_x, val_y_sgx, label='SGX-Biniax2 Vanilla')
lsn3 = plt.plot(val_x, val_y_sgxmonitor, label='SGX-Biniax2 + SgxMonitor')

delta = [abs(d1-d2)/min(d1,d2)*100 for d1, d2 in zip(val_y_sgx, val_y_sgxmonitor)]

ax2 = ax.twinx()
ax2.set_ylabel('overhead\nVanilla vs SgxMonitor', fontsize=18)
ax2.yaxis.set_major_formatter(FormatStrFormatter('%.0f%%'))
lsn4 = ax2.plot(val_x, delta, color = 'r')

lns = lsn2+lsn3 #+lsn4
labs = [l.get_label() for l in lns]
plt.legend(lns, labs, loc='upper center', ncol=2, bbox_to_anchor=(0.5, 1.2), prop={'size': 14})
# plt.legend()

# plt.xticks(val_x)
plt.tight_layout()

plt.fill_between(val_x, delta, color = 'r', alpha=0.3)

# plt.yticks(fontsize=14)
# plt.xticks(fontsize=14)
plt.autoscale()  
# plt.savefig('biniax2_performance.eps', bbox_inches='tight', dpi=100, format='eps')
plt.savefig('biniax2_performance.pdf', bbox_inches='tight', dpi=100, format='pdf')
# plt.savefig('biniax2_performance.jpg', bbox_inches='tight', dpi=100, format='jpg')
# plt.show()
