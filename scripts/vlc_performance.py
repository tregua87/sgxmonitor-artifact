#!/usr/bin/python3

import statistics
import csv
import matplotlib.pyplot as plt
import sys
from matplotlib.pyplot import cm
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
            values_y += [ ( float(v[0]), float(v[1]), " ".join([v[2], v[3]]), int(v[4]) ) ]

    return values_y

fVlc = load_log(sys.argv[1])
fVlcSgx = load_log(sys.argv[2])
fVlcSgxMonitor = load_log(sys.argv[3])

fVlcSgxMonitor1 = load_log(sys.argv[4])
fVlcSgxMonitor2 = load_log(sys.argv[5])
fVlcSgxMonitor3 = load_log(sys.argv[6])

# print(fVlc)
# print(fVlcSgx)
# print(fVlcSgxMonitor)

val_x = range( min( len(fVlc), len(fVlcSgx), len(fVlcSgxMonitor), len(fVlcSgxMonitor1), len(fVlcSgxMonitor2), len(fVlcSgxMonitor3) ) )

print(len(val_x))

val_y = [t[0] for t in fVlc]
val_y_sgx = [t[0] for t in fVlcSgx]
val_y_sgxmonitor = [t[0] for t in fVlcSgxMonitor]

val_y_sgxmonitor1 = [t[0] for t in fVlcSgxMonitor1]
val_y_sgxmonitor2 = [t[0] for t in fVlcSgxMonitor2]
val_y_sgxmonitor3 = [t[0] for t in fVlcSgxMonitor3]

if len(val_x) < len(val_y):
    del val_y[-(len(val_y)-len(val_x)):]

if len(val_x) < len(val_y_sgx):
    del val_y_sgx[-(len(val_y_sgx)-len(val_x)):]

if len(val_x) < len(val_y_sgxmonitor):
    del val_y_sgxmonitor[-(len(val_y_sgxmonitor)-len(val_x)):]


if len(val_x) < len(val_y_sgxmonitor1):
    del val_y_sgxmonitor1[-(len(val_y_sgxmonitor1)-len(val_x)):]

if len(val_x) < len(val_y_sgxmonitor2):
    del val_y_sgxmonitor2[-(len(val_y_sgxmonitor2)-len(val_x)):]

if len(val_x) < len(val_y_sgxmonitor3):
    del val_y_sgxmonitor3[-(len(val_y_sgxmonitor3)-len(val_x)):]

fig, ax = plt.subplots()

plt.ylabel('%CPU', fontsize=18)
plt.xlabel('seconds', fontsize=18)
# plt.title('Micro-benchmark')

# cmap = cm.get_cmap('Spectral')

# ax.set_yscale('log')
plt.plot(val_x, val_y, label='VLC + CSS')
plt.plot(val_x, val_y_sgx, label='VLC + CSS + SGX')
plt.plot(val_x, val_y_sgxmonitor, label='VLC + CSS + SGX-Monitor')

# plt.plot(val_x, val_y_sgxmonitor1, label='VLC + CSS + SGX-Monitor (10000)')
# plt.plot(val_x, val_y_sgxmonitor2, label='VLC + CSS + SGX-Monitor (1000)')
plt.plot(val_x, val_y_sgxmonitor3, label='VLC + CSS + SGX-Monitor (5000)')

plt.legend()

plt.tight_layout()
plt.yticks(fontsize=14)
plt.xticks(fontsize=14)
plt.autoscale()  
# plt.savefig('vlc_performance.eps', bbox_inches='tight', dpi=100, format='eps')
plt.savefig('vlc_performance.jpg', bbox_inches='tight', dpi=100, format='jpg')
# plt.show()
