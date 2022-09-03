#!/usr/bin/python3

import statistics, csv, json
import matplotlib.pyplot as plt
import sys
from matplotlib.pyplot import cm
from matplotlib import colors
import numpy as np
import math, re

def printStuff(val_x, val_y1, val_y2, title, xlabel, ylabel):

    fig, ax = plt.subplots()

    plt.rcParams.update({'font.size': 12, 'lines.markersize': 12})
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    
    plt.title(title)
    plt.xlabel(xlabel, fontsize=12)
    plt.ylabel(ylabel, fontsize=12)

    # plt.scatter(val_x, val_y1, color='b', label="Vanilla", marker="x")
    # plt.scatter(val_x, val_y2, color='r', label="SgxMonitor", marker="*")
    lns1 = ax.plot(val_x, val_y1, color='b', label="Vanilla", marker="x")
    lns2 = ax.plot(val_x, val_y2, color='g', label="SgxMonitor", marker="*")
    # ax.legend(loc=0)

    val_diff = []
    for y1, y2 in zip(val_y1, val_y2):
        if y1 > y2:
            # val_diff += [y2/y1]
            val_diff += [y1/y2]
        else:
            # val_diff += [y1/y2]
            val_diff += [y2/y1]

    print(val_diff)

    ax2 = ax.twinx()
    ax2.set_ylabel('Percentage (%)')
    lns3 = ax2.plot(val_x, val_diff, color='r', label="Overhead (%)")
    # ax2.tick_params(axis='y', labelcolor=color)

    lns = lns1+lns2+lns3
    labs = [l.get_label() for l in lns]
    plt.legend(lns, labs, loc=0)
    # plt.legend()

    plt.xticks(val_x)
    plt.tight_layout()
    # plt.show()
    file_name = title.lower().replace(" ", "_")
    plt.savefig(f'{file_name}.jpg', bbox_inches='tight', dpi=100, format='jpg')

    avg_diff = sum(val_diff)/len(val_diff)
    print(f"{title} : {avg_diff}")



fPath = sys.argv[1]

data_vanilla = {}
data_sgxmonitor = {}
is_vanilla = None

scale_factor = None
latency_average = None
tps_wconn = None
tps_woconn = None

with open(fPath, 'r') as f:
    r = json.load(f)

    # from IPython import embed; embed(); exit()

    for (s, (l,tpsw, tpswo)) in r["SgxMonitor"]:
        data_sgxmonitor[s] = (l,tpsw, tpswo)

    for (s, (l,tpsw, tpswo)) in r["Vanilla"]:
        data_vanilla[s] = (l,tpsw, tpswo)

    # for l in f:
    #     if "VANILLA" in l:
    #         is_vanilla = True
    #         continue
    #     elif "SGXMONITOR" in l:
    #         is_vanilla = False
    #         continue

    #     if not scale_factor and "s " in l:
    #         scale_factor = re.findall(r's +(\d+)', l)[0]

    #     if not latency_average and "latency average" in l:
    #         latency_average = re.findall(r'latency average = (\d+.\d+) ms', l)[0]

    #     if not tps_wconn and "including connections establishing" in l:
    #         tps_wconn = re.findall(r'tps = (\d+.\d+) \(including connections establishing\)', l)[0]

    #     if not tps_woconn and "excluding connections establishing" in l:
    #         tps_woconn = re.findall(r'tps = (\d+.\d+) \(excluding connections establishing\)', l)[0]

    #     if scale_factor and latency_average and tps_wconn and tps_woconn:
    #         key = None
    #         # if is_vanilla:
    #         #     key = "vanilla"
    #         # else:
    #         #     key = "sgxmonitor"
    #         # print(f"{key}:")
    #         # print(f"{scale_factor} => ({latency_average}, {tps_wconn}, {tps_woconn})")

    #         if is_vanilla:
    #             data_vanilla[scale_factor] = (latency_average, tps_wconn, tps_woconn)
    #         else:
    #             data_sgxmonitor[scale_factor] = (latency_average, tps_wconn, tps_woconn)

    #         scale_factor = None
    #         latency_average = None
    #         tps_wconn = None
    #         tps_woconn = None



val_x = []

val_y1_latency = []
val_y2_latency = []

val_y1_tpsw = []
val_y2_tpsw = []

val_y1_tpswo = []
val_y2_tpswo = []

for s, (l, tpsw, tpswo) in data_vanilla.items():
    val_x += [int(s)]
    val_y1_latency += [float(l)]
    val_y1_tpsw += [float(tpsw)]
    val_y1_tpswo += [float(tpswo)]

for s, (l, tpsw, tpswo) in data_sgxmonitor.items():
    val_y2_latency += [float(l)]
    val_y2_tpsw += [float(tpsw)]
    val_y2_tpswo += [float(tpswo)]

print(val_x)
print(val_y1_latency)
print(val_y1_latency)

printStuff(val_x, val_y1_latency, val_y2_latency, "Latency", "Scale Factor", "Latency [ms]")
printStuff(val_x, val_y1_tpsw, val_y2_tpsw, "Transactions per second including connections establishing", "Scale Factor", "TPS")
printStuff(val_x, val_y1_tpswo, val_y2_tpswo, "Transactions per second excluding connections establishing", "Scale Factor", "TPS")