#!/usr/bin/python3

import statistics, csv, json
import matplotlib.pyplot as plt
import sys, os
from matplotlib.pyplot import cm
from matplotlib import colors
from matplotlib.ticker import FormatStrFormatter
import numpy as np
import math, re

def round_of_rating(number):
    return round(number * 2) / 2

def printStuff(val_x, val_y1, val_y2, title, xlabel, ylabel, deltatype, val_y1_err = None, val_y2_err = None):

    fig, ax = plt.subplots(figsize=(10,4))

    plt.rcParams.update({'font.size': 12, 'lines.markersize': 12})
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    
    # plt.title(title)
    plt.xlabel(xlabel, fontsize=18)
    plt.ylabel(ylabel, fontsize=18)

    val_x_enum = [(i + 1) for i, v in enumerate(val_x)]

    plt.grid(True)
    
    lns1 = ax.scatter(val_x_enum, val_y1, color='b', label="Vanilla", marker="x")
    lns2 = ax.scatter(val_x_enum, val_y2, color='g', label="SgxMonitor", marker="+")

    if val_y1_err:
        ax.errorbar(val_x_enum, val_y1, yerr=val_y1_err, linestyle="None", color='b')

    if val_y2_err:
        ax.errorbar(val_x_enum, val_y2, yerr=val_y2_err, linestyle="None", color='g')
    
    val_diff = []
    # for y1, y2 in zip(val_y1, val_y2):
    #     if y1 > y2:
    #         val_diff += [(y1/y2)]
    #     else:
    #         val_diff += [(y2/y1)]

    if deltatype == "slowdown":
        for y1, y2 in zip(val_y1, val_y2):
            if y1 > y2:
                val_diff += [(y1/y2)]
            else:
                val_diff += [(y2/y1)]
    elif deltatype == "percentage":
        # print("percentage")
        for y1, y2 in zip(val_y1, val_y2):
            if y1 < y2:
                val_diff += [(1-(float(y1)/float(y2)))*100]
            else:
                val_diff += [(1-(float(y2)/float(y1)))*100]
        # val_diff = [(e - 1)*100 for e in val_diff]
    else:
        print("unknown")
        exit()

    print(val_diff)

    plt.rcParams['xtick.labelsize']=14
    plt.rcParams['ytick.labelsize']=14

    ax2 = ax.twinx()
    ax2.yaxis.set_major_formatter(FormatStrFormatter('%.2f'))

    if deltatype == "slowdown":
        # print("do slowdown")
        ax2.set_ylabel('slowdown', fontsize=18)
        lns3 = ax2.scatter(val_x_enum, val_diff, color='r', label="Slowdown",  marker=".")
        ax2.yaxis.set_major_formatter(FormatStrFormatter('%.2fx'))
    elif deltatype == "percentage":
        # print("percentage")
        ax2.set_ylabel('overhead', fontsize=18)
        lns3 = ax2.scatter(val_x_enum, val_diff, color='r', label="Ovehead",  marker=".")
        # from IPython import embed; embed(); exit()
        plt.yticks(np.arange(np.floor(min(val_diff)), 1.75, 0.25))
        ax2.yaxis.set_major_formatter(FormatStrFormatter('%.2f%%'))
        # plt.yticks(np.arange(np.floor(min(val_diff)), round_of_rating(max(val_diff)+0.5)-0.5, 0.25))
    else:
        print("unknown")
        exit()

    lns = [lns1, lns2, lns3]
    labs = [l.get_label() for l in lns]
    plt.legend(lns, labs, loc='upper center', ncol=4, bbox_to_anchor=(0.5, 1.2), prop={'size': 14})
    # plt.legend()

    plt.xticks(val_x_enum)
    ax.set_xticklabels(val_x)
    plt.tight_layout()
    # plt.show()
    file_name = title.lower().replace(" ", "_")
    # plt.savefig(f'{file_name}.jpg', bbox_inches='tight', dpi=100, format='jpg')
    plt.savefig(f'{file_name}.eps', bbox_inches='tight', dpi=100, format='eps')

    avg_diff = sum(val_diff)/len(val_diff)
    # print(f"{title} : {avg_diff}")
    print(f"{title} | mean: {np.mean(val_diff)} | stdev: {np.std(val_diff)} | median: {np.median(val_diff)}")


fPath = sys.argv[1]

data_vanilla = {}
data_sgxmonitor = {}
is_vanilla = None

scale_factor = None
to_trace = False

for x in os.listdir(fPath):

    to_trace = False

    if x.startswith("vanilla_"):
        # print(f"a vanilla dir {x}")
        is_vanilla = True
        scale_factor = int(x.split("_")[1])
        to_trace = True

    if x.startswith("sgxmonitor_"):
        # print(f"an sgxmonitor dir {x}")
        is_vanilla = False
        scale_factor = int(x.split("_")[1])
        to_trace = True

    if to_trace:
        # n_test = 
        latency = []
        tps = []
        for res in os.listdir(os.sep.join([fPath, x])):
            if res.endswith(".res"):
                # print(f"analyze: {res}")
                with open(os.sep.join([fPath, x, res]), 'r') as f:
                    next(f)
                    for l in f:
                        if l.strip():
                            l_arr = l.split(",")
                            tps += [float(l_arr[1])]
                            latency += [float(l_arr[2])]
                            # n_test += 1
                            # print(f"{n_test} - {tps}")

        # print("finally!")
        # print(f"{n_test} - {tps}")

        tps_err = np.std(tps)
        tps = np.mean(tps)
        latency_err = np.std(latency)
        latency = np.mean(latency)

        if is_vanilla:
            data_vanilla[scale_factor] = (tps, latency, tps_err, latency_err)
        else:
            data_sgxmonitor[scale_factor] = (tps, latency, tps_err, latency_err)

# print(f"vanilla {data_vanilla}")
# print(f"sgxxmonitor data_sgxmonitor)

# exit()

val_x = []

val_y1_latency = []
val_y2_latency = []

val_y1_tps = []
val_y2_tps = []

val_y1_tps_error = []
val_y2_tps_error = []

val_y1_lat_error = []
val_y2_lat_error = []

# for s, (l, tpsw, tpswo) in data_vanilla.items():
for s, (tps, l, tps_e, l_e) in sorted(data_vanilla.items()):
    val_x += [int(s)]
    val_y1_tps += [float(tps)]
    val_y1_latency += [float(l)] 
    val_y1_tps_error += [float(tps_e)]
    val_y1_lat_error += [float(l_e)]

# for s, (l, tpsw, tpswo) in data_sgxmonitor.items():
for s, (tps, l, tps_e, l_e) in sorted(data_sgxmonitor.items()):
    val_y2_tps += [float(tps)]
    val_y2_latency += [float(l)] 
    val_y2_tps_error += [float(tps_e)]
    val_y2_lat_error += [float(l_e)]

print(val_y1_lat_error)
print(val_y2_lat_error)

printStuff(val_x, val_y1_latency, val_y2_latency, "Latency 2", "Scale Factor", "latency [ms]", "percentage", val_y1_lat_error, val_y2_lat_error)
printStuff(val_x, val_y1_tps, val_y2_tps, "Request per second", "Scale Factor", "requets per second", "slowdown", val_y1_tps_error, val_y2_tps_error)