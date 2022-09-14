#!/usr/bin/env python3

from prettytable import PrettyTable
import os, json

HOME_SGXMONITOR = os.getenv('SGXMONITOR_PATH')

def get_sec_fun(use_case):
    if use_case == "Contact":
        return 6
    if use_case == "libdvdcss":
        return 4
    if use_case == "StealthDB":
        return 3
    if use_case == "SGX-Biniax2":
        return 7
    if use_case == "Unit-Test":
        return 3

    print(f"[ERROR] use case {use_case} unknown")
    exit(1)

def lookup_loc(file_path, use_case):
    print(file_path)
    print(use_case)

    with open(file_path) as f:
        for l in f:
            if l.startswith(use_case):
                return int(l.replace(f"{use_case}|".strip(), ""))
    
    print(f"[ERROR] LoC for use case {use_case} unknown")
    exit(1)

def main():

    table_rows = []

    statistic_folder = os.path.join(HOME_SGXMONITOR, "statistic_analysis")

    use_case = ""
    loc = 0
    node_avg = 0
    node_stdev = 0
    edge_avg = 0
    edge_stdev = 0
    n_sec_fun = 0
    cc_avg = 0
    cc_std = 0
    n_dc = 0
    n_ic = 0

    # read statistics from model
    with open(os.path.join(statistic_folder, "model.txt")) as f:
        for l in f:
            # 11 cols
            t_row = [0 for i in range(11)]

            for i, cstr in enumerate(l.split("|")):
                c = 0
                try:
                    c = float(cstr)
                except ValueError:
                    pass

                if i == 0:
                    use_case = cstr
                elif i == 1:
                    cc_avg = f"{c:.2f}"
                elif i == 2:
                    cc_std = f"{c:.2f}"
                elif i == 3:
                    node_avg = f"{c:.2f}"
                elif i == 4:
                    node_stdev = f"{c:.2f}"
                elif i == 5:
                    edge_avg = f"{c:.2f}"
                elif i == 6:
                    edge_stdev = f"{c:.2f}"
                elif i == 7:
                    continue
                elif i == 8:
                    continue
                elif i == 9:
                    n_dc = int(c)
                elif i == 10:
                    continue
                elif i == 11:
                    continue
                elif i == 12:
                    n_ic = int(c)

            loc = lookup_loc(os.path.join(statistic_folder, "loc.txt"), use_case)

            t_row[0] = use_case
            t_row[1] = loc
            t_row[2] = get_sec_fun(use_case)
            t_row[3] = cc_avg
            t_row[4] = cc_std
            t_row[5] = node_avg
            t_row[6] = node_stdev
            t_row[7] = edge_avg
            t_row[8] = edge_stdev
            t_row[9] = n_dc
            t_row[10] = n_ic

            table_rows += [t_row]

    x = PrettyTable()

    x.field_names = ["Use case", "LoC", "#sec. func", "cc mu", "cc std", "node mu", "node std", "edge mu", "edge std", "dir. call", "ind. call"]
    for r in table_rows:
        x.add_row(r)

    print(x)
    

if __name__ == "__main__":
    main()