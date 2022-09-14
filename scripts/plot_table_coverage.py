#!/usr/bin/env python3.9

from prettytable import PrettyTable
import os, json

HOME_SGXMONITOR = os.getenv('SGXMONITOR_PATH')

def main():

    table_rows = []

    analyze3_folder = os.path.join(HOME_SGXMONITOR, "analyzer3")
    for d in os.listdir(analyze3_folder):
        if d.startswith("data_"):

            # 14 cols
            t_row = [0 for i in range(14)]

            n_function = 0
            n_static_function = 0
            tot_anal_time = 0
            avg_anal_time = 0
            std_anal_time = 0

            use_case = ""
            tradeoff_static = 0
            tradeoff_symex = 0
            tradeoff_delta = 0

            coverage = 0
            actions_avg = 0
            actions_stdev = 0
            edge_avg = 0
            edge_stdev = 0

            data_folder = os.path.join(analyze3_folder, d)
            # read statistics
            with open(os.path.join(data_folder, "statistics.txt")) as f:
                for l in f:
                    if l.startswith("n_function"):
                        n_function = l[len("n_function "):].strip()
                    if l.startswith("n_static function "):
                        n_static_function = l[len("n_static function "):].strip()
                    if l.startswith("tot. anal time "):
                        tot_anal_time_str = float(l[len("tot. anal time "):-4].strip())
                        tot_anal_time = f"{tot_anal_time_str:.2f}"
                    if l.startswith("avg. anal time "):
                        avg_anal_time_str = float(l[len("avg. anal time "):-4].strip())
                        avg_anal_time = f"{avg_anal_time_str:.2f}"
                    if l.startswith("std. dev anal time"):
                        std_anal_time_str = float(l[len("std. dev anal time "):-4].strip())
                        std_anal_time = f"{std_anal_time_str:.2f}"

            # read delta_info
            with open(os.path.join(data_folder, "delta_info.txt")) as f:
                f_str = f.readlines()
                f_str_1 = f_str[0].replace("'", "\"").strip()
                r = json.loads(f_str_1)
                print(r)

                use_case = r["use_case"]
                tradeoff_static = r["static"]
                tradeoff_symex = r["symex"]
                tradeoff_delta_str = r["delta"]
                tradeoff_delta = f"{tradeoff_delta_str:.2f}"

            with open(os.path.join(data_folder, "coverage.txt")) as f:
                for l in f:
                    if l.startswith("Coverage:"):
                        coverage_str = float(l[len("Coverage: "):].strip())*100
                        coverage = f"{coverage_str:.1f}%"
                    if l.startswith("Actions_Avg:"):
                        actions_avg_str = float(l[len("Actions_Avg: "):].strip())
                        actions_avg = f"{actions_avg_str:.2f}"
                    if l.startswith("Actions_Stdev:"):
                        actions_stdev_str = float(l[len("Actions_Stedv: "):].strip())
                        actions_stdev = f"{actions_stdev_str:.2f}"
                    if l.startswith("Edge_Avg:"):
                        edge_avg_str = float(l[len("Edge_Avg: "):].strip())
                        edge_avg = f"{edge_avg_str:.2f}"
                    if l.startswith("Edge_Stdev:"):
                        edge_stdev_str = float(l[len("Edge_Stedv: "):].strip())
                        edge_stdev = f"{edge_stdev_str:.2f}"


            t_row[0] = use_case
            t_row[1] = n_function
            t_row[2] = actions_avg
            t_row[3] = actions_stdev
            t_row[4] = edge_avg
            t_row[5] = edge_stdev
            t_row[6] = coverage
            t_row[7] = n_static_function
            t_row[8] = avg_anal_time
            t_row[9] = std_anal_time
            t_row[10] = tot_anal_time
            t_row[11] = tradeoff_static
            t_row[12] = tradeoff_symex
            t_row[13] = tradeoff_delta

            # print(f"n_function: {n_function}")
            # print(f"n_static_function: {n_static_function}")
            # print(f"tot_anal_time: {tot_anal_time}")
            # print(f"avg_anal_time: {avg_anal_time}")
            # print(f"std_anal_time: {std_anal_time}")

            table_rows += [t_row]

    x = PrettyTable()

    x.field_names = ["Use case", "#func", "act mu", "act std", "edge mu", "edge std", "act expl", "func static", "an. mu", "an. std", "an. tot.", "static", "symex", "delta%"]
    for r in table_rows:
        x.add_row(r)

    print(x)
    

if __name__ == "__main__":
    main()