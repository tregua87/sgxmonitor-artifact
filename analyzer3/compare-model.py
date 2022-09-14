#!/usr/bin/env python3

import argparse, json, statistics

class ReportEnclave:
    def __init__(self):
        self.report_functions = []

    def add(self, r):
        self.report_functions.append(r)

    def get_coverage(self):
        tot_vtx = 0.0
        mis_vtx = 0.0
        for r in self.report_functions:
            tot_vtx += len(r.vertex_ground_truth)
            mis_vtx += len(r.vertex_missing)
        return 1-(float(mis_vtx)/float(tot_vtx))

    def get_average_action(self):
        actions = [len(r.vertex_ground_truth) for r in self.report_functions]
        return statistics.mean(actions)

    def get_stdev_action(self):
        actions = [len(r.vertex_ground_truth) for r in self.report_functions]
        return statistics.stdev(actions)

    def get_average_edge(self):
        edge = [sum(r.edge_ground_truth) for r in self.report_functions]
        return statistics.mean(edge)

    def get_stdev_edge(self):
        edge = [sum(r.edge_ground_truth) for r in self.report_functions]
        return statistics.stdev(edge)

class ReportFunction:
    def __init__(self, function_name, mgt, mtc):
        self.function_name = function_name
        self.model_ground_trurth = mgt
        self.model_to_check = mtc

        self.are_equal = False
        self.vertex_missing = []
        self.edge_missing = []
        self.vertex_ground_truth = []
        self.edge_ground_truth = []

        self.init()

        self.ariety_gt = [len(adj) for v, adj in self.model_ground_trurth.items()] 
        self.ariety_tc = [len(adj) for v, adj in self.model_to_check.items()] 

    def init(self):

        for v, adj in self.model_ground_trurth.items():
            # if v not in self.model_to_check:
            if not self.vertexIsIn(v, self.model_to_check):
                self.vertex_missing.append(v)
                for vv in adj:
                    self.edge_missing.append((v, vv))
            else:
                # adj_tc = self.model_to_check[v]
                adj_tc = self.getAdjFrom(v, self.model_to_check)
                for vv in adj:
                    # if vv not in adj_tc:
                    if not self.vertexIsIn(vv, adj_tc):
                        self.edge_missing.append((v, vv))

            self.vertex_ground_truth.append(v)
            self.edge_ground_truth.append(len(adj))

        # print(self.vertex_ground_truth)
        # print(self.edge_ground_truth)
        # exit()

        self.are_equal = len(self.vertex_missing) == 0 and len(self.edge_missing) == 0

    def vertexIsIn(self, v, mdl):
        if isinstance(mdl, dict):
            elem = mdl.keys()
        else:
            elem = mdl

        o = v[2:-1].split(", ")
        if len(o) == 3 and o[2] == "<?>":
            return any([o[0] == k[2:-1].split(", ")[0] for k in elem])
        else:
            return v in mdl

    def getAdjFrom(self, v, mdl):
        o = v[2:-1].split(", ")
        if len(o) == 3 and o[2] == "<?>":
            src = o[0]
            for k, adj in mdl.items():
                if src == k[2:-1].split(", ")[0]:
                    return adj
            raise Exception("{} not in {}".format(v, mdl))
        else:
            return mdl[v]

    def __repr__(self):
        return self.tostring()

    def __str__(self):
        return self.tostring()

    def tostring(self):
        s = "are_equal = {}\nvertex_missing = {}\nedge_missing = {}".format(self.are_equal, len(self.vertex_missing), len(self.edge_missing))
        #s += "\navg ariety gt = {}\nsdev ariety gt = {}\n".format(statistics.mean(self.ariety_gt), statistics.stdev(self.ariety_gt))
        #s += "\navg ariety tc = {}\nsdev ariety tc = {}\n".format(statistics.mean(self.ariety_tc), statistics.stdev(self.ariety_tc))

        s += "\nvertex_missing = {}".format(self.vertex_missing)

        return s



def load_model(model_file):
    model = {}
    with open(model_file, 'r') as f:
        model = json.load(f)
    return model


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model_ground_trurth', '-g', required=True, type=str, help='Ground truth model, it is considered the max overapproximation')
    parser.add_argument('--model_to_check', '-m', required=True, type=str, help='The model to compare with the ground truth')
    parser.add_argument('--function_name', '-f', required=False, type=str, help='Narrow the comparison to a specific function', default=None)

    args = parser.parse_args()

    mgt = args.model_ground_trurth
    mtc = args.model_to_check
    fnc = args.function_name

    m_mgt = load_model(mgt)
    m_mtc = load_model(mtc)

    # print(m_mgt)
    # print(m_mtc)

    if fnc is None:

        report_enclave = ReportEnclave()
        
        # I compare all the functions 
        for fnc in m_mgt.keys():
            if fnc in m_mtc:
                f_mgt = m_mgt[fnc]
                f_mtc = m_mtc[fnc]
                report = ReportFunction(fnc, f_mgt, f_mtc)
                if report.are_equal:
                    print("[OK] {}".format(fnc))
                elif not report.are_equal and len(report.vertex_missing) == 0:
                    print("[SUBS] {}".format(fnc))
                else:
                    print("[NOPE] {}".format(fnc))
                    print("\t - vertex: {}".format(len(report.vertex_missing)))
                    print("\t - edges: {}".format(len(report.edge_missing)))
                    print(report)
                    # exit()

                report_enclave.add(report)
            else:
                report = ReportFunction(fnc, m_mgt[fnc], {})
                report_enclave.add(report)
                print("[MISS] {}".format(fnc))

        print()
        print("Coverage: {}".format(report_enclave.get_coverage()))
        print("Actions_Avg: {}".format(report_enclave.get_average_action()))
        print("Actions_Stdev: {}".format(report_enclave.get_stdev_action()))
        print("Edge_Avg: {}".format(report_enclave.get_average_edge()))
        print("Edge_Stdev: {}".format(report_enclave.get_stdev_edge()))

        with open('coverage.txt', 'w') as f:
            f.write("Coverage: {}\n".format(report_enclave.get_coverage()))
            f.write("Actions_Avg: {}\n".format(report_enclave.get_average_action()))
            f.write("Actions_Stdev: {}\n".format(report_enclave.get_stdev_action()))
            f.write("Edge_Avg: {}\n".format(report_enclave.get_average_edge()))
            f.write("Edge_Stdev: {}\n".format(report_enclave.get_stdev_edge()))
        
    else:
        if fnc not in m_mgt:
            print("function {} not in {}".format(fnc, mgt))
            exit()
        if fnc not in m_mtc:
            print("function {} not in {}".format(fnc, m_mtc))
            exit()

        f_mgt = m_mgt[fnc]
        f_mtc = m_mtc[fnc]
        
        print("start comparison of {}".format(fnc))

        report = ReportFunction(fnc, f_mgt, f_mtc)

        if report.are_equal:
            print("[OK]")
        elif not report.are_equal and len(report.vertex_missing) == 0:
            print("[SUBS] {}".format(fnc))
        else:
            print("[NOPE]")

        print(report)
        if report.vertex_missing:
            print("missing vertex:")
            for v in report.vertex_missing:
                print(v)

        print()
        
        if report.edge_missing:
            print("missing edge:")
            for v in report.edge_missing:
                print(v)


if __name__ == "__main__":
    main()
