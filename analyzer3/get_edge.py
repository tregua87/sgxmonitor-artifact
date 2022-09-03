#!/usr/bin/env python3

import json, os, argparse

def get_edges(model_static, ignored_functions):
    edges = {}

    with open(model_static) as f:
        model = json.load(f)

    for f, m in model.items():
        # print(f)
        if f in ignored_functions:
            continue
        n_edges = sum([ len(adj) for e, adj in m.items() ])
        edges[f] = n_edges

    return edges

def get_avg_edges(edges_static):

    n_function = len(edges_static.keys())
    if n_function == 0:
        return 0

    n_edges = sum([e for f, e in edges_static.items()])
    return n_edges/n_function

def get_functions(model):

    if not os.path.exists(model):
        return []

    fnc = set()
    with open(model, 'r') as f:
        for l in f:
            l = l.strip()
            if ">:" in l:
                f_name = l[1:-2]
                if f_name == "end":
                    continue
                fnc.add(f_name)

    return list(fnc)

def _main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--use_case', required=True, type=str, help='Use case name')
    parser.add_argument('--model_static',  required=True, type=str, help='Model extracted with ONLY static analysis')
    parser.add_argument('--model_symex', required=True, type=str, help='Model extracted with symex')
    parser.add_argument('--model_insensitive', required=True, type=str, help='Model extracted with static analysis in case of symex timeout')

    args = parser.parse_args()

    model_static = args.model_static
    model_symex = args.model_symex
    model_insensitive = args.model_insensitive
    use_case = args.use_case

    ignored_functions = get_functions(model_insensitive)
    
    edges_static = get_edges(model_static, ignored_functions)
    edges_symex = get_edges(model_symex, ignored_functions)

    # for (k1, static), (k2, symex) in zip(edges_static.items(), edges_symex.items()):
    #     if symex > static:
    #         print(f"{k1} {static} {symex}")

    edges_static = sum([e for f, e in edges_static.items()])
    # print(f"static {edges_static}")

    edges_symex = sum([e for f, e in edges_symex.items()])
    # print(f"symex {edges_symex}")

    delta = 100 * (edges_static - edges_symex) / edges_static 

    d = {}
    d["use_case"] = use_case
    d["static"] = edges_static
    d["symex"] = edges_symex
    d["delta"] = delta
    d["ignored_functions"] = ignored_functions

    print(d)

    # print(f"static {edges_static} \t symex {edges_symex} \t perc. delta {delta}%")


    # edges_avg = get_avg_edges(edges_static)
    # print(f"For static analysis: {edges_avg}")

    # edges_avg = get_avg_edges(edges_symex)
    # print(f"For symex analysis: {edges_avg}")

if __name__ == "__main__":
    _main()
    