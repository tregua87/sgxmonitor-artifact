#!/usr/bin/python3

import sys, argparse, ntpath, os, re

def getOperands(l):
    # print(l)
    typ = l[0]
    el = l[2:-1].split(", ")

    if len(el) == 2:
        (op1, op2) = el
        tag = None
    elif len(el) == 3:
        (op1, op2, tag) = el
        tag = tag[1:-1]
    else:
        raise Exception("{} is not a valid action".format(l))

    op1 = int(op1, 16)
    if op1 > 0x7FFFFFFFFFFFFFFF:
        op1 -= 0x10000000000000000 
    # if op2 == "0xfffffffe":
    #     op2 = -2
    # else:
    #     op2 = int(op2, 16)
    op2 = int(op2, 16)
    if op2 > 0x7FFFFFFFFFFFFFFF:
        op2 -= 0x10000000000000000 

    return (typ,op1,op2,tag)

def parseEdges(edges_in):
    edges = []

    with open(edges_in, 'r') as f:
        for l in f:
            if l.strip():
                edges.append(getOperands(l.strip()))

    edges.pop()

    return edges

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--edges', '-e', required=True, type=str, help='List of Edges')
    parser.add_argument('--first_action', '-f', required=True, type=str, help='First action used to infer the base address')
    parser.add_argument('--normalized_edges', '-n', required=True, type=str, help='Output for normalized edges')

    args = parser.parse_args()

    f_edges = args.edges
    first_action = args.first_action
    normalized_edges = args.normalized_edges

    # print(edges)
    # print(first_action)

    t_addr = int(re.findall(r"T\[(0x[a-f0-9]+)", first_action)[0], 16)
    
    edges = parseEdges(f_edges)

    e_baseadd = None

    print(t_addr)

    with open(normalized_edges, 'a+') as n_edges:
        for i, e in enumerate(edges):

            if i == 0:
                e_baseadd = e[1] - t_addr

            ne_1 = e[1] - e_baseadd
            if ne_1 < 0:
                ne_1 += 0x10000000000000000

            ne_2 = e[2] - e_baseadd
            if ne_2 < 0:
                ne_2 += 0x10000000000000000

            # from IPython import embed; embed(); exit()
            
            ne = (e[0], ne_1, ne_2, e[3])

            n_edges.write(f"{ne[0]}[0x{ne[1]:x}, 0x{ne[2]:x}]\n")
    
            # print(ne)
            # print(e)

if __name__ == "__main__":
    main()