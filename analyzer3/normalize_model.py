#!/usr/bin/env python3

import argparse, json, sys, os

def getOperands(l):
    # print(l)
    t = l[0]
    (op1, op2) = l[2:-1].split(", ")
    op1 = int(op1, 16)
    op2 = int(op2, 16)
    # if op2 == "0xfffffffe":
    #     op2 = -2
    # elif op2 == "0xfffffffd":
    #     op2 = -3
    # else:
    #     op2 = int(op2, 16)
    return (t,op1,op2)


def main():
    parser = argparse.ArgumentParser(description='Normalize the model outputed from (explore_exception_enclave.py and explore_traced_enclave.py)')
    parser.add_argument('--outputmodel', '-o', required=True, type=str, help='Output normalized model')
    parser.add_argument('--rawmodels', '-r', nargs='+', required=True, type=str, help='Input raw models')

    args = parser.parse_args()

    raw_models = args.rawmodels
    out_model  = args.outputmodel

    normalized_models = {}
    for r in raw_models:
        if not os.path.isfile(r):
            print(f"[WARNING] {r} does not exist!")
            continue
        with open(r, 'r') as m:

            funName = None
            prevFunName = None

            for l in m:
                l = l.strip()

                # skip empty lines
                if not l:
                    continue

                if l[0] == "<" and l[-1] == ":":
                    funName = l[1:-2]
                    continue

                if funName != prevFunName:
                    # if prevFunName is not None:
                    #     # print(normalized_models[prevFunName])
                    #     # exit()
                    prevFunName = funName

                # sequence = l.split(":")[1].strip().split(" -> ")
                sequence = l.strip().split(" -> ")
                
                model = normalized_models.get(funName, {})

                prev_e = None
                for e in sequence:
                    if prev_e is None:
                        prev_e = e
                        continue
                
                    adj_list = model.get(prev_e, [])
                    if e not in adj_list:
                        adj_list.append(e)

                    model[prev_e] = adj_list

                    prev_e = e

                if prev_e not in model:
                    model[prev_e] = []

                normalized_models[funName] = model

    with open(out_model, 'w') as o:
        json.dump(normalized_models, o)

if __name__ == "__main__":
  main()