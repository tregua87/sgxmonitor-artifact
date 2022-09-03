#!/usr/bin/python3

import argparse

def getOperands(l):
    # print(l)
    type = l[0]
    (op1, op2) = l[2:-1].split(", ")
    op1 = int(op1, 16)
    if op2 == "0xfffffffe":
        op2 = -2
    else:
        op2 = int(op2, 16)
    return (type,op1,op2)

def printTrace(t):
    print(" -> ".join(["{}[0x{:x}, 0x{:x}]".format(e[0], e[1], e[2]) for e in t]))

def parseModel(model_in):
    model = []

    with open(model_in, 'r') as f:
        for l in f:
            if l.strip():
                larr = l.strip().split(" -> ")
                x = larr[0].find(' ')
                larr[0] = larr[0][x+1:]
                model.append([getOperands(l) for l in larr])

    return model

def parseEdges(edges_in):
    edges = []

    with open(edges_in, 'r') as f:
        for l in f:
            if l.strip():
                edges.append(getOperands(l.strip()))

    edges.pop()

    return edges

def equalEdge(e1, e2, zero):
    # actions that not compare yet
    if e1[0] == 'F' and e2[0] == 'F':
        return True

    if e1[0] == 'A' and e2[0] == 'A':
        return True

    verdict = True

    if e1[0] != e2[0]:
        verdict = False

    if e1[1] != e2[1]:
        verdict = False

    if e1[0] == 'E':
        if e1[2] != e2[2]:
            verdict = False
    elif e1[0] in {'G', 'D', 'C'}:
        pass
    else:
        if (e1[2] - zero) != e2[2]:
            verdict = False

    # if not verdict:
    #     print("[ERROR] These are not ok:")
    #     print(zero)
    #     print("{}[0x{:x}, 0x{:x}]".format(e1[0], e1[1], e1[2]))
    #     print("{}[0x{:x}, 0x{:x}]".format(e2[0], e2[1], e2[2]))
    #     print()

    return verdict

def validateTrace(trace, model, zero):

    for m in model:
        if len(trace) == len(m):
            if all([equalEdge(et, em, zero) for et, em in zip(trace, m)]):
                return True

    return False

def validate(edges, model):

    ZERO = None

    tmp = []
    for i, e in enumerate(edges):
        # print(e)
        if i == 0:
            if e[0] != "T":
                raise Exception("edge {} [{}] is not T like".format(i, e))
            ZERO = e[2]
        else:
            tmp.append(e)
            if e[0] in ['T', 'D']:
                if not validateTrace(tmp, model, ZERO):
                    printTrace(tmp)
                    from IPython import embed; embed()
                    raise Exception("trace not valid!")
                tmp = []

def main():
    parser = argparse.ArgumentParser(description='Validate traces by using a raw model (i.e., the output of explore_exception_enclave.py and explore_traced_enclave.py)')
    parser.add_argument('--edges', '-e', required=True, type=str, help='Execution trace to validate')
    parser.add_argument('--model', '-m', required=True, type=str, help='The model extracted from angr')

    args = parser.parse_args()

    edges_in = args.edges
    model_in = args.model

    model = parseModel(model_in)
    edges = parseEdges(edges_in)

    try:
        validate(edges, model)
        print("[OK] Edges [{}] match the model [{}]".format(edges_in, model_in))
    except Exception as e:
        print("[ERROR] Edges [{}] NOT match the model [{}]".format(edges_in, model_in))
        print(e)

if __name__ == "__main__":
  main()
