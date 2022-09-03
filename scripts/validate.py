#!/usr/bin/python3

import argparse, json, traceback

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


def edgeToString(e):
    if len(e) != 3 or not isinstance(e[0], str) or not isinstance(e[1], int) or not isinstance(e[2], int):
        raise Exception("this thing [{0}] is not a proper edge".format(e))
    return "{}[0x{:x}, 0x{:x}]".format(e[0], e[1], e[2])

def printTrace(t):
    print(" -> ".join(["{}[0x{:x}, 0x{:x}]".format(e[0], e[1], e[2]) for e in t]))

def parseModel(model_in):

    model = {}
    model_raw = None
    with open(model_in, 'r') as f:
        model_raw = json.load(f)

    for sf, m in model_raw.items():

        model_sf = {}
        for k, vs in m.items():
            model_sf[getOperands(k)] = [getOperands(v) for v in vs]

        model[sf] = model_sf

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
    elif e1[0] in {'G', 'D', 'C', 'J', 'K'}:
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

def getAdjLst(edge, model, zero):
    for k in model.keys():
        if equalEdge(edge, k, zero):
            return model[k]

    return None

def validate(edges, model):
    ZERO = None

    prev_e = None
    sec_func = None
    prev_secfunc = None
    for i, e in enumerate(edges):

        # the very first one is the end of "boot secure communication" function
        # I use it to get the ZERO value
        if i == 0:
            if e[0] != "T":
                raise Exception("edge at position {} '{}' is not T like".format(i, edgeToString(e)))
            ZERO = e[2]
            continue

        if sec_func is None:
            # it Must be an EENTER, and I get the secure function index from here
            if e[0] == "N":
                sec_func = str(e[2] - ZERO)
            elif e[0] == "L": # the internal exception handler has a special secure function
                sec_func = "L"
            elif prev_secfunc is not None:
                sec_func = prev_secfunc
            
            if sec_func is None:
                raise Exception("edge at position {} '{}' is not N or L".format(i, edgeToString(e)))

        model_sf = model.get(sec_func, None)

        # e has not other elements after it
        if getAdjLst(e, model_sf, ZERO) is None:
            # import ipdb; ipdb.set_trace()
            if e[0] == "N" and e[2] - ZERO == -3:
                sec_func = "-3"
                prev_secfunc = sec_func
                prev_e = None
            else:
                sec_func = None
                prev_e = None
            continue

        if prev_e is None:
            prev_e = e
            continue

        if model_sf is None:
            raise Exception("No model for secure function {}".format(sec_func))

        adj_lst = getAdjLst(prev_e, model_sf, ZERO)

        if not adj_lst:
            raise Exception("Edge '{}' is not valid!".format(edgeToString(prev_e)))

        if not any([equalEdge(e, l, ZERO) for l in adj_lst]):
            raise Exception("No connection from '{0}' to '{1}': {2}".format(edgeToString(prev_e), edgeToString(e), [edgeToString(e) for e in adj_lst]))

        # encounter an EEXIT
        if e[0] == 'D' or e[0] == 'T':
            prev_e = None
            sec_func = None
        else:
            prev_e = e

def main():
    parser = argparse.ArgumentParser(description='Validate traces by using a normalized model (i.e., the output of normalize_model.py)')
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
        traceback.print_exc()

if __name__ == "__main__":
  main()
