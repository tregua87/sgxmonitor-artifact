#!/usr/bin/python3

import argparse, json, traceback

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


def edgeToString(e):
    if len(e) != 4 or not isinstance(e[0], str) or not isinstance(e[1], int) or not isinstance(e[2], int):
        raise Exception("this thing [{0}] is not a proper edge".format(e))

    return "{}[0x{:x}, 0x{:x}, {}]".format(e[0], e[1], e[2], e[3])

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
        if e1[2] != e2[2] and (e2[2] != 0):
            verdict = False
    elif e1[0] == 'T':
        if e1[1] != e2[1] or e1[2] != e2[2]:
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
    # for k in model.keys():
    #     if equalEdge(edge, k, zero):
    #         return model[k]

    # return None
    found = None
    default = None
    for k in model.keys():
        if equalEdge(edge, k, zero) and not (k[0] == "E" and k[1] == 0x0 and k[2] == 0x0):
            found = k
        if k[0] == "E" and k[1] == 0x0 and k[2] == 0x0:
            default = k
        if default is not None and found is not None:
            break

    if found:
        return model[found]

    if default:
        return model[default]

def getModelEntry(edge, model, zero):
    found = None
    default = None
    for k in model.keys():
        if equalEdge(edge, k, zero) and not (k[0] == "E" and k[1] == 0x0 and k[2] == 0x0):
            found = k
        if k[0] == "E" and k[1] == 0x0 and k[2] == 0x0:
            default = k
        if default is not None and found is not None:
            break

    if found:
        return found

    if default:
        return default

    # print("we can't find the relative ation in the model")
    # from IPython import embed; embed()
    # raise Exception("for {}, we can't find the relative ation in the model".format(edgeToString(edge)))

def validate(edges, model):
    ZERO = None

    shadowstack = []
    shadowstack_saved = {}

    prev_e = None
    actual_func = None
    prev_actfunc = None
    for i, e in enumerate(edges):

        mystr = f"{i} - {edgeToString(e)} - ["
        for X, Y in shadowstack:
            mystr += f"({X}, {edgeToString(Y)})"

        mystr += "]"

        print(mystr)
        # print(f"{i} - {e} - {shadowstack}")


        # the very first one is the end of "boot secure communication" function
        # I use it to get the ZERO value
        if i == 0:
            if e[0] != "T":
                raise Exception("edge at position {} '{}' is not T like".format(i, edgeToString(e)))
            ZERO = e[2]
            continue

        if actual_func is None:
            # it Must be an EENTER, and I get the secure function index from here
            if e[0] == "N":
                actual_func = "enter_enclave"
            # elif e[0] == "L": # the internal exception handler has a special secure function
            #     actual_func = "L"
            # elif prev_actfunc is not None:
            #     actual_func = prev_actfunc
            
            if actual_func is None:
                raise Exception("edge at position {} '{}' is not N or L".format(i, edgeToString(e)))

        if e[0] == "N" or e[0] == "E":
            # actual_func = e[3]
            if e[2]-ZERO == -3:
                actual_func = "enter_enclave"                

            me = getModelEntry(e, model[actual_func], ZERO) 
            if me is None:
                print("Me is none, e is {}".format(edgeToString(e)))
                from IPython import embed; embed()
                raise Exception("Me is none, e is {}".format(edgeToString(e)))

            # the edge E returns from a function: pop from shadowstack
            if me[3] is None and me[2] == 0x0:
                lstfrm = shadowstack.pop()
                adj = getAdjLst(lstfrm[1], model[lstfrm[0]], ZERO)
                # print("return")
                # from IPython import embed; embed()
                if len(adj) == 1:
                    prev_e = adj[0]
                else:
                    for a in adj:
                        if equalEdge(e, a, ZERO):
                            prev_e = a

                # check that the reutrn address from 'e' follows the return address from the model
                if lstfrm[0] != "enter_enclave" and prev_e[2] != e[2]:
                    # from IPython import embed; embed()
                    raise Exception("The runtime return address is not coherent with the shadowstack value")
                    
                actual_func = lstfrm[0]
                continue
            # the edge E calls a traced function (i.e., not SKIPped): push into shadowstack
            elif me[3] != "SKIP":
                # from IPython import embed; embed()

                shadowstack.append((actual_func, e))
                actual_func = me[3]
                prev_e = None
                continue
                
        if e[0] == 'C':
            prev_ctx = hex(e[2])
            if prev_ctx not in shadowstack_saved:
                raise Exception("{} not in any previous stacks".format(prev_ctx))
            shadowstack = shadowstack_saved[prev_ctx]
            lstfrm = shadowstack.pop()
            actual_func = lstfrm[0]
            prev_e = lstfrm[1]
            continue

        model_sf = model.get(actual_func, None)

        if prev_e is None:
            prev_e = e
            continue

        if model_sf is None:
            raise Exception("No model for secure function {} [edge {}]".format(actual_func,i))

        adj_lst = getAdjLst(prev_e, model_sf, ZERO)

        if adj_lst is None:
            print("Edge '{}' is not valid!".format(edgeToString(prev_e)))
            from IPython import embed; embed()
            raise Exception("Edge '{}' is not valid!".format(edgeToString(prev_e)))

        if prev_e[0] == 'G':
            shadowstack_saved[hex(prev_e[2])] = shadowstack
            shadowstack = []

        if adj_lst == [] and e[0] == 'T':
            # print("exit from eexit")
            # from IPython import embed; embed()
            # break
            continue

        if e[0] == 'D':
            # print("exit from ocall")
            actual_func = None
            prev_e = None
            continue

        if not any([equalEdge(e, l, ZERO) for l in adj_lst]):
            print("no connection")
            from IPython import embed; embed()
            raise Exception("No connection from '{0}' to '{1}': {2}".format(edgeToString(prev_e), edgeToString(e), [edgeToString(e) for e in adj_lst]))

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
