#!/usr/bin/python3

import sys, argparse, os, ntpath

def disassemble(enclave_bin, asm_folder):
    asm_name = "{}.asm".format(ntpath.basename(enclave_bin))
    asm_file = os.sep.join([asm_folder, asm_name])

    try:
        if os.path.exists(asm_file):
            os.remove(asm_file)
        cmd = "objdump -M intel -d {} > {}".format(enclave_bin, asm_file)
        if os.system(cmd):
            os.remove(asm_file)
            raise Exception("didn't work!")
    except:
        print("Impossible to create {} from {}".format(asm_file, asm_file))
        exit(-1)

    return asm_file

def parseinsaddr(line, separator):
	temp = line[:line.find(separator)]
	try:
		temp1 = int(temp, 16)
	except:
		return -1

	return temp1

def get_action_ids(asm_file, f_actions = None):

    ids = []

    with open(asm_file,'r') as f1:
        lines = f1.readlines()
        max_linex = len(lines)
        for idx, l in enumerate(lines):
            if ":" in l and "call" in l and "trace" in l and idx < max_linex - 1:

                line_after = lines[idx+1]

                addr = parseinsaddr(line_after, ":")
                if addr == -1:
                    continue

                if f_actions and any([ addr >= ba and addr <= be for ba, be in f_actions ]):
                    continue

                ids.append("0x{:x}".format(addr))

    return ids

def get_unique_model_ids(model):

    ids = set()

    with open(model,'r') as f1:
        lines = f1.readlines()
        
        for l in lines:

            if not l.split():
                continue
            ll = l.split(": ")[1]

            for a in ll.split(" -> "):
                addr = a[2:-1].split(", ")[0] # C[0x2d891, 0]
                ids.add(addr)

    return list(ids)

def get_falseactions(inline_f):

    f_actions = []

    with open(inline_f,'r') as f:
        for l in f:
            l = l.strip()

            la = l[1:-1].split(",")

            ba = int(la[0], 16)
            ea = int(la[1], 16)

            f_actions.append((ba,ea))

    return f_actions

def get_function_list(asm_file):

    fcts = []

    with open(asm_file, 'r') as f:
        for l in f:
            l = l.strip()

            # remove comment '#'
            if "#" in l:
                l = l.split("#")[0]

            # 0000000000012700 <_mm256_set1_epi64x>:
            if l.endswith(">:"):
                la = l.split()
                addr = int(la[0],16)
                fname = la[1][1:-2]

                fcts.append((addr, fname))

    return fcts

def get_function(function_list, b):

    b = int(b, 16)

    last_function = None
    for a, f in function_list:
        if b < a:
            break
        last_function = f

    return last_function

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--enclave', '-e', required=True, type=str, help='The enclave to analyze')
    parser.add_argument('--model', '-m', nargs='+', required=False, type=str, help='Model', default='model.txt')
    parser.add_argument('--asm_folder', '-f', required=False, type=str, help='Folder where keeping asm fies', default='asms')
    parser.add_argument('--leftover', '-l', required=False, action='store_true', help='Print unmatched actions')
    parser.add_argument('--inline_functions', '-i', required=False, type=str, help='Inline function list')

    args = parser.parse_args()

    enclave_bin = args.enclave
    model = args.model
    asm_folder = args.asm_folder
    leftover = args.leftover
    inline_f = args.inline_functions

    asm_file = disassemble(enclave_bin, asm_folder)

    function_list = get_function_list(asm_file)

    f_actions = None
    if inline_f:
        f_actions = get_falseactions(inline_f)

    all_action_ids = get_action_ids(asm_file, f_actions)

    unique_model_ids = {}
    
    if not model:
        model = []

    for m in model:
        unique_model_ids[m] = get_unique_model_ids(m)

    print("#all_action_ids: {}".format(len(all_action_ids)))

    all_actions_traversed = set()

    for k, acts in unique_model_ids.items():
        match = list(set(acts) & set(all_action_ids))
        print("#match for {}: {}".format(k, len(match)))
        all_actions_traversed = all_actions_traversed.union(acts)

    match = list(set(all_actions_traversed) & set(all_action_ids))
    print("#match total: {}".format(len(match)))


    if leftover:

        leftover_function = {}

        print("[*] leftover basic blocks:")
        for b in list(set(all_action_ids) - set(match)):
            f = get_function(function_list, b)
            if not f:
                print("{} does not belong to any function".format(b))

            tmp = leftover_function.get(f, [])

            tmp.append(b)

            leftover_function[f] = tmp
            print(b)

        print("[*] leftover functions:")
        for f, b in leftover_function.items():
            # print("{}: [{}]".format(f,", ".join(b)))
            print("{}".format(f))


if __name__ == "__main__":
    main()
