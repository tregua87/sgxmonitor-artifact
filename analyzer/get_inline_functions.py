#!/usr/bin/python3

import sys, argparse, ntpath, os
from pathlib import Path

def get_uncalled_functions(enclave):
    uncalled_functions = []

    functions = []
    callsites = []

    with open(enclave, 'r') as f:
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

                # if fname in hardcode:
                #     continue

                functions.append((addr, fname))

            token = "\tcall "
            if token in l:
                addr_s = l.split(":")[0]
                cs = int(addr_s,16)

                x = l.index(token)

                # 126e3:	e8 28 12 00 00       	call   13910 <_Z10traceedgecPv>
                if "<" in l:
                    try:
                        p = l[x+len(token):].strip().split()[0]
                        dst = int(p, 16)
                    except:
                        print(l)
                        exit()
                # call   QWORD PTR [r14+0x18]
                else:
                    dst = l[x+len(token):].strip()

                callsites.append((cs, dst))
    
    inline_functions = []

    for a, f in functions:

        if not any([a == dst for cs, dst in callsites if isinstance(dst, int)]):
            inline_functions.append((a, f))

    # inline_functions = sorted(inline_functions, key=lambda e: e[1])

    # for a, f in inline_functions:
    #     print("0x{:x} {}".format(a, f))
    # exit()

    inline_functions_end = []

    open_fn = False
    with open(enclave, 'r') as f:
        for l in f:
            l = l.strip()

            if open_fn and l.endswith(">:"):

                addrs = l.split(" <")[0]
                addr = int(addrs, 16)

                inline_functions_end.append(addr)

                open_fn = False

            if any(["<{}>:".format(fn) in l for a, fn in inline_functions]):
                open_fn = True

    # for (s, f), e in zip(inline_functions, inline_functions_end):
    #     print("(0x{:x}, 0x{:x}, {})".format(s, e , f))

    uncalled_functions = [ (s, e, f) for (s, f), e in zip(inline_functions, inline_functions_end)]

    # uncalled_functions = sorted(inline_functions_full, key=lambda e: e[2])

    return uncalled_functions

def get_real_inline(enclave, uncalled_functions):

    real_inline = set()

    with open(enclave, 'r') as f:
        lines = f.readlines()
        padding = 10
        for i in range(len(lines)-padding):
            l0 = lines[i].strip()
            # trace functions snipped
            #  e95:	48 8d 3d 64 30 01 00 	lea    rdi,[rip+0x13064]        # 13f00 <sgx_is_outside_enclave>
            #  there could be at most 10 lines in between
            #  e9c:	e8 6f 2a 01 00       	call   13910 <_Z10traceedgecPv>
            if "\tlea " in l0: 

                funToTrace = None

                if len(l0.split("#")) == 2:
                    comment = l0.split("#")[1]
                    for s, e, fn in uncalled_functions:
                        if "<{}>".format(fn) in comment:
                            funToTrace = (s, e, fn)
                            break

                if funToTrace is not None:
                    for x in range(padding):
                        lx = lines[i+x+1].strip()

                        # if "\tlea " in lx and len(lx.split("#")) == 2 and any([ "<{}>".format(fn) in lx.split("#")[1] for s, e, fn in uncalled_functions ]): 
                        #     break

                        if "<_Z10traceedgecPv>" in lx:
                            real_inline.add(funToTrace)
                        # if any(["<{}>".format(fn) in l0 for s, e, fn in uncalled_functions]):
                        #     real_inline.append()

    return list(real_inline)

def disassemble_enclave(enclave_bin, asm_folder):
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
        exit(-1)(parameter_list)

    return asm_file
    

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--enclave', '-e', required=True, type=str, help='The enclave to analyze')
    parser.add_argument('--asm_folder', '-f', required=False, type=str, help='Folder where keeping asm fies', default='asms')

    args = parser.parse_args()

    enclave = args.enclave
    asm_folder = args.asm_folder

    Path(asm_folder).mkdir(parents=True, exist_ok=True)

    enclave_asm = disassemble_enclave(enclave, asm_folder)

    uncalled_functions = get_uncalled_functions(enclave_asm)

    real_inline = get_real_inline(enclave_asm, uncalled_functions)

    with open("uncalled_functions.txt", "w") as of:
        for s, e , f in uncalled_functions:
            of.write("(0x{:x}, 0x{:x}, {})\n".format(s, e , f))

    with open("real_inline.txt", "w") as of:
        for s, e , f in real_inline:
            of.write("(0x{:x}, 0x{:x}, {})\n".format(s, e , f))

if __name__ == "__main__":
    main()
    