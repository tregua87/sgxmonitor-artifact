#!/usr/bin/env python3

from angr import *
import pyvex, ntpath, os, hashlib, argparse, sys
from pathlib import Path
from functools import partial

# for internal usage
class BasicBlockNode:
    def __init__(self, state, parent = None):
        self.state = state

        if parent and not isinstance(parent, BasicBlockNode):
            print(" ERROR: {} shoud be a BasicBlockNode".format(parent))
            exit()

        self.parent = parent
        self.children = []

        # update parent's children
        if self.parent:
            self.parent.children.append(self)

    def hasVisited(self, state):

        p = self.parent
        while p:
            iv = p.state.block().vex
            if state.addr >= iv.addr and state.addr < (iv.addr + iv.size):
                return True
            p = p.parent

        return False    

        # return state.addr in self.prev_nodes

def isWithinFun(instrAddr, funAddr, functions):

    prevAddr = None
    prevName = None      
    for addr, name in functions:
        if funAddr == prevAddr:
            return instrAddr > prevAddr and instrAddr < addr

        prevAddr = addr
        prevName = name

    return False

def md5sum(filename):
    with open(filename, mode='rb') as f:
        d = hashlib.md5()
        for buf in iter(partial(f.read, 128), b''):
            d.update(buf)
    return d.hexdigest()

def disassemble(enclave, asm_folder):
    asm_name = "{}.asm".format(ntpath.basename(enclave))
    asm_file = os.sep.join([asm_folder, asm_name])

    try:
        if os.path.exists(asm_file):
            os.remove(asm_file)
        cmd = "objdump -M intel -d {} > {}".format(enclave, asm_file)
        if os.system(cmd):
            os.remove(asm_file)
            raise Exception("didn't work!")
    except:
        print("Impossible to create {} from {}".format(asm_file, asm_file))
        exit(-1)

    return asm_file

def findloops(enclave, loop_file, project, enclave_asm):
        
    md5enclave = md5sum(enclave)
    addr_loops = {}

    if os.path.exists(loop_file):
        with open(loop_file, 'r') as f:
            md5enclave_salved = f.readline()

            if md5enclave == md5enclave_salved[:-1]:
                print("LOOP FILE '{}' SEEMS ALREADY HAVING '{}' LOOP INFO".format(loop_file, enclave))
                exit(1)
            else:
                print(" ERROR! LOOP FILE '{}' IS NOT COMPATIBILE WITH THE ENCLAVE! [{}]".format(loop_file, md5enclave))
                exit(1)

    traced_symb = ['_Z10traceedgecPv', '_Z15traceassigmentfPv', '_Z7tracebrPv', 'trace_context_generation',
                    'trace_eexit', 'trace_context_consume', '_Z12trace_eenteri', '_Z12trace_eexit2v', 
                    '_Z13trace_eresumev', '_Z27trace_exception_consumptionP17_exception_info_t', 
                    '_Z26trace_exception_generationP17_exception_info_t']

    traced_addr = []
    for s in traced_symb:
        ss = project.loader.main_object.get_symbol(s)
        if ss:
            traced_addr.append(ss.linked_addr)

    stop_exploration_symb = ['__stack_chk_fail', 'abort']
    stop_exploration_addr = []
    for s in stop_exploration_symb:
        ss = project.loader.main_object.get_symbol(s)
        if ss:
            stop_exploration_addr.append(ss.linked_addr)

    functions = []
    current_fname = None
    current_addr = None
    is_traced = False
    with open(enclave_asm,'r') as f1:
        for l in f1:
            l = l.strip()
            # skip comments
            if "#" in l:
                l = l.split("#")[0]

            # 0000000000012700 <_mm256_set1_epi64x>:
            if l.endswith(">:"):
                if current_fname is not None and current_addr is not None and is_traced:
                    functions.append((current_addr, current_fname))
                    is_traced = False
                la = l.split()
                addr = int(la[0],16)
                fname = la[1][1:-2]

                current_addr = addr
                current_fname = fname
            else:
                is_traced |= any([ s in l for s in traced_symb ])

        if current_fname is not None and current_addr is not None and is_traced:
            functions.append((current_addr, current_fname))
    
    for addr, fname in functions:
        if fname in traced_symb:
            print(" => Skip {} [traced]".format(fname))
            continue

        if fname in stop_exploration_symb:
            print(" => Skip {} [stop]".format(fname))
            continue

        # if fname.startswith("_"):
        #     print(" => Skip {}".format(fname))
        #     continue

        # if fname != "fmonty":
        #     continue

        if project.is_hooked(addr):
            print(" => Skip {} [hooked]".format(fname))
            continue

        print(" => Seeking loops in {}".format(fname))
        addr_loops_local = {}

        i_s = project.factory.call_state(addr)
        node_to_visit = [BasicBlockNode(i_s)]

        while node_to_visit:
            node = node_to_visit.pop()

            iv = node.state.block().vex
            ninst = node.state.block().instructions

            # print(" -> visit 0x{:x}".format(node.state.addr))

            if iv.jumpkind == 'Ijk_Call':
                # print(" ****** I am a call ******")
                # if module.gettargetaddr(node.state, iv) != stack_chk_fail:
                if iv.constant_jump_targets and iv.constant_jump_targets.pop() not in stop_exploration_addr:
                    n_state = node.state.copy()
                    n_state.regs.rip = n_state.regs.rip + iv.size
                    n_node = BasicBlockNode(n_state, parent=node)
                    node_to_visit.append(n_node)
                    # from IPython import embed; embed()
                # else:
                #     print(" ****** SKIP CHECK_FAIL******")
            elif iv.jumpkind == 'Ijk_Ret':
                # if I find a ret, I just stop the exploration
                # print(" ****** I am a ret ******")
                # print(" ***** node_to_visit {}".format(len(node_to_visit)))
                # from IPython import embed; embed()
                pass
            else:
                # print(" ****** I am a normal one ******")
                # from IPython import embed; embed()

                # this is to identify jmp to tracing functions, which de-facto leaves the function
                # if len(iv.constant_jump_targets) == 1 and iv.constant_jump_targets.pop() in traced_addr:
                if len(iv.constant_jump_targets) == 1 and iv.constant_jump_targets.pop() in traced_addr:
                    # from IPython import embed; embed()
                    pass
                else:

                    my_target = []
                    if iv.default_exit_target:
                        my_target += [iv.default_exit_target]

                    if len(iv.statements) != 0x0 and isinstance(iv.statements[-1], pyvex.stmt.Exit):
                        my_target += [iv.statements[-1].dst.value]

                    # we keep only the targets that fall within the function
                    my_target = [a for a in my_target if isWithinFun(a, addr, functions)]

                    if any([e is None for e in my_target]):
                        from IPython import embed; embed()

                    successors = []
                    successors_not_visited = []
                    for t in my_target:
                        # some instruction jumps to themselves; e.g., rep smth; we have to skip them
                        if t != iv.addr or ninst != 0x1:
                            succ = node.state.copy()
                            succ.regs.rip = t
                            successors.append(succ)
                            successors_not_visited.append((succ, not node.hasVisited(succ)))

                    # if node.state.addr == 0x5161:
                    #   from IPython import embed; embed()

                    # handle jumps which goes backwords
                    if len(successors) == 1:
                        n_node = BasicBlockNode(successors[0], parent=node)
                        node_to_visit.append(n_node)
                    elif all([ nv for s, nv in successors_not_visited]):
                        for succ in successors:
                            n_node = BasicBlockNode(succ, parent=node)
                            node_to_visit.append(n_node)
                    elif any([ nv for s, nv in successors_not_visited]):
                        for s, nv in successors_not_visited:
                            if nv:
                                # from IPython import embed; embed()
                                way_out = s.addr

                                n_node = BasicBlockNode(s, parent=node)
                                node_to_visit.append(n_node)
                            else:
                                iterat = s.addr

                        li = node.state.block().capstone.insns[-1]
                        addr_loops_local[li.insn.address] = (way_out, iterat)

        
        # for a, b in addr_loops_local.items():
        #     print("0x{:x} -> 0x{:x}".format(a,b))

        for a, (wo, i) in addr_loops_local.items():
            print("0x{:x} -> [0x{:x}, 0x{:x}]".format(a,wo, i))

        # addr_loops |= addr_loops_local
        addr_loops.update(addr_loops_local)
    
    # print("EXIT FOR DEBUG")
    # exit()

    # print("\n => all loops found:")
    with open(loop_file, 'w') as f:
        f.write("{}\n".format(md5enclave))
        for a, (wo, i) in addr_loops.items():
            f.write("0x{:x} 0x{:x} 0x{:x}\n".format(a,wo,i))

    # print("EXIT FOR DEBUG")
    # exit()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--enclave', '-e', required=True, type=str, help='The enclave to analyze')
    parser.add_argument('--asm_folder', '-f', required=False, type=str, help='Folder where keeping asm fies', default='asms')
    parser.add_argument('--loops', '-l', required=False, type=str, help='Loop info file', default=None)

    args = parser.parse_args()

    enclave = args.enclave
    asm_folder = args.asm_folder
    loops = args.loops

    enclave_asm = disassemble(enclave, asm_folder)
    project = Project(enclave, auto_load_libs=False, main_opts = {'base_addr': 0x0})
    findloops(enclave, loops, project, enclave_asm)

if __name__ == "__main__":
    main()