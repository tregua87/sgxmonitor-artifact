#!/usr/bin/env python3

from angr import *
import pyvex, ntpath, os, hashlib, argparse, sys
from pathlib import Path
from functools import partial
import copy

# project imports
sys.path.append('./lib')
import module
import shadowstack, tracer, common, tracer_collector, loopsmanager

class CFG:
    def __init__(self):
        self.node0 = None
        self.nodes = set()
        self.children = {}
        self.parents = {}

    def setNode0(self, node):

        if not isinstance(node, BasicBlockNode):
            raise Exception("{} is not a BasicBlockNode".format(node))
        if self.node0 is not None:
            raise Exception("Node zero already set")

        self.node0 = node
        self.nodes.add(node)
        node_id = node.getId()
        self.parents[node_id] = set()
        self.children[node_id] = set()

    def addEdge(self, source, target):

        if not isinstance(source, BasicBlockNode):
            raise Exception("source {} is not a BasicBlockNode".format(source))
        if not isinstance(target, BasicBlockNode):
            raise Exception("target {} is not a BasicBlockNode".format(target))

        cgfChanged = False
        if source not in self.nodes:
            self.nodes.add(source)
            cgfChanged = True
        if target not in self.nodes:
            self.nodes.add(target)
            cgfChanged = True

        source_id = source.getId()
        target_id = target.getId()

        source_children = self.children.get(source_id, set())
        source_children.add(target_id)
        self.children[source_id] = source_children

        target_parents = self.parents.get(target_id, set())
        target_parents.add(source_id)
        self.parents[target_id] = target_parents

        if target_id not in self.children:
            self.children[target_id] = set()

        return cgfChanged

    def replaceNode(self, node, node_new):
        # from IPython import embed; embed()
        # import ipdb; ipdb.set_trace()

        # fix nodes set
        self.nodes.remove(node)
        self.nodes.add(node_new)

        node_id = node.getId()
        node_new_id = node_new.getId()

        # fix children
        for c in self.children[node_id]:
            self.parents[c].remove(node_id)
            self.parents[c].add(node_new_id)

        new_children = self.children.get(node_new_id, set())
        new_children.update(self.children[node_id].copy())
        self.children[node_new_id] = new_children
        del self.children[node_id]

        # fix parents
        for p in self.parents[node_id]:
            self.children[p].remove(node_id)
            self.children[p].add(node_new_id)

        new_parents = self.parents.get(node_new_id, set())
        new_parents.update(self.parents[node_id].copy())
        self.parents[node_new_id] = new_parents
        del self.parents[node_id]

        return node_new

    def __str__(self):
        s = ""
        s += "nodes visited {}\n".format(len(self.nodes))
        s + "\n"

        s += "children relation:\n"
        for n, cs in self.children.items():
            s += "(0x{:x}, {}) c=> [".format(n[0], n[1])

            m_c = len(cs)
            for i, c in enumerate(cs):
                s += "(0x{:x}, {})".format(c[0], c[1])
                if i != m_c - 1:
                    s += ", "

            s += "]\n"

        s += "\n"

        s += "parent relation:\n"
        for n, ps in self.parents.items():
            s += "(0x{:x}, {}) p=> [".format(n[0], n[1])

            m_p = len(ps)
            for i, p in enumerate(ps):
                s += "(0x{:x}, {})".format(p[0], p[1])
                if i != m_p - 1:
                    s += ", "

            s += "]\n"

        return s

    # def __getitem__(self, key):
    #     if ket not in self.nodes:
    #     cfg[c_id]

# for internal usage
class BasicBlockNode:
    def __init__(self, state):
        self.state = state
        self.addr = state.block().addr
        self.size = state.block().size

    def overlaps(self, other):
        # n1 contains n2

        min_n1 = self.addr
        max_n1 = self.addr + self.size

        min_n2 = other.addr
        max_n2 = other.addr + other.size

        # n1 contains n2
        return min_n1 < min_n2 and max_n1 == max_n2

    def getId(self):
        return (self.addr, self.size)

    def __str__(self):
        return "(0x{:x}, {})".format(self.addr, self.size)

    def __repr__(self):
        return "(0x{:x}, {})".format(self.addr, self.size)

    def __hash__(self):
        return hash((self.addr, self.size))

    def __eq__(self, other):
        return self.addr == other.addr and self.size == other.size

    def __copy__(self):
        dup = BasicBlockNode(self.state)
        dup.addr = self.addr
        dup.size = self.size
        return dup

def md5sum(filename):
    with open(filename, mode='rb') as f:
        d = hashlib.md5()
        for buf in iter(partial(f.read, 128), b''):
            d.update(buf)
    return d.hexdigest()

class LoopExtraction(common.Analysis):
    def load_binary(self):
        self.project = Project(self.enclave_bin, auto_load_libs=False, main_opts = {'base_addr': 0x0})
        
        self.traced_symb = ['_Z10traceedgecPv', '_Z15traceassigmentfPv', '_Z7tracebrPv', 'trace_context_generation',
                            'trace_eexit', 'trace_context_consume', '_Z12trace_eenteri', '_Z12trace_eexit2v', 
                            '_Z13trace_eresumev', '_Z27trace_exception_consumptionP17_exception_info_t', 
                            '_Z26trace_exception_generationP17_exception_info_t']

        self.traced_addr = []
        for s in self.traced_symb:
            ss = self.project.loader.main_object.get_symbol(s)
            if ss:
                self.traced_addr.append(ss.linked_addr)

        self.stop_exploration_symb = ['__stack_chk_fail', 'abort', 'continue_execution']
        self.stop_exploration_addr = []
        for s in self.stop_exploration_symb:
            ss = self.project.loader.main_object.get_symbol(s)
            if ss:
                self.stop_exploration_addr.append(ss.linked_addr)

    def get_cfg(self, addr):

        cfg = CFG()

        addr_loops_local = {}

        i_s = self.project.factory.call_state(addr)
        cfg.setNode0(BasicBlockNode(i_s))
        node_to_visit = [cfg.node0]

        while node_to_visit:
            node = node_to_visit.pop()

            iv = node.state.block().vex
            ninst = node.state.block().instructions

            # print(" -> visit 0x{:x}".format(node.state.addr))
            # print("nodes visited: {}".format(len(cfg.nodes_id)))

            if iv.jumpkind == 'Ijk_Call':
                # print(" ****** I am a call ******")
                # if module.gettargetaddr(node.state, iv) != stack_chk_fail:
                if (not iv.constant_jump_targets) or (iv.constant_jump_targets and iv.constant_jump_targets.pop() not in self.stop_exploration_addr):
                    n_state = node.state.copy()
                    n_state.regs.rip = n_state.regs.rip + iv.size
                    n_node = BasicBlockNode(n_state)
                    if cfg.addEdge(node, n_node):
                        node_to_visit.append(n_node)
            elif iv.jumpkind == 'Ijk_Ret':
                pass
            elif iv.jumpkind == 'Ijk_NoDecode':
                if iv.addr == self.ocall_enclu_addr:
                    # enclu in ocall => stop
                    # pass 
                    leng = 3 # enclu is always 3 bytes long

                    node_new = copy.copy(node)
                    node_new.size = leng
                    node = cfg.replaceNode(node, node_new)

                    n_state = node.state.copy()
                    n_state.regs.rip = n_state.regs.rip + leng
                    n_node = BasicBlockNode(n_state)
                    if cfg.addEdge(node, n_node):
                        node_to_visit.append(n_node)
                elif iv.addr in self.rdrandlist:
                    leng = self.rdrandlengthlist[self.rdrandlist.index(iv.addr)]

                    node_new = copy.copy(node)
                    node_new.size = leng
                    node = cfg.replaceNode(node, node_new)

                    n_state = node.state.copy()
                    n_state.regs.rip = n_state.regs.rip + leng
                    n_node = BasicBlockNode(n_state)
                    if cfg.addEdge(node, n_node):
                        node_to_visit.append(n_node)
                elif iv.addr in self.ud2list:
                    # ud2 => stop
                    pass
                else:
                    print("I don't really know what to do!")
                    from IPython import embed; embed()
            else:
                # this is to identify jmp to tracing functions, which de-facto leaves the function
                # if len(iv.constant_jump_targets) == 1 and iv.constant_jump_targets.pop() in traced_addr:
                if len(iv.constant_jump_targets) == 1 and iv.constant_jump_targets.pop() in self.traced_addr:
                    # from IPython import embed; embed()
                    pass
                else:

                    my_target = []
                    # if iv.default_exit_target:
                    #     my_target += [iv.default_exit_target]

                    # if len(iv.statements) != 0x0 and isinstance(iv.statements[-1], pyvex.stmt.Exit):
                    #     my_target += [iv.statements[-1].dst.value]

                    (iv_min, iv_max) = (iv.addr, iv.addr + iv.size)
                    for d in iv.constant_jump_targets:
                        if d < iv_min or d >= iv_max:
                             my_target += [d]

                    # we keep only the targets that fall within the function
                    my_target = [a for a in my_target if self.isWithinFun(a, addr)]

                    if any([e is None for e in my_target]):
                        from IPython import embed; embed()

                    for t in my_target:
                        # some instruction jumps to themselves; e.g., rep smth; we have to skip them
                        if t != iv.addr or ninst != 0x1:
                            succ = node.state.copy()
                            succ.regs.rip = t
                            n_node = BasicBlockNode(succ)
                            if cfg.addEdge(node, n_node):
                                node_to_visit.append(n_node)

        return cfg
    
    def normalize_cfg(self, cfg):

        is_changed = True
        while is_changed:
            # print(cfg)
            is_changed = False
            for n1 in cfg.nodes.copy():
                for n2 in cfg.nodes.copy():
                    if n1.overlaps(n2):
                        # print("=> {} overlaps {}".format(n1, n2))

                        # if n1.addr == 0x17d8 and n1.size == 16 and n1.addr == 0x17de and n1.size == 10:
                        #     print("BEFORE")
                        #     from IPython import embed; embed()

                        n1_prime = BasicBlockNode(n1.state)
                        n1_prime.size = n1.size - n2.size

                        n1_id = n1.getId()
                        n2_id = n2.getId()
                        n1_prime_id = n1_prime.getId()

                        # step 1
                        cfg.addEdge(n1_prime, n2)
                        n1_n2_common_children = cfg.children[n1_id].intersection(cfg.children[n2_id])

                        # step 2
                        cfg.children[n1_prime_id].update(cfg.children[n1_id].copy().difference(n1_n2_common_children))
                        cfg.parents[n1_prime_id] = cfg.parents[n1_id].copy()

                        for p in cfg.parents[n1_prime_id]:
                            cfg.children[p].remove(n1_id)
                            cfg.children[p].add(n1_prime_id)

                        # step 3
                        for chld in n1_n2_common_children:
                            cfg.parents[chld].remove(n1_id)

                        # step 4
                        cfg.nodes.remove(n1)
                        del cfg.children[n1_id]
                        del cfg.parents[n1_id]
                        
                        # if n1.addr == 0x17d8 and n1.size == 16 and n2.addr == 0x17de and n2.size == 10:
                        #     print("AFTER")
                        #     from IPython import embed; embed()

                        # print(cfg)
                        
                        is_changed = True
                        break
                if is_changed:
                    break

        return cfg

    def compute_dominators(self, cfg):
        dom_list = {}

        # dominator of the start node is the start itself
        # Dom(n0) = {n0}
        n0 = cfg.node0
        n0_id = n0.getId()
        dom_list[n0_id] = set( { n0_id } )
        # for all other nodes, set all nodes as the dominators
        # for each n in N - {n0}
        for n in cfg.nodes.difference({n0}):
            # Dom(n) = N;
            n_id = n.getId()
            dom_list[n_id] = set([_.getId() for _ in cfg.nodes])

        # iteratively eliminate nodes that are not dominators
        theres_changes = True
        while theres_changes:
            theres_changes = False
            # for each n in N - {n0}:
            for n in cfg.nodes.difference( { n0 } ):
                
                n_id = n.getId()

                d = dom_list[n_id]
                prev_dom = len(d)
                # Dom(n) = {n} union with intersection over Dom(p) for all p in pred(n)
                if n_id in cfg.parents and cfg.parents[n_id]:
                    dom_parent = []
                    for p_id in cfg.parents[n_id]:
                        dom_parent.append(dom_list[p_id])
                    if not dom_parent:
                        from IPython import embed; embed()
                    inter_dom = set.intersection( *dom_parent )
                else:
                    inter_dom = set()
                
                dom_list[n_id] = inter_dom | { n_id }

                curr_dom = len(dom_list[n_id])

                theres_changes |= curr_dom != prev_dom

        return dom_list

    def start_analysis(self):

        print("[INFO] start loop analysis..")

        self.addr_loops = {}
        for addr, fnc, is_traced in self.functions:

            if not is_traced:
                continue

            if fnc in self.traced_symb:
                continue

            if self.function is not None and self.function != fnc:
                continue

            print("[INFO] search loops in {}".format(fnc))

            # get control-flow graph
            cfg = self.get_cfg(addr)
            # print(cfg)
            cfg = self.normalize_cfg(cfg)
            # print(cfg)
            
            # compute dominators
            dom_list = self.compute_dominators(cfg)

            addr_loops_local = {}
            # find back-edge
            # print("\nback edges:")
            for n in cfg.nodes:
                n_id = n.getId()
                for c_id in cfg.children[n_id]:
                    # if len(cfg.children[n_id]) == 2 and c_id in dom_list[n_id]:
                    if c_id in dom_list[n_id]:
                        # print("{} => {}".format(n_id, c_id))
                        # from IPython import embed; embed()

                        if len(cfg.children[n_id]) == 2:
                            # iterat = c.addr
                            iterat = c_id[0]

                            # c_cp = n.children.copy()
                            # c_cp.remove(c)
                            # wo_node = c_cp.pop()
                            c_cp = cfg.children[n_id].copy()
                            c_cp.remove(c_id)
                            wo_node = c_cp.pop()

                            if n.state.block().capstone.insns:
                                li = n.state.block().capstone.insns[-1]
                                # way_out = wo_node.addr
                                way_out = wo_node[0]
                                adl = li.insn.address
                                addr_loops_local[adl] = (way_out, iterat)
                                print("0x{:x} -> [0x{:x}, 0x{:x}]".format(adl,way_out,iterat))

                        elif len(cfg.children[c_id]) == 2:

                            wo_node = None
                            iterat = None
                            max_iter = 4
                            _idx = 0
                            while max_iter:
                            # for cc in cfg.children[c_id]:
                                cc = list(cfg.children[c_id])[_idx]
                                if c_id[0] + c_id[1] == cc[0]:
                                    iterat = cc[0]
                                    # continue
                                if iterat:
                                    wo_node = cc
                                    # break
                                _idx = (_idx + 1) % len(cfg.children[c_id])
                                max_iter -= 1

                            # n_cp = cfg.children[c_id].copy()
                            # n_cp.remove(n_id)
                            # wo_node = c_cp.pop()

                            if wo_node is not None:
                                for c in cfg.nodes.copy():
                                    if c.getId() == c_id and c.state.block().capstone.insns:
                                        li = c.state.block().capstone.insns[-1]
                                        # way_out = wo_node.addr
                                        way_out = wo_node[0]
                                        adl = li.insn.address
                                        addr_loops_local[adl] = (way_out, iterat)
                                        print("0x{:x} -> [0x{:x}, 0x{:x}]".format(adl,way_out,iterat))
                            else:
                                from IPython import embed; embed(); exit()
                                print(c_id)
                                exit()


            self.addr_loops.update(addr_loops_local)



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--enclave', '-e', required=True, type=str, help='The enclave to analyze')
    parser.add_argument('--asm_folder', '-f', required=False, type=str, help='Folder where keeping asm fies', default='asms')
    parser.add_argument('--loops', '-l', required=False, type=str, help='Loop info file', default="loops.txt")
    parser.add_argument('--function', '-n', required=False, type=str, help='Function to focus on', default=None)

    args = parser.parse_args()

    enclave = args.enclave
    asm_folder = args.asm_folder
    loops = args.loops
    function = args.function

    md5enclave = md5sum(enclave)
    if os.path.exists(loops):
        with open(loops, 'r') as f:
            md5enclave_salved = f.readline()

            if md5enclave == md5enclave_salved[:-1]:
                print("LOOP FILE '{}' SEEMS ALREADY HAVING '{}' LOOP INFO".format(loops, enclave))
                exit(1)
            else:
                print(" ERROR! LOOP FILE '{}' IS NOT COMPATIBILE WITH THE ENCLAVE! [{}]".format(loops, md5enclave))
                exit(1)

    a = LoopExtraction(enclave, asm_folder, None, None, None, None, function=function)
    a.loops = loops
    a.load_binary()
    a.preliminaries()
    a.start_analysis()

    with open(a.loops, 'w') as f:
        f.write("{}\n".format(md5enclave))
        for a, (wo, i) in a.addr_loops.items():
            f.write("0x{:x} 0x{:x} 0x{:x}\n".format(a,wo,i))

if __name__ == "__main__":
    main()