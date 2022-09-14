#!/usr/bin/env python3

# https://docs.angr.io/core-concepts/solver

import os, sys, argparse, ntpath, pyvex, json, copy
import statistics


# project imports
sys.path.append('./lib')
# import module
# import shadowstack, tracer, common, tracer_collector, loopsmanager
import common

from angr import *

import signal
def killmyself():
    os.system('kill %d' % os.getpid())
def sigint_handler(signum, frame):
    print('Stopping Execution for Debug. If you want to kill the programm issue: killmyself()')
    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)

import logging

def checkInstr0(state):
    print(" ***** HIT A ZERO! *****")
    from IPython import embed; embed()

class CFG:
    def __init__(self):
        self.node0 = None
        self.nodes = {}
        self.children = {}
        self.parents = {}

    def setNode0(self, node):

        if not isinstance(node, BasicBlockNode):
            raise Exception("{} is not a BasicBlockNode".format(node))
        if self.node0 is not None:
            raise Exception("Node zero already set")

        node_id = node.getId()
        self.node0 = node_id
        self.nodes[node_id] = node
        self.nodes[node_id].cfg = self
        self.parents[node_id] = set()
        self.children[node_id] = set()

    def addEdge(self, source, target):

        if not isinstance(source, BasicBlockNode):
            raise Exception("source {} is not a BasicBlockNode".format(source))
        if not isinstance(target, BasicBlockNode):
            raise Exception("target {} is not a BasicBlockNode".format(target))

        source_id = source.getId()
        target_id = target.getId()

        cgfChanged = False
        # if source not in self.nodes:
        if source_id not in self.nodes.keys():
            # self.nodes.add(source)
            self.nodes[source_id] = source
            self.nodes[source_id].cfg = self
            cgfChanged = True
        # if target not in self.nodes:
        if target_id not in self.nodes.keys():
            # self.nodes.add(target)
            self.nodes[target_id] = target
            self.nodes[target_id].cfg = self
            cgfChanged = True

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

        node_id = node.getId()
        node_new_id = node_new.getId()

        # fix nodes
        # self.nodes.remove(node)
        # self.nodes.add(node_new)
        del self.nodes[node_id]
        self.nodes[node_new_id] = node_new

        # node_id = node.getId()
        # node_new_id = node_new.getId()

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

    def get_input_of(self, iv, obj, typ, min_s):

        # # return (0x0, 'imm')

        # if iv.addr == 0x39f5f:
        #     print("addr 0x{:x}".format(iv.addr))
        #     # import ipdb; ipdb.set_trace()
        #     from IPython import embed; embed()
        
        for i, s in enumerate(reversed(iv.statements)):

            if i < min_s:
                continue

            # if typ == 'reg' and isinstance(s, pyvex.stmt.Put) and iv.arch.translate_register_name(s.offset, s.data.result_size(iv.tyenv)// 8) == obj:
            if typ == 'reg' and isinstance(s, pyvex.stmt.Put) and s.offset == obj:
                # print(" => {}".format(s))
                # if obj == 'rbp' and typ == 'reg' and iv.addr == 0x1cfe:
                #     # import ipdb; ipdb.set_trace()
                    # from IPython import embed; embed()
                if isinstance(s.data, pyvex.expr.Const):
                    return (s.data.constants[0].value, 'imm', i)
                elif isinstance(s.data, pyvex.expr.RdTmp):
                    return (s.data.tmp, 'tmp', i)
                else:
                    print("don't know with reg")
                    iv.pp()
                    from IPython import embed; embed()
                    exit()

            if typ == 'tmp' and isinstance(s, pyvex.stmt.WrTmp) and s.tmp == obj:
                # if s.constants:
                #     return (s.constants[0].value, 'imm')
                # elif s.data.args:
                if isinstance(s.data, pyvex.expr.Unop):
                    return (s.data.args[0].tmp, 'tmp', i)
                elif isinstance(s.data, pyvex.expr.RdTmp):
                    return (s.data.tmp, 'tmp', i)
                elif isinstance(s.data, pyvex.expr.Binop):
                    for arg in s.data.args:
                        if isinstance(arg, pyvex.expr.RdTmp):
                            return (arg.tmp, 'tmp', i)
                    print("No RdTmp found here")
                    s.pp()
                    from IPython import embed; embed()
                elif isinstance(s.data, pyvex.expr.Get):
                    # return (iv.arch.translate_register_name(s.data.offset, 8), 'reg')
                    return (s.data.offset, 'reg', i)
                elif isinstance(s.data, pyvex.expr.Load):
                    return (None, 'mem', i)
                else:
                    print("don't know with tmp")
                    iv.pp()
                    from IPython import embed; embed()
                    exit()

        return (None, 'unset', 0)

    def get_rdi(self):

        # # backward analysis to find RDI value
        # # the analysis follow RDI (and EDI) assignments until we find a *constant* or a *memory assignment*

        # val_s = 'rdi'
        val_s = 72 # => offset=72 => register rdi
        typ_s = 'reg'
        # bb = self
        bb_id = self.getId()

        # print("SEEK")
        # from IPython import embed; embed()

        values = set()

        # it contains elements (bb_id, stmt_i, val, typ)
        worklist = [(bb_id, val_s, typ_s, 0)]

        nodes_visited = set()

        # if bb_id[0] == 0x1d13:
        #     import ipdb; ipdb.set_trace()

        while worklist:
            a_work = worklist.pop()
            bb_id = a_work[0]
            # if bb_id in nodes_visited:
            #     continue

            # from IPython import embed; embed()
            _bb = self.cfg.nodes[bb_id]
            _val_s = a_work[1]
            _typ_s = a_work[2]
            _min_stmt = a_work[3]

            (val_f, typ_f, min_r) = self.get_input_of(_bb.state.block().vex, _val_s, _typ_s, _min_stmt)

            if typ_f == 'imm':
                values.add(val_f)
            if typ_f == 'mem':
                values.add(0x0)
            if typ_f == 'reg':
                val_s = val_f
                typ_s = 'reg'
                # min_stmt = min_r
                worklist.append((bb_id, val_f, 'reg', min_r))
            if typ_f == 'tmp':
                val_s = val_f
                typ_s = 'tmp'
                # min_stmt = min_r
                worklist.append((bb_id, val_f, 'tmp', min_r))
            if typ_f == 'unset':
                for p_id in self.cfg.parents[bb_id]:
                    if p_id not in nodes_visited:
                        worklist.append((p_id, val_s, typ_s, 0))
                nodes_visited.add(bb_id)
                    # bb = self.cfg.nodes[prnts.pop()]
                # bb = bb.parent
                # min_stmt = 0

        # print("STOP")

        return values 

        # # print("SEEK")
        # # from IPython import embed; embed()

        # min_stmt = 0
        # while bb:
        #     # if bb.state.addr == 0x39f5f:
        #     #     from IPython import embed; embed()

        #     (val_f, typ_f, min_r) = self.get_input_of(bb.state.block().vex, val_s, typ_s, min_stmt)

        #     # print(f"(0x{bb.state.addr:x}): [{val_s}, {typ_s}] => [{val_f}, {typ_f}]")

        #     if typ_f == 'imm':
        #         return val_f
        #     if typ_f == 'mem':
        #         return 0x0
        #     if typ_f == 'reg':
        #         val_s = val_f
        #         typ_s = 'reg'
        #         min_stmt = min_r
        #     if typ_f == 'tmp':
        #         val_s = val_f
        #         typ_s = 'tmp'
        #         min_stmt = min_r
        #     if typ_f == 'unset':
        #         bb_id = bb.getId()
        #         prnts = self.cfg.parents[bb_id].copy()
        #         if len(prnts) > 1:
        #             print("too many parents")
        #             break
        #         bb = self.cfg.nodes[prnts.pop()]
        #         # bb = bb.parent
        #         min_stmt = 0

        # # print("STOP")

        # return None 

class DecomposedEnclave(common.Analysis):
    def load_binary(self):
        ## NOTE:
        # auto_load_libs = Flase -> I don't want libc, in SGX everything is statically linked
        # base_addr = 0x0 -> I want relative address, that's easier
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
    
    def compute_dominators(self, cfg):
        dom_list = {}

        # dominator of the start node is the start itself
        # Dom(n0) = {n0}
        n0_id = cfg.node0
        n0 = cfg.nodes[n0_id]
        dom_list[n0_id] = set( { n0_id } )
        # for all other nodes, set all nodes as the dominators
        # for each n in N - {n0}
        for n_id, n in set(cfg.nodes.items()).difference( { (n0_id, n0) } ):
            # Dom(n) = N;
            # n_id = n.getId()
            # dom_list[n_id] = set([_.getId() for _ in cfg.nodes])
            dom_list[n_id] = set(cfg.nodes.keys())

        # iteratively eliminate nodes that are not dominators
        theres_changes = True
        while theres_changes:
            theres_changes = False
            # for each n in N - {n0}:
            # for n in cfg.nodes.difference( { n0 } ):
            for n_id, n in set(cfg.nodes.items()).difference( { (n0_id, n0) } ):
                
                # n_id = n.getId()

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

    def get_backedges(self, cfg, dom_list):
        backedges = set()
        # find back-edge
        # print("\nback edges:")
        for n_id, n in cfg.nodes.items():
            # n_id = n.getId()
            for c_id in cfg.children[n_id]:
                if len(cfg.children[n_id]) == 2 and c_id in dom_list[n_id]:
                    # print("{} => {}".format(n, c))

                    # iterat = c.addr
                    iterat = c_id[0]

                    # c_cp = n.children.copy()
                    # c_cp.remove(c)
                    # wo_node = c_cp.pop()
                    c_cp = cfg.children[n_id].copy()
                    c_cp.remove(c_id)
                    wo_node = c_cp.pop()

                    if n.state.block().capstone.insns:
                        # li = n.state.block().capstone.insns[-1]
                        # # way_out = wo_node.addr
                        # way_out = wo_node[0]
                        # adl = li.insn.address
                        # addr_loops_local[adl] = (way_out, iterat)
                        # print("0x{:x} -> [0x{:x}, 0x{:x}]".format(adl,way_out,iterat))
                        backedges.add((n_id[0], iterat))
        return backedges

    def normalize_cfg(self, cfg):

        is_changed = True
        while is_changed:
            # print(cfg)
            is_changed = False
            for n1_id, n1 in cfg.nodes.copy().items():
                for n2_id, n2 in cfg.nodes.copy().items():
                    if n1.overlaps(n2):
                        # print("=> {} overlaps {}".format(n1, n2))

                        # if n1.addr == 0x17d8 and n1.size == 16 and n1.addr == 0x17de and n1.size == 10:
                        #     print("BEFORE")
                        #     from IPython import embed; embed()

                        n1_prime = BasicBlockNode(n1.state)
                        n1_prime.size = n1.size - n2.size

                        # n1_id = n1.getId()
                        # n2_id = n2.getId()
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
                        # cfg.nodes.remove(n1)
                        del cfg.nodes[n1_id]
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

    def get_cfg(self, addr):

        cfg = CFG()

        addr_loops_local = {}

        i_s = self.project.factory.call_state(addr)
        cfg.setNode0(BasicBlockNode(i_s))
        node_to_visit = [cfg.nodes[cfg.node0]]

        while node_to_visit:
            node = node_to_visit.pop()

            iv = node.state.block().vex
            ninst = node.state.block().instructions

            # if iv.addr == 0xfdb:
            #     print("frmo get_cfg")
            #     import ipdb, monkeyhex; ipdb.set_trace()

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
                    pass 
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
    

    def isWithinFun(self, instrAddr, funAddr):
        prevAddr = None
        prevName = None
        for addr, name, is_traced in self.functions:
            if funAddr == prevAddr:
                return instrAddr > prevAddr and instrAddr < addr

            prevAddr = addr
            prevName = name

        return False

    def getFunBound(self, funAddr):
        prevAddr = None
        for addr, name, is_traced in self.functions:
            if funAddr == prevAddr:
                return (prevAddr, addr)
            prevAddr = addr

        return None

    # TODO: this thing is very ugly! try with a dictionary plz
    def get_action_type(self, funName):
        if funName == '_Z10traceedgecPv':
            return 'E'
        if funName == '_Z15traceassigmentfPv':
            return 'A'
        if funName == '_Z7tracebrPv':
            return 'B'
        if funName == 'trace_context_generation':
            return 'G'
        if funName == 'trace_eexit':
            return 'D'
        if funName == 'trace_context_consume':
            return 'C'
        if funName == '_Z12trace_eenteri':
            return 'N'
        if funName == '_Z12trace_eexit2v':
            return 'T'
        if funName == '_Z13trace_eresumev':
            return 'L'
        if funName == '_Z27trace_exception_consumptionP17_exception_info_t':
            return 'K'
        if funName == '_Z26trace_exception_generationP17_exception_info_t':
            return 'J'

        return None

    def make_action(self, typ, src, value, tag = None):
        # if tag is None:
        #     return  "{}[0x{:x}, 0x{:x}]".format(typ, src, value)
        # else:
        #     return "{}[0x{:x}, 0x{:x}, <{}>]".format(typ, src, value, tag)
        return (typ, f"0x{src:x}", f"0x{value:x}", tag)
        
    def analyze_static(self, addr, fnc):

        # get control-flow graph
        cfg = self.get_cfg(addr)

        # print(cfg)
        cfg_n = self.normalize_cfg(cfg)
        # print(cfg)
        # compute dominators
        # dom_list = self.compute_dominators(cfg_n)

        N = len(cfg.nodes)

        # get backedges
        # cfg.backedges = self.get_backedges(cfg_n, dom_list)

        # node_to_process = cfg.nodes.copy()
        node_to_process = set()
        node_to_process.add(cfg.node0)
        node_visited = set()

        E = 0
        P = 1
    
        DC = 0
        IC = 0

        while node_to_process:
            
            node_id = node_to_process.pop()
            if node_id not in cfg.nodes:
                continue
            node = cfg.nodes[node_id]

            # print(node)
            # print(node.state.block().pp())

            iv = node.state.block().vex
            if iv.jumpkind == 'Ijk_Call':
                if len(iv.constant_jump_targets) > 0:
                    DC += 1
                else:
                    IC +=1
                    print("-----")
                    print(f"{fnc}")
                    print("-----")
                    print(iv.pp())

            children = {}

            if node_id in cfg.children:
                children = cfg.children[node_id]

            if len(children) > 1:
                P += 1

            for child_id in children:
                E += 1
                if child_id in node_visited:
                    continue
                node_to_process.add(child_id)

            node_visited.add(node_id)

        M = E - N + P
        # print(f"[INFO] n. nodes {N}")
        # print(f"[INFO] n. edges {E}")
        # print(f"[INFO] n. branches {P}")
        # print(f"[INFO] cyclomatic complexity {M}")


        # from IPython import embed; embed(); exit()

        return (P, N, E, DC, IC)


    
    # def analyze_enter_enclave(self):
                
    #     tc = tracer_collector.TracerCollector(self.dump_model)
    #     ecall_tbl = self.project.loader.main_object.get_symbol("g_ecall_table")
    #     if ecall_tbl is None:
    #         print(" **** ERROR, g_ecall_table not found")
    #         exit()
    #     ecall_tbl_addr = ecall_tbl.linked_addr
    #     print("ecall_tbl_addr = 0x{:x}".format(ecall_tbl_addr))

    #     st = self.project.factory.blank_state()

    #     sym_ecall_n = st.memory.load(ecall_tbl_addr, 8, endness=archinfo.Endness.LE) 
    #     ecall_n = st.solver.eval(sym_ecall_n)
        
    #     print("ecall_n = 0x{:x}".format(ecall_n))

    #     for i in range(ecall_n):
    #         ecall_addr = ecall_tbl_addr + 0x8 + (0x8 * (i*2))
    #         sym_sfun_addr = st.memory.load(ecall_addr, 8, endness=archinfo.Endness.LE) 
    #         sfun_addr = st.solver.eval(sym_sfun_addr)

    #         sym_fun = self.project.loader.find_symbol(sfun_addr)
    #         if sym_fun is None:
    #             print(" **** ERROR: {} is not a symbol".format(sym_fun))
    #             exit()
    #         if not sym_fun.is_function:
    #             print(" **** ERROR: {} is not a function".format(sym_fun))
    #             exit()

    #         sfun_name = sym_fun.name

    #         print("0x{:x} @ 0x{:x} @ {}".format(i, sfun_addr, sfun_name))

    #         t = tracer.MyTracer() 
    #         t.add("N", self.specialactions["N"], f"0x{i:x}", sfun_name)
    #         t.add("T", self.specialactions["T"], "0x0")
    #         tc.dump(t)
    #         del(t)

    #     t = tracer.MyTracer() 
    #     t.add("N", self.specialactions["N"], "0x{:x}".format(-2 & 0xffffffffffffffff), "asm_oret")
    #     tc.dump(t)
    #     del(t)

    #     t = tracer.MyTracer() 
    #     t.add("N", self.specialactions["N"], "0x{:x}".format(-3 & 0xffffffffffffffff), "trts_handle_exception")
    #     tc.dump(t)
    #     del(t)

    def start_analysis(self):

        failedfunctions = []

        self.functions = self.get_functions()
        self.traced_functions = [fnc for addr, fnc, is_traced in self.functions if is_traced]

        M = []
        N = []
        E = []
        DC = []
        IC = []

        for addr, fnc, is_traced in self.functions:

            if not is_traced:
                continue
            
            if self.function is not None and fnc != self.function:
                continue
            
            print("{} @ 0x{:x}".format(fnc, addr))

            # with open(self.dump_model, 'a+') as f:
            #     f.write("<{}>:\n".format(fnc))
                
            if fnc == "enter_enclave":
                print("[INFO] I skip enter_enclave")
                # self.analyze_enter_enclave()
            else:
                _M, _N, _E, _DC, _IC = self.analyze_static(addr, fnc)
                M.append(_M)
                N.append(_N)
                E.append(_E)
                DC.append(_DC)
                IC.append(_IC)
                

        print("[INFO] end analysis")

        M_avg = sum(M)/len(M)
        M_std = statistics.stdev(M)
        print(f"[INFO] average cyclomatic complexity = {M_avg}")
        print(f"[INFO] std. dev cyclomatic complexity = {M_std}")
        N_avg = sum(N)/len(N)
        N_std = statistics.stdev(N)
        print(f"[INFO] average n. nodes = {N_avg}")
        print(f"[INFO] std. dev n. nodes = {N_std}")
        E_avg = sum(E)/len(E)
        E_std = statistics.stdev(E)
        print(f"[INFO] average n. edges = {E_avg}")
        print(f"[INFO] std. dev n. edges = {E_std}")
        DC_avg = sum(DC)/len(DC)
        DC_std = statistics.stdev(DC)
        DC_sum = sum(DC)
        print(f"[INFO] average n. direct call = {DC_avg}")
        print(f"[INFO] std. dev n. direct call = {DC_std}")
        print(f"[INFO] number of direct call = {DC_sum}")
        IC_avg = sum(IC)/len(IC)
        IC_std = statistics.stdev(IC)
        IC_sum = sum(IC)
        print(f"[INFO] average n. indirect call = {IC_avg}")
        print(f"[INFO] std. dev n. indirect call = {IC_std}")
        print(f"[INFO] number of indirect call = {IC_sum}")
        # print(IC)

        global use_case

        with open(self.dump_model, 'a+') as f:
            f.write(f"{use_case}|{M_avg}|{M_std}|{N_avg}|{N_std}|{E_avg}|{E_std}|{DC_avg}|{DC_std}|{DC_sum}|{IC_avg}|{IC_std}|{IC_sum}\n")
            # f.write(f"{self.enclave_bin}|{M_avg}|{M_std}|{N_avg}|{N_std}|{E_avg}|{E_std}|{DC_avg}|{DC_std}|{DC_sum}|{IC_avg}|{IC_std}|{IC_sum}\n")

        # from IPython import embed; embed()

        print("failed functions:")
        print(failedfunctions)

use_case = ""

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--enclave', '-e', required=True, type=str, help='The enclave to analyze')
    parser.add_argument('--asm_folder', '-f', required=False, type=str, help='Folder where keeping asm fies', default='asms')
    parser.add_argument('--dump', '-d', required=False, type=str, help='Model', default='model.txt')
    parser.add_argument('--trace_bbl', '-b', action='store_true', required=False, help='Dump basic-blocks')
    parser.add_argument('--errored', '-r', required=False, type=str, help='Errored status', default=None)
    parser.add_argument('--custom_module', '-c', required=False, type=str, help='Module with customization for enclaves', default=None)
    parser.add_argument('--loops', '-l', required=False, type=str, help='Loop info file', default=None) # maybe no need
    parser.add_argument('--function', '-n', required=False, type=str, help='Analyze a single function', default=None) 
    parser.add_argument('--use_case', '-u', required=True, type=str, help='Use case name', default=None) 


    args = parser.parse_args()

    enclave_bin = args.enclave
    asm_folder = args.asm_folder
    dump_model = args.dump
    trace_bbl = args.trace_bbl
    errored = args.errored
    custom_module = args.custom_module
    loop_info = args.loops
    function = args.function
    l_use_case args.use_case

    global use_case
    use_case = l_use_case


    global a
    a = DecomposedEnclave(enclave_bin, asm_folder, trace_bbl, custom_module, dump_model, loop_info, function)
    a.load_binary()
    a.preliminaries()
    a.start_analysis()

    if dump_model:
        a.dumpModel(dump_model)
    else:
        for i, t in enumerate(a.traces):
            print("{}: {}".format(i, t))
            print()

if __name__ == "__main__":
    main()
