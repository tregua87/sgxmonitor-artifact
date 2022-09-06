#!/usr/bin/env python3

# https://docs.angr.io/core-concepts/solver

import os, sys, argparse, ntpath, pyvex, time, timeout_decorator, subprocess, statistics

# project imports
sys.path.append('./lib')
import module, shadowstack, tracer, common, tracer_collector, loopsmanager

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

class BasicBlockNode:
    def __init__(self, state, parent = None, action = None):
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

        if not iv.statements:
            return  (None, 'unset', 0)
        return (None, 'unset', i)

    def get_origin_of(self, val_s, typ_s):

        # # backward analysis to find val_s value
        # # the analysis follow RDI (and EDI) assignments until we find a *constant* or a *memory assignment*

        bb = self

        # print("SEEK")
        # from IPython import embed; embed()

        min_stmt = 0
        is_free = True
        while bb:
            # if bb.state.addr == 0x39f5f:
            #     from IPython import embed; embed()

            (val_f, typ_f, min_r) = self.get_input_of(bb.state.block().vex, val_s, typ_s, min_stmt)

            # print("(0x{:x}): [{}, {}] => [{}, {}]".format(bb.state.addr, val_s, typ_s, val_f, typ_f))

            if typ_f == 'imm':
                is_free = False
                break
            if typ_f == 'mem':
                is_free = False
                break
            if typ_f == 'reg':
                val_s = val_f
                typ_s = 'reg'
                min_stmt = min_r
            if typ_f == 'tmp':
                val_s = val_f
                typ_s = 'tmp'
                min_stmt = min_r
            if typ_f == 'unset':
                # print()
                bb = bb.parent
                min_stmt = 0

        # print("STOP")

        return (is_free, val_s, typ_s)
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
    
    def isWithinFun(self, instrAddr, funAddr):
        prevAddr = None
        prevName = None
        for addr, name, is_traced in self.functions:
            if funAddr == prevAddr:
                return instrAddr > prevAddr and instrAddr < addr

            prevAddr = addr
            prevName = name

        return False

    def get_free_arguments(self, fnc, addr):

        free_arguments = set()
        cache = set() # (addr, obj, tmp)
        addr_loops_local = {}

        i_s = self.project.factory.call_state(addr)
        node_to_visit = [BasicBlockNode(i_s)]

        while node_to_visit:
            node = node_to_visit.pop()

            iv = node.state.block().vex
            ninst = node.state.block().instructions

            # if iv.addr == 0x360b:
            #     from IPython import embed; embed()

            #     # import ipdb, monkeyhex; ipdb.set_trace()

            # print("iv @ 0x{:x}".format(iv.addr))

            # search load statements in iv
            for s in iv.statements:
                if isinstance(s, pyvex.stmt.WrTmp) and isinstance(s.data, pyvex.expr.Load):
                    # s.pp()
                    if isinstance(s.data.addr, pyvex.expr.RdTmp):
                        typ = 'tmp'
                        obj = s.data.addr.tmp
                    elif isinstance(s.data.addr, pyvex.expr.Const):
                        continue
                    else:
                        print("don't know how to do")
                        from IPython import embed; embed()

                    if (iv.addr, obj, typ) not in cache:
                        (is_free, obj_f, typ_f) =  node.get_origin_of(obj, typ)
                        if is_free:
                            # print("0x{:x} @ {} - {} is free var driven by {} {}".format(iv.addr, obj, typ, obj_f, typ_f))
                            free_arguments.add((obj_f, typ_f))
                        cache.add((iv.addr, obj, typ))
                    # from IPython import embed; embed()

            # print(" -> visit 0x{:x}".format(node.state.addr))

            if iv.jumpkind == 'Ijk_Call':
                # print(" ****** I am a call ******")
               if iv.constant_jump_targets and iv.constant_jump_targets.pop() not in self.stop_exploration_addr:
                    n_state = node.state.copy()
                    n_state.regs.rip = n_state.regs.rip + iv.size
                    n_node = BasicBlockNode(n_state, parent=node)
                    node_to_visit.append(n_node)
            elif iv.jumpkind == 'Ijk_Ret':
                # ret from function => stop
                pass
            elif iv.jumpkind == 'Ijk_NoDecode':
                if iv.addr == self.ocall_enclu_addr or iv.addr in self.ud2list:
                    # enclu in ocall => stop
                    pass 
                elif iv.addr in self.rdrandlist:
                    leng = self.rdrandlengthlist[self.rdrandlist.index(iv.addr)]
                    n_state = node.state.copy()
                    n_state.regs.rip = n_state.regs.rip + leng
                    n_node = BasicBlockNode(n_state, parent=node)
                    node_to_visit.append(n_node)
                else:
                    print("I don't really kow what to do!")
                    from IPython import embed; embed()
            else:
                # print(" ****** I am a normal one ******")
                # from IPython import embed; embed()

                # this is to identify jmp to tracing functions, which de-facto leaves the function
                # if len(iv.constant_jump_targets) == 1 and iv.constant_jump_targets.pop() in traced_addr:
                if len(iv.constant_jump_targets) == 1 and iv.constant_jump_targets.pop() in self.traced_addr:
                   pass
                else:

                    # I keep only target the falls outside the basicblock
                    my_target = [t for t in iv.constant_jump_targets if t < iv.addr or t >= iv.addr + iv.size]
                    # and those targets that fall within the function
                    my_target = [t for t in my_target if self.isWithinFun(t, addr)]

                    if any([e is None for e in my_target]):
                        print("all the target are None")
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

        # translate to name
        free_args_name = []
        # from IPython import embed; embed()
        for (obj, typ) in free_arguments:
            if typ == 'reg':
                free_args_name.append(iv.arch.translate_register_name(obj, 8))

        return free_args_name

    # 10 minutes
    @timeout_decorator.timeout(60*10, timeout_exception=StopIteration)
    def analyse_symbolic(self, addr, fnc):
        self.make_state(fnc)

        # import ipdb; ipdb.set_trace()

        if not self.vanilla:
            if self.custom is not None and fnc in self.custom.functions:
                self.custom.make_arguments(fnc, self.init_state)
            else:
                # find undef struct pointers passed as argument
                print("[{}] Getting free arguments...".format(fnc))
                free_args = self.get_free_arguments(fnc, addr)
                print("[{}] Free arguments: {}".format(fnc, ", ".join([x for x in free_args if x not in ['rbp', 'rsp', 'fs']])))
                default_arg_size = 512 #byte
                for r in free_args:
                    if r not in  ['rbp', 'rsp', 'fs']:
                        # symbolic object somewere in the heap
                        sym_obj_addr = self.init_state.heap.allocate(default_arg_size) 
                        sym_obj = self.init_state.solver.BVS("sym_obj_{}".format(r), default_arg_size*8)
                        self.init_state.memory.store(sym_obj_addr, sym_obj, endness=archinfo.Endness.LE)
                        for x in range(default_arg_size):
                            sym_obj = self.init_state.solver.BVS("sym_obj_{}_{}".format(r,x), 8)
                            self.init_state.memory.store(sym_obj_addr + x, sym_obj, endness=archinfo.Endness.LE)
                        
                        arg_sym_ptr = self.init_state.solver.BVS("ptr_arg_{}".format(r), 8*8)
                        
                        # self.init_state.solver.add(arg_sym_ptr == sym_obj_addr)
                        # self.init_state.solver.add(arg_sym_ptr == 0x0)
                        self.init_state.solver.Or(arg_sym_ptr == 0x0, arg_sym_ptr == sym_obj_addr)
                        setattr(self.init_state.regs, r, arg_sym_ptr)
                        # setattr(self.init_state.regs, r, sym_obj_addr)


        # NOTE: this is for me, sometimes angr gets crazy and attempts at executing instructions at address 0x0
        # self.init_state.inspect.b('instruction', when=BP_BEFORE, action=checkInstr0, instruction=0x0)

        # self.makeregistersymbolicEcall(self.secfun)

        stack_base_addr = 0xFFFFFFFFFFFFFFFF

        self.init_state.regs.gs = 0x7f000000
        self.init_state.mem[self.init_state.regs.gs].uint64_t = 0x7f000000

        # THREAD DATA
        # stack_base_addr
        self.init_state.mem[self.init_state.regs.gs + 0x10].uint64_t = stack_base_addr
        self.init_state.memory.store(self.init_state.regs.rsp, 0x0, endness=archinfo.arch.Endness.LE)

        # I get a simulation manager
        simgr = self.project.factory.simgr(self.init_state)
        self.simgr = simgr

        try:
            print("[{}] Starting exploration...".format(fnc))
            simgr.run()
            # simgr.explore(find=0x4780)
            print("[{}] Done".format(fnc))
        except:
            print("[ERROR] {} failed, go for insensitive analysis".format(fnc))
            self.failedfunctions.append(fnc)

            print("[INFO] start dumping whatever traversed in {}".format(fnc))
            tc = self.tracer_collector
            for s in self.simgr.active:
                mt = s.my_tracer
                tc.dump(mt)
            print("[INFO] done")

        # if not simgr.found:
        #     print(" => NOT FOUND")
        # else:
        #     print(simgr.one_found)
        #     f = simgr.one_found
        #     from IPython import embed; embed()
        
        # from IPython import embed; embed()
        # self.extractTrace(simgr.deadended)

        # if simgr.errored:
        #     for er in simgr.errored:
        #         s = er.state
        #         self.errored.add(str(s))
        # from IPython import embed; embed()
        # exit()


    def start_analysis(self):

        self.failedfunctions = []
        self.timeoutfunctions = []

        print("[INFO] start analysis..")

        self.stats = {}

        old_hook = None
        for addr, fnc, is_traced in self.functions:

            if not is_traced:
                continue

            # FOR DEBUG ONLY
            # if fnc in ["ocall_ioctl_ReportRPC"]:
            #     continue
            if self.function is not None and self.function != fnc:
                continue

            if self.project.is_hooked(addr):
                old_hook = self.project.hooked_by(addr)
                self.project.unhook(addr)
            
            print("{} @ 0x{:x}".format(fnc, addr))

            with open(self.dump_model, 'a+') as f:
                f.write("<{}>:\n".format(fnc))

            if fnc == "trts_handle_exception":
                t = tracer.MyTracer() 
                t.add("J", self.specialactions["J"], "0x0")
                self.tracer_collector.dump(t)

                self.stats[fnc] = {}
            elif fnc == "enter_enclave":
                ecall_tbl = self.project.loader.main_object.get_symbol("g_ecall_table")
                if ecall_tbl is None:
                    print(" **** ERROR, g_ecall_table not found")
                    exit()
                ecall_tbl_addr = ecall_tbl.linked_addr
                print("ecall_tbl_addr = 0x{:x}".format(ecall_tbl_addr))

                st = self.project.factory.blank_state()

                sym_ecall_n = st.memory.load(ecall_tbl_addr, 8, endness=archinfo.Endness.LE) 
                ecall_n = st.solver.eval(sym_ecall_n)
                
                print("ecall_n = 0x{:x}".format(ecall_n))

                for i in range(ecall_n):
                    ecall_addr = ecall_tbl_addr + 0x8 + (0x8 * (i*2))
                    sym_sfun_addr = st.memory.load(ecall_addr, 8, endness=archinfo.Endness.LE) 
                    sfun_addr = st.solver.eval(sym_sfun_addr)

                    sym_fun = self.project.loader.find_symbol(sfun_addr)
                    if sym_fun is None:
                        print(" **** ERROR: {} is not a symbol".format(sym_fun))
                        exit()
                    if not sym_fun.is_function:
                        print(" **** ERROR: {} is not a function".format(sym_fun))
                        exit()

                    sfun_name = sym_fun.name

                    print("0x{:x} @ 0x{:x} @ {}".format(i, sfun_addr, sfun_name))

                    t = tracer.MyTracer() 
                    t.add("N", self.specialactions["N"], f"0x{i:x}", sfun_name)
                    t.add("T", self.specialactions["T"], "0x0")
                    self.tracer_collector.dump(t)
                    del(t)

                t = tracer.MyTracer() 
                t.add("N", self.specialactions["N"], "0x{:x}".format(-2 & 0xffffffffffffffff), "asm_oret")
                self.tracer_collector.dump(t)
                del(t)

                t = tracer.MyTracer() 
                t.add("N", self.specialactions["N"], "0x{:x}".format(-3 & 0xffffffffffffffff), "trts_handle_exception")
                self.tracer_collector.dump(t)
                del(t)

                self.stats[fnc] = {}
            elif fnc == "internal_handle_exception":

                self.make_state(fnc, False)

                gFirstNode = self.project.loader.main_object.get_symbol('_ZL12g_first_node')

                # heap address
                queue_handler_addr = 0xA000000000000000
                size_handler_node = 0x10 # 0x8 -> callback; 0x8 -> next
                # no have registered handler -> the queue is zero
                if not self.registeredhandler:
                    self.init_state.memory.store(gFirstNode.linked_addr, 0x0)
                else:
                    addr = queue_handler_addr
                    s_addr = self.init_state.solver.BVS("first_handler", 64)

                    # this allows angr to pretend having 0 or > 0 handlers
                    # thus, it explores better :)
                    self.init_state.solver.add(s_addr == addr)

                    self.init_state.memory.store(gFirstNode.linked_addr, s_addr, endness=archinfo.Endness.LE)
                    maxH = len(self.registeredhandler)
                    for i, h in enumerate(self.registeredhandler):
                        # typedef struct _handler_node_t
                        # {
                        #     uintptr_t callback;
                        self.init_state.memory.store(addr, h, endness=archinfo.Endness.LE)
                        #     struct _handler_node_t   *next;
                        next = 0 if i == maxH - 1 else addr + size_handler_node
                        self.init_state.memory.store(addr + 0x8, next, endness=archinfo.Endness.LE)
                        # } handler_node_t;
                        addr = addr + size_handler_node

                gEDMMSupport = self.project.loader.main_object.get_symbol('EDMM_supported')
                # self.init_state.memory.store(gEDMMSupport.linked_addr, self.init_state.solver.BVV(0x0, 8))
                self.init_state.memory.store(gEDMMSupport.linked_addr, self.init_state.solver.BVS('EDMM_supported', 64*8))

                # don't know if we need this
                gGlobalData = self.project.loader.main_object.get_symbol('g_global_data')
                self.init_state.memory.store(gGlobalData.linked_addr, self.init_state.solver.BVS("gGlobalData", 64*8))
                # self.init_state.memory.store(gGlobalData.linked_addr, 0x2)

                gEnclaveState = self.project.loader.main_object.get_symbol('g_enclave_state')
                self.init_state.memory.store(gEnclaveState.linked_addr, self.init_state.solver.BVV(0x2, 8))

                gIsFirstEcall = self.project.loader.main_object.get_symbol('_ZL16g_is_first_ecall')
                self.init_state.memory.store(gIsFirstEcall.linked_addr, 0x0)

                # NOTE: this is for me, sometimes angr gets crazy and attempts at executing instructions at address 0x0
                # self.init_state.inspect.b('instruction', when=BP_BEFORE, action=checkInstr0, instruction=0x0)

                # self.makeregistersymbolicEcall(self.secfun)

                stack_base_addr = 0xFFFFFFFFFFFFFFFF

                self.init_state.regs.gs = 0x7f000000
                self.init_state.mem[self.init_state.regs.gs].uint64_t = 0x7f000000

                # THREAD DATA
                # stack_base_addr
                self.init_state.mem[self.init_state.regs.gs + 0x10].uint64_t = stack_base_addr

                self.init_state.regs.rsp = stack_base_addr
                self.init_state.regs.rbp = stack_base_addr

                self.init_state.memory.store(self.init_state.regs.rsp, 0x0, endness=archinfo.arch.Endness.LE)

                # #XXX exception_flag = 1
                # self.init_state.mem[self.init_state.regs.gs + 0x60].uint64_t = 1
                #
                # #XXX first_ssa_gpr
                # self.init_state.mem[self.init_state.regs.gs + 0x20].uint64_t = self.init_state.solver.BVS("first_ssa_gpr", 64)

                # I get a simulation manager
                simgr = self.project.factory.simgr(self.init_state)
                self.simgr = simgr

                # from IPython import embed; embed()

                try:
                    print("[{}] Starting exploration...".format(fnc))
                    begin_anal = time.time()
                    simgr.run()
                    end_anal = time.time()
                    anal_time =  end_anal - begin_anal

                    self.stats[fnc] = {"anal": anal_time}
                    # simgr.explore(find=0xd6f0)
                    print("[{}] Done".format(fnc))
                except:
                    self.failedfunctions.append(fnc)
                    del self.simgr
                    del self.init_state

                # if not simgr.found:
                #     print(" => NOT FOUND")
                # else:
                #     print(simgr.one_found)
                #     f = simgr.one_found
                #     from IPython import embed; embed()

            else:
                try:
                    begin_anal = time.time()
                    self.analyse_symbolic(addr, fnc)
                    end_anal = time.time()
                    anal_time =  end_anal - begin_anal
                    self.stats[fnc] = {"anal": anal_time}
                    del self.simgr
                    del self.init_state
                except:
                    print("[ERROR] {} took too long, go for insensitive analysis".format(fnc))
                    self.timeoutfunctions.append(fnc)
                    # del self.simgr
                    # del self.init_state
                
                    # print("start a console?")
                    # from IPython import embed; embed(); exit()
                    print("[INFO] start dumping whatever traversed in {}".format(fnc))
                    try:
                        self.simgr
                    except NameError:
                        self.simgr = None
                    if self.simgr is not None:
                        tc = self.tracer_collector
                        for s in self.simgr.active:
                            mt = s.my_tracer
                            tc.dump(mt)
                    print("[INFO] done")

            if old_hook is not None:
                self.project.hook(addr, old_hook)
                old_hook = None

        with open(self.dump_model, 'a+') as f:
            f.write("<end>:\n")

        print("failed functions:")
        print(self.failedfunctions)
        print("timeout functions:")
        print(self.timeoutfunctions)

        for f in set(self.timeoutfunctions + self.failedfunctions):
            self.stats[f]["static"] = True
            # ./explore_decomposed_stc_enclave.py -e ../src/contact_traced_toplaywith/enclave.signed.so -n crecip
            arg_insensitive_analysis = ["./explore_decomposed_stc_enclave.py", "-e", self.enclave_bin, "-n", f, "-d", os.path.join(os.getcwd(), "model-insensitive.txt")]
            subprocess.run(arg_insensitive_analysis, cwd="../analyzer2/")
            
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
    parser.add_argument('--vanilla', '-v', required=False, action='store_true', help='Vanilla analysis (no free args or public vars)') 


    args = parser.parse_args()

    enclave_bin = args.enclave
    asm_folder = args.asm_folder
    dump_model = args.dump
    trace_bbl = args.trace_bbl
    errored = args.errored
    custom_module = args.custom_module
    loop_info = args.loops
    function = args.function
    vanilla = args.vanilla

    global a
    a = DecomposedEnclave(enclave_bin, asm_folder, trace_bbl, custom_module, dump_model, loop_info, function)
    a.vanilla = vanilla
    a.load_binary()
    a.preliminaries()
    a.start_analysis()

    if errored is not None:
        a.dumpErrored(errored)

    if dump_model:
        a.dumpModel(dump_model)
    else:
        for i, t in enumerate(a.traces):
            print("{}: {}".format(i, t))
            print()


    # print(a.stats)
    n_function = len(a.stats.keys())
    n_static = 0
    anal_time = []
    for k, v in a.stats.items():
        if "static" in v:
            n_static += 1
        if "anal" in v:
            anal_time += [v["anal"]]

    with open("statistics.txt", "w") as sf:
        sf.write(f"n_function {n_function}\n")
        sf.write(f"n_static function {n_static}\n")
        x = sum(anal_time)
        sf.write(f"tot. anal time {x} [s]\n")
        x = statistics.mean(anal_time)
        sf.write(f"avg. anal time {x} [s]\n")
        x = statistics.stdev(anal_time)
        sf.write(f"std. dev anal time {x}\n")

if __name__ == "__main__":
    main()
