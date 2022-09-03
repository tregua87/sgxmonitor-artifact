#!/usr/bin/python3

# https://docs.angr.io/core-concepts/solver

import os
import sys
import argparse
import ntpath


# project imports
sys.path.append('./lib')
import module
import shadowstack, tracer, common, tracer_collector, loopsmanager

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

class TracedEnclave(common.Analysis):
    def start_analysis(self):

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
        self.init_state.inspect.b('instruction', when=BP_BEFORE, action=checkInstr0, instruction=0x0)

        self.makeregistersymbolicEcall(self.secfun)

        stack_base_addr = 0xFFFFFFFFFFFFFFFF

        self.init_state.regs.gs = 0x7f000000
        self.init_state.mem[self.init_state.regs.gs].uint64_t = 0x7f000000

        # same stack than before?
        self.init_state.regs.rbp = stack_base_addr
        # self.init_state.regs.rsp = stack_base_addr

        # THREAD DATA
        # stack_base_addr
        self.init_state.mem[self.init_state.regs.gs + 0x10].uint64_t = stack_base_addr

        # #XXX exception_flag = 1
        # self.init_state.mem[self.init_state.regs.gs + 0x60].uint64_t = 1
        #
        # #XXX first_ssa_gpr
        # self.init_state.mem[self.init_state.regs.gs + 0x20].uint64_t = self.init_state.solver.BVS("first_ssa_gpr", 64)

        # I get a simulation manager
        simgr = self.project.factory.simgr(self.init_state)
        self.simgr = simgr

        # from IPython import embed; embed()

        print("[ECALL] Starting exploration...")
        simgr.run()
        # simgr.explore(find=[0x195d])
        print("[ECALL] Done")

        # if not simgr.found:
        #     print(" => NOT FOUND")
        # else:
        #     print(simgr.one_found)
        #     f = simgr.one_found
        #     # logging.getLogger('angr').setLevel('DEBUG')
        #     from IPython import embed; embed()
        #     # f = f.step()[0].step()[0]
        #     # sim = self.project.factory.simgr(f)
        #     # sim.explore(find=[0x6db8])

        #     # f = simgr.one_found

        #     # # from IPython import embed; embed()
        #     # import pdb; pdb.set_trace()
        #     # f.step()
        # # from IPython import embed; embed()
        
        # print(" I END HERE FOR DEBUG")
        # exit()

        self.extractTrace(simgr.deadended)

        if simgr.errored:
            for er in simgr.errored:
                s = er.state
                self.errored.add(str(s) + " - " + str(s.my_shadowstack))

        # for endness
        e=archinfo.Endness.LE
        # &context = 0xffffffffffffff60
        # 0xffffffffffffdc67 context+0x58
        prevPending = len(self.pendingstate)
        # from IPython import embed; embed()
        print("I have [{}] pending states".format(len(self.pendingstate)))
        while self.pendingstate:
            if prevPending > len(self.pendingstate):
                prevPending = len(self.pendingstate)
            elif prevPending < len(self.pendingstate):
                print(" **** => PENDING STATES GET BIGGER <= ****")
                print(" > prevPending: {}".format(prevPending))
                print(" > currPending: {}".format(len(self.pendingstate)))
                # sys.stdin.read(1)
                prevPending = len(self.pendingstate)

            print(" **** => PICK A PENDING STATE <= ****")
            s = self.pendingstate.pop()

            # saved_stack = s.globals["saved_stack"]

            r_gs = s.regs.gs
            sym_last_sp = s.memory.load(r_gs + 0x8, 8, endness=e)
            last_sp = s.solver.eval(sym_last_sp)
            print("last_sp 0x{:x}".format(last_sp))

            ocall_context = s.solver.eval(last_sp)

            print("ocall_context 0x{:x}".format(ocall_context))

            sym_prev_rbp = s.memory.load(ocall_context + 0x58, 8, endness=e)
            prev_rbp = s.solver.eval(sym_prev_rbp)

            print("prev_rbp 0x{:x}".format(prev_rbp))

            sym_rbp = s.memory.load(prev_rbp, 8, endness=e)
            sym_rip = s.memory.load(prev_rbp + 0x8, 8, endness=e)

            rbp = s.solver.eval(sym_rbp)
            rip = s.solver.eval(sym_rip)

            print(" **** => INFERRED VALUES <= ****")
            print("rbp 0x{:x}".format(rbp))
            print("rip 0x{:x}".format(rip))
            # from IPython import embed; embed()
            if rip == 0:
                print(" **** => SKIP BAD OCALL_CONTEXT <= ****")
                continue

            self.init_state = self.project.factory.call_state(self.enclave_entry.linked_addr)
            self.init_state.options.add(options.LAZY_SOLVES)
            self.init_state.register_plugin('my_shadowstack', shadowstack.MyShadowStack())
            self.init_state.register_plugin('my_tracer', tracer.MyTracer())
            self.init_state.register_plugin('my_loopsmanager', loopsmanager.MyLoopsManager(0))
            # self.init_state.register_plugin("sym_heap", state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())
            # this needs if we encounter new do_ocall
            self.init_state.globals["ocall_enclu_addr"] = self.ocall_enclu_addr
            self.init_state.globals["pendingstate"] = self.pendingstate
            self.init_state.globals["tracer_collector"] = self.tracer_collector
            # self.init_state.globals["saved_stack"] = saved_stack



            # from IPython import embed; embed()

            # NOTE: this MUST stay here because when angr generates the symbolic
            # ocall_context, it cannot infer extra conditions. The new
            # ocall_context must be located at least 0xF0 after the stack_base_addr
            # by design. Therefore, when I craft the new memory structures for
            # further analysis, I must WRITE the ocall_context in a correct position.
            ocall_context = ocall_context - 0xF0 # I try to move the ocall_context

            self.init_state.regs.gs = 0x7f000000
            self.init_state.mem[self.init_state.regs.gs].uint64_t = 0x7f000000

            self.makeregistersymbolicOcall(self.init_state)

            # same stack than before?
            self.init_state.regs.rbp = stack_base_addr

            # THREAD DATA
            # last_sp
            self.init_state.mem[self.init_state.regs.gs + 0x8].uint64_t = ocall_context
            # stack_base_addr
            self.init_state.mem[self.init_state.regs.gs + 0x10].uint64_t = stack_base_addr

            # OCALL_CONTEXT
            # xbp (rbp)
            self.init_state.mem[ocall_context + 0x58].uint64_t = prev_rbp

            # RET_RPB ARRAY
            # real rbp register used for restore the execution stack
            self.init_state.mem[prev_rbp].uint64_t = rbp
            # instruction to restart the execution
            self.init_state.mem[prev_rbp + 0x8].uint64_t = rip

            # I get a simulation manager
            simgr = self.project.factory.simgr(self.init_state)
            self.simgr = simgr

            self.init_state.globals["stack_base_addr"] = stack_base_addr
            self.init_state.globals["state_origin"] = s
            # self.project.hook(rip, module.RestoreStack(s, stack_base_addr), length=0)
            if not self.project.is_hooked(rip):
                self.project.hook(rip, module.myRestoreStack, length=0)

            print("[ORET] Starting exploration...")
            simgr.run()
            # simgr.explore(find=[0x133a])
            print("[ORET] Done.")

            # # NOTE: FOR DEBUGING USING EXPLORE(addr=0xsomewhere)
            # if not simgr.found:
            #     print(" => NO FOUND")
            # else:
            #     print(simgr.one_found)
            #     f = simgr.one_found
            #     from IPython import embed; embed()

            self.extractTrace(simgr.deadended)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--enclave', '-e', required=True, type=str, help='The enclave to analyze')
    parser.add_argument('--secure_function', '-s', required=True, type=int, help='The secure function to model')
    parser.add_argument('--enclave_entry', '-n', required=False, type=str, help='Enclave entry point', default='enclave_entry')
    parser.add_argument('--asm_folder', '-f', required=False, type=str, help='Folder where keeping asm fies', default='asms')
    parser.add_argument('--dump', '-d', required=False, type=str, help='Model', default='model.txt')
    parser.add_argument('--trace_bbl', '-b', action='store_true', required=False, help='Dump basic-blocks')
    parser.add_argument('--errored', '-r', required=False, type=str, help='Errored status', default=None)
    parser.add_argument('--custom_module', '-c', required=False, type=str, help='Module with customization for enclaves', default=None)
    parser.add_argument('--loops', '-l', required=False, type=str, help='Loop info file', default=None)


    args = parser.parse_args()

    fun_to_start = args.enclave_entry
    enclave_bin = args.enclave
    secfun = args.secure_function
    asm_folder = args.asm_folder
    dump_model = args.dump
    trace_bbl = args.trace_bbl
    errored = args.errored
    custom_module = args.custom_module
    loop_info = args.loops

    global a
    a = TracedEnclave(enclave_bin, fun_to_start, secfun, asm_folder, trace_bbl, custom_module, dump_model, loop_info)
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

if __name__ == "__main__":
    main()
