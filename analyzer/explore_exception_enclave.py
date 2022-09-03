#!/usr/bin/python3

# https://docs.angr.io/core-concepts/solver

import argparse
import logging
import ntpath
import os
import signal
import sys

from angr import *

sys.path.append('./lib')

import module
import shadowstack
import tracer
import common

def killmyself():
    os.system('kill %d' % os.getpid())
def sigint_handler(signum, frame):
    print('Stopping Execution for Debug. If you want to kill the programm issue: killmyself()')
    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)



def checkInstr0(state):
    print(" ***** HIT A ZERO! *****")
    from IPython import embed; embed()

class TracedException(common.Analysis):

    def preliminaries(self):
        super().preliminaries()

        # This is used to find exception handlers
        # 1) find sgx_register_exception_handler address
        regexc_addr = None
        with open(self.enclave_asm, 'r') as f:
            for l in f:
                if l.strip().endswith("<sgx_register_exception_handler>:"):
                    regexc_addr = common.parseinsaddr(l, "<")
                    break
        if not regexc_addr:
            print("sgx_register_exception_handler not found")
            exit(0)

        print("<sgx_register_exception_handler>: 0x{:x}".format(regexc_addr))

        # 2) find where sgx_register_exception_handler is called and get the parameters (from rsi)
        # 1b2a:	bf 01 00 00 00       	mov    edi,0x1
        # 1b2f:	48 8d 35 7a ff ff ff 	lea    rsi,[rip+0xffffffffffffff7a]        # 1ab0 <_Z22divide_by_zero_handlerP17_exception_info_t>
        # 1b36:	e8 25 2e 00 00       	call   4960 <sgx_register_exception_handler>
        token = "call{:x}<sgx_register_exception_handler>".format(regexc_addr)
        prevLine = None
        with open(self.enclave_asm, 'r') as f:
            for l in f:
                ll = l.strip().replace(" ", "")
                if ll.endswith(token):
                    if not prevLine:
                        print("Error in getting paramters of <sgx_register_exception_handler>")
                        exit(0)
                    # get parameters
                    sharpPos = prevLine.find("#")
                    minPos = prevLine.find("<")
                    handler_addr = prevLine[sharpPos + 1: minPos]
                    self.registeredhandler.append(int(handler_addr, 16))

                prevLine = l

    def analyze_trts_handle_exception(self):

        beginTrtsHandleException = False
        beginEnterEnclave = False

        excGenId = None
        trcEntId = None
        trcExtId = None

        # a.enclaveentry = getinsaddr(line1, "<")

        with open(self.enclave_asm,'r') as f1:
            lines = f1.readlines()
            for i, line1 in enumerate(lines):

                # this extracts the trace_exception_generation ID
                if not excGenId:
                    if "<trts_handle_exception>:" in line1:
                        beginTrtsHandleException = True
                    if beginTrtsHandleException:
                        if "trace_exception_generation" in line1:
                            excGenId = common.getinsaddr(lines[i+1],":")

                # this extracts the trace_eenter ID
                if not trcEntId:
                    if 'enter_enclave' in line1:
                        beginEnterEnclave = True
                    if beginEnterEnclave:
                        if "trace_eenter" in line1:
                            trcEntId = common.getinsaddr(lines[i+1],":")
                        
                # this extracts the trace_eexit ID
                if not trcExtId:
                    if 'enter_enclave' in line1:
                        beginEnterEnclave = True
                    if beginEnterEnclave:
                        if "trace_eexit" in line1:
                            trcExtId = common.getinsaddr(lines[i+1],":")

        eenter = "N[0x{:x}, 0x{:x}]".format(trcEntId, 0xfffffffd) # -3
        excGen = "J[0x{:x}, 0x{:x}]".format(excGenId, 0)
        eexit = "T[0x{:x}, 0x{:x}]".format(trcExtId, 0)

        tt = [eenter, excGen, eexit]

        self.traces.add(" -> ".join(tt))

    def start_analysis(self):

        gEDMMSupport = self.project.loader.main_object.get_symbol('EDMM_supported')
        self.init_state.memory.store(gEDMMSupport.linked_addr, self.init_state.solver.BVV(0x0, 8))

        # don't know if we need this
        gGlobalData = self.project.loader.main_object.get_symbol('g_global_data')
        self.init_state.memory.store(gGlobalData.linked_addr, self.init_state.solver.BVS("gGlobalData", 64*8))
        # self.init_state.memory.store(gGlobalData.linked_addr, 0x2)


        gEnclaveState = self.project.loader.main_object.get_symbol('g_enclave_state')
        self.init_state.memory.store(gEnclaveState.linked_addr, self.init_state.solver.BVV(0x2, 8))

        gIsFirstEcall = self.project.loader.main_object.get_symbol('_ZL16g_is_first_ecall')
        self.init_state.memory.store(gIsFirstEcall.linked_addr, 0x0)

        gFirstNode = self.project.loader.main_object.get_symbol('_ZL12g_first_node')

        ## TODO: for future FLAVIO, think something about setting global variables in .bss as unconstratin 
        ## simbols, or else you can't explore all the paths
        # gNodeInitialized = self.project.loader.main_object.get_symbol('g_sgxsd_enclave_node_initialized')
        # self.init_state.memory.store(gNodeInitialized.linked_addr, self.init_state.solver.BVS('gNodeInitialized', 8))

        self.init_state.inspect.b('instruction', when=BP_BEFORE, action=checkInstr0, instruction=0x0)

        # self.init_state.globals["shadowstack"] = module.MyShadowStack()

        ## CUSTOM SETTING

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


        # makeregistersymbolicEcall(self.secfun)

        stack_base_addr = 0xFFFFFFFFFFFFFFFF

        self.init_state.regs.gs = 0x7f000000
        self.init_state.mem[self.init_state.regs.gs].uint64_t = 0x7f000000

        # same stack than before?
        self.init_state.regs.rbp = stack_base_addr

        # THREAD DATA
        # stack_base_addr
        self.init_state.mem[self.init_state.regs.gs + 0x10].uint64_t = stack_base_addr

        # exception_flag = 1
        self.init_state.mem[self.init_state.regs.gs + 0x60].uint64_t = 1

        # I get a simulation manager
        simgr = self.project.factory.simgr(self.init_state)
        self.simgr = simgr

        print("[INTERNAL_HANDLE_EXCEPTION] Starting exploration...")
        simgr.run()
        # simgr.explore(find=[0x454a])
        print("[INTERNAL_HANDLE_EXCEPTION] Done")

        # from IPython import embed; embed();

        # if not simgr.found:
        #     print(" => NO FOUND")
        # else:
        #     print(simgr.one_found)
        #     f = simgr.one_found
        #     from IPython import embed; embed()

        print("[TRTS_HANDLE_EXCEPTION] Starting exploration...")
        self.analyze_trts_handle_exception()
        print("[TRTS_HANDLE_EXCEPTION] Done")

        self.extractTrace(simgr.deadended)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--enclave', '-e', required=True, type=str, help='The enclave to analyze')
    parser.add_argument('--enclave_entry', '-n', required=False, type=str, help='Enclave entry point', default='internal_handle_exception')
    parser.add_argument('--asm_folder', '-f', required=False, type=str, help='Folder where keeping asm fies', default='asms')
    parser.add_argument('--dump', '-d', required=False, type=str, help='Model', default='model.txt')
    parser.add_argument('--trace_bbl', '-b', action='store_true', required=False, help='Dump basic-blocks')
    parser.add_argument('--errored', '-r', required=False, type=str, help='Errored status', default=None)
    parser.add_argument('--custom_module', '-c', required=False, type=str, help='Module with customization for enclaves', default=None)
    parser.add_argument('--loops', '-l', required=False, type=str, help='Loop info file', default=None)

    args = parser.parse_args()

    fun_to_start = args.enclave_entry
    enclave_bin = args.enclave
    asm_folder = args.asm_folder
    dump_model = args.dump
    trace_bbl = args.trace_bbl
    errored = args.errored
    custom_module = args.custom_module
    loop_info = args.loops

    a = TracedException(enclave_bin, fun_to_start, None, asm_folder, trace_bbl, custom_module, dump_model, loop_info)

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
