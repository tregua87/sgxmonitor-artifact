from angr import *
import copy
from pathlib import Path

class Analysis(object):
    def __init__(self, binary, fun_to_start, secfunc, asm_folder, trace_bbl):
        self.project = None
        self.enclave_bin = binary
        self.fun_to_start = fun_to_start
        self.secfun = secfunc
        self.trace_bbl = trace_bbl

        self.ocall_enclu_addr = None

        self.asm_folder = asm_folder
        Path(asm_folder).mkdir(parents=True, exist_ok=True)

        self.enclave_asm = None
        self.enclave_entry = None
        self.init_state = None
        self.simgr = None
        self.insnaddrs = []

        # things to skip
        self.xsavelist = []
        self.xsaveclist = []
        self.xsaveslist = []
        self.xsave64list = []
        self.xsavec64list = []
        self.xsaves64list = []
        self.fxsavelist = []
        self.fxsave64list = []
        self.xrstorlist = []
        self.xrstorslist = []
        self.xrstor64list = []
        self.xrstors64list = []
        self.fxrstorlist = []
        self.fxrstor64list = []

        self.movapslist = []
        self.movapslengthlist = []

        self.repstoslist = []
        self.rdrandlist = []
        self.wrfsbaselist = []
        self.strlenflist = []
        self.memcpyflist = []

        self.enclulist = []
        self.enclaveentry = None
        self.enclaexit = []

        self.pendingstate = []
        self.traces = set()

def passf(state):
    pass

def enclu_sim(state):
    # from IPython import embed; embed()
    pass

# just exit
class MyCloseExploration(SimProcedure):
    def run(self, *args, **kwargs):
        self.exit(0)


def firstcallf(state):
	state.regs.eax = 0

def my_sty_func(state):
    print("=> calling memset_s")
    state.regs.rax = 0

def myFix(state):
    # from IPython import embed; embed()
    if state.solver.constraints and "fakecanary" in str(state.solver.constraints[-1]):
        # from IPython import embed; embed()
        state.solver.constraints.pop()
        canary = state.solver.Unconstrained("fakecanary", 64)
        state.mem[state.regs.fs+0x28].uint64_t = canary

def myRestoreStack(state):
    # global a

    stack_base_addr = state.globals["stack_base_addr"]
    state_origin = state.globals["state_origin"]
    state_current = state
    endness = 'Iend_LE'

    print(" **** => STACK RESTORING: <= ****")
    print(" **** => RIP: 0x{:x}".format(state.addr)) #457f ??
    print(" **** => stack_base_addr: 0x{:x}".format(stack_base_addr))
    print(" **** => state_origin: 0x{:x}".format(state_origin.addr))
    print(" **** => endness: {}".format(endness))
    # from IPython import embed; embed()

    # state_current.regs.rax = 0x0

    ####################################################################
    # NOTE: this snipped moves a callstack from a state to another but #
    # it seem affecting nothing but the merge function result. If the  #
    # two states have same callstack, it is possible to make a         #
    # successful merge                                                 #
    ####################################################################
    skipfirst = True
    for cs in reversed(state_origin.callstack):
        if skipfirst: # the first is already in the new state
            skipfirst = False
            continue
        func_addr = cs.func_addr
        call_site_addr = cs.call_site_addr
        stack_ptr = cs.stack_ptr
        ret_addr = cs.ret_addr
        state_current.callstack.call(call_site_addr, func_addr, ret_addr, stack_ptr)

    # NOTE: just merge
    # new_state = state_current.merge(state_origin)

    #######################################################################
    # NOTE: copy stack from the origin_state to the current state.        #
    # I need this because the state_currest has to know how to move       #
    # around the called functions. Maybe there is a better way to do this #
    # PS: to stay on the safe side, always copy concrete values from the  #
    # memory or the solver will generate kinda random values              #
    #######################################################################
    # bottom_stack_o = state_origin.solver.eval(state_origin.regs.rsp)
    bottom_stack = state_current.solver.eval(state_current.regs.rsp)
    addr = stack_base_addr
    while addr > bottom_stack:
        sym_v = state_origin.memory.load(addr, 8, endness=endness)
        v = state_origin.solver.eval(sym_v)

        if v == 0x2d635:
            print(" => I FOUND THE VALUE I WAS LOOKING FOR!")
            from IPython import embed; embed()

        # # TODO: understand why this address is not reportred correctly or
        # # find a way to infer it from the asm
        # if addr == 0xffffffffffffff7f:
        #     v = 0x2d635

        state_current.memory.store(addr, v, 8, endness=endness)
        # state_current.mem[addr].uint64_t = v
        addr = addr - 0x8

    # sp = state_origin.solver.eval(state_origin.regs.rsp)
    # state_current.regs.rsp = sp

    fs = state_origin.solver.eval(state_origin.regs.fs)

    state_current.regs.fs = fs

    # NOTE: restore the stack canary too? XD
    # canary = state_current.solver.BVS("fakecanary", 64)
    canary_addr = state_current.solver.eval(fs + 0x28)
    canary = state_current.solver.Unconstrained("fakecanary", 64)
    state_current.mem[fs+0x28].uint64_t = canary
    # NOTE: clear canary constraints whenever I use it
    state_current.inspect.b('constraints', when=BP_AFTER, action=myFix)

    # print(" [WITHIN THE HOOK]")
    # from IPython import embed; embed()

class MyEncluSim(SimProcedure):
    def run(self, *args, **kwargs):

        # rax == 0x4 => EEXIT (ERET or OCALL)
        if self.state.solver.eval(self.state.regs.rax) == 0x4:
            # this is the ENCLU belonging to do_oret()
            if self.state.addr == self.state.globals["ocall_enclu_addr"]:
                print(" **** => ENCLU: OCALL - save status <= ****")
                self.state.globals['pendingstate'].append(self.state.copy())
            else:
                print(" **** => ENCLU: NO RETURN <= ****")
            # print(" ===> {:x}".format(self.state.addr))
            self.exit(0)
        else:
            print(" **** => ENCLU: CONTINUE (0x{:x}) <= ****".format(self.state.addr))

        # from IPython import embed; embed()

class MyAbort(SimProcedure):
    def run(self, *args, **kwargs):
        print(" **** => ABORT AND EXIT <= ****")
        self.exit(0)

class MyTracerFakeHook(SimProcedure):
    def run(self, *args, **kwargs):
        arg1 = hex(self.state.solver.eval(self.state.addr))

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("F ({})".format(arg1))

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyTracerFrameHook(SimProcedure):
    def run(self, *args, **kwargs):
        arg1 = hex(self.state.solver.eval(self.state.regs.rdi))

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("F[{}, 0]".format(arg1))

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyTracerBranchHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)
        dst = hex(self.state.solver.eval(self.state.regs.rdi))

        dstMin = hex(self.state.solver.min(self.state.regs.rdi))
        dstMax = hex(self.state.solver.max(self.state.regs.rdi))

        if dstMin != dstMax:
            from IPython import embed; embed()

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("B[{}, {}]".format(src,dst))
        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyCtxGenHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)
        # dst = hex(self.state.solver.eval(self.state.regs.rdi))

        # if self.state.solver.eval(self.state.regs.rdi) == 0x25e9ffffff500d:
        #     from IPython import embed; embed()

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("G[{}, {}]".format(src,0))
        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyEExitOcallHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)
        # dst = hex(self.state.solver.eval(self.state.regs.rdi))

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("D[{}, 0]".format(src))
        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyEExitHook(SimProcedure):
    def run(self, *args, **kwargs):
        # print(" > THIS IS MyEExitHook")
        # from IPython import embed; embed()
        src = hex(self.state.callstack.current_return_target)
        # dst = hex(self.state.solver.eval(self.state.regs.rdi))

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("T[{}, 0]".format(src))
        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyEEnterHook(SimProcedure):
    def run(self, *args, **kwargs):
        # print(" > THIS IS MyEEnterHook")
        # from IPython import embed; embed()

        src = hex(self.state.callstack.current_return_target)
        dst = hex(self.state.solver.eval(self.state.regs.rdi))

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("N[{}, {}]".format(src,dst))
        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyCtxConHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("C[{}, 0]".format(src))
        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyTracerEdgeHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)
        dst = hex(self.state.solver.eval(self.state.regs.rdi))

        # if self.state.solver.eval(self.state.regs.rdi) == 0x25e9ffffff500d:
        #     from IPython import embed; embed()

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("E[{}, {}]".format(src,dst))

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyTracerAssigmentHook(SimProcedure):
    def run(self, *args, **kwargs):
        add = hex(self.state.solver.eval(self.state.regs.rsi))
        val = hex(self.state.solver.eval(self.state.regs.rdi))

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("A[{}, {}]".format(val,add))

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyTracerPtrHook(SimProcedure):
    def run(self, *args, **kwargs):
        obj = hex(self.state.solver.eval(self.state.regs.rsi))
        vtbl = hex(self.state.solver.eval(self.state.regs.rdi))

        t = self.state.globals["trace"]
        self.state.globals["trace"] = copy.deepcopy(t)
        self.state.globals["trace"].append("P[{},{}]".format(obj,vtbl))

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyTrueFun(SimProcedure):
    def run(self, argc, argv):
        return 1

class MyFalseFun(SimProcedure):
    def run(self, argc, argv):
        return 0
