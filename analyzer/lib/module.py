from angr import *
import claripy
import copy
import hashlib
from pathlib import Path

import shadowstack
import tracer
import loopsmanager

def passf(state):
    pass

def passf_rep(state):
    # rcx == 0x0 => skip the rep
    state.rcx = 0x0

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

def loop_handling(state):
    state = state.copy()
    addr = state.addr
    lm = state.my_loopsmanager
    ss = state.my_shadowstack

    ss_ctx = hashlib.sha256(str(ss).encode()).hexdigest()

    # # TEST FOR STRAGE STEP
    # try:
    #     state.project.unhook(addr)
    #     state.step()
    #     from IPython import embed; embed()
    # except:
    #     print(" ***** => ERROR! STATE AT 0x{:x} RAISES EXCEPTION <= *****".format(addr))
    #     return
    # finally:
    #     # ANYWAY, I HAVE TO RE-HOOK
    #     print(" ***** => RE-HOOK @ 0x{:x} <= *****".format(addr))
    #     state.project.hook(addr, loop_handling, length=0)

    # from IPython import embed; embed()

    if not state.solver.satisfiable():
        # state.regs.rip = lm.way_out[addr]
        # # from IPython import embed; embed()
        # state.history.jumpkind = 'Ijk_Boring'
        # state.scratch.guard = state.solver.true
        # state.solver.simplify()
        print(" ***** LOOP @ 0x{:x}: UNSAT ***** ".format(addr))

        with open('loop_log.txt','a') as log:
            log.write("0x{:x} UNSAT\n".format(addr))

        # state.regs.rip = lm.iteration[addr]
        state.history.jumpkind = 'Ijk_Exit'
        state.scratch.guard = state.solver.true
        state.solver.simplify()

        return [state]

    print(" ***** LOOP @ 0x{:x}: LEFTOVER [{}] ***** ".format(addr, lm.getLeftover(ss_ctx, addr)))
    if lm.unroll(ss_ctx, addr):
        state.regs.rip = lm.way_out[addr]
        # from IPython import embed; embed()
        state.history.jumpkind = 'Ijk_Boring'
        state.scratch.guard = state.solver.true
        state.solver.simplify()

        with open('loop_log.txt','a') as log:
            log.write("0x{:x} 0x{:x} SKIPPED\n".format(addr, lm.way_out[addr]))

        print(" ***** LOOP @ 0x{:x}: SKIPPED ***** ".format(addr))
        return [state]
    else:
        state.regs.rip = lm.iteration[addr]
        state.history.jumpkind = 'Ijk_Boring'
        state.scratch.guard = state.solver.true
        state.solver.simplify()

        with open('loop_log.txt','a') as log:
            log.write("0x{:x} 0x{:x} ITERACTION\n".format(addr, lm.iteration[addr]))        

        print(" ***** LOOP @ 0x{:x}: ITERACTION ***** ".format(addr))
        return [state]

def myRestoreStack(state):
    # global a

    # if "saved_stack" not in state.globals:
    #     return

    # saved_stack = state.globals["saved_stack"]
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
    # bottom_stack = state_current.solver.eval(state_current.regs.rbp)
    # addr = stack_base_addr
    # while addr > bottom_stack:
    #     sym_v = state_origin.memory.load(addr, 8, endness=endness)
    #     v = state_origin.solver.eval(sym_v)

    #     if v == 0x2d635:
    #         print(" => I FOUND THE VALUE I WAS LOOKING FOR!")
    #         from IPython import embed; embed()

    #     state_current.memory.store(addr, v, 8, endness=endness)
    #     addr = addr - 0x8

    # if saved_stack:
    #     for a, v in saved_stack:
    #         state_current.memory.store(a, v, 8, endness=endness)

    state_current.my_shadowstack.clear()
    ss_frames = state_origin.my_shadowstack.frames
    for f in ss_frames[:-1]:
        state_current.my_shadowstack.call(f.callsite_addr, f.function_addr, f.stack_addr, f.return_addr)

    top_stack = state_current.solver.eval(state_current.regs.rbp)
    
    bp = None
    ret_rip = None
    addr = top_stack
    nRestored = 0
    while bp != stack_base_addr and addr <= stack_base_addr:
        sym_bp = state_origin.memory.load(addr, 8, endness=endness)
        bp = state_origin.solver.eval(sym_bp)
        sym_rip = state_origin.memory.load(addr + 0x8, 8, endness=endness)
        ret_rip = state_origin.solver.eval(sym_rip)
    
        if not bp or not ret_rip:
            break
    
        # print("[0x{:x}] -> 0x{:x}".format(addr, bp))
        # print("[0x{:x}] -> 0x{:x}".format(addr + 0x8, ret_rip))
        # print("-" * 30)
    
        # if ret_rip == 0x2d635:
        #     print(" => I FOUND THE VALUE I WAS LOOKING FOR!")
        #     from IPython import embed; embed()
    
        state_current.memory.store(addr, bp, 8, endness=endness)
        state_current.memory.store(addr + 0x8, ret_rip, 8, endness=endness)
    
        addr = bp
        nRestored = nRestored + 1

    # while v != stack_base_addr and addr <= stack_base_addr:
    #     sym_v = state_origin.memory.load(addr, 8, endness=endness)
    #     v = state_origin.solver.eval(sym_v)
    #     print("[0x{:x}] -> 0x{:x}".format(addr, v))
    
    #     if v == 0x2d635:
    #         print(" => I FOUND THE VALUE I WAS LOOKING FOR!")
    #         from IPython import embed; embed()
    
    #     state_current.memory.store(addr, v, 8, endness=endness)
    #     addr = addr + 0x8
    #     nRestored = nRestored + 1

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

def myDoOcall(state):
    return
    x = state
    top_stack = x.solver.eval(x.regs.rbp)

    # TODO: stack base addr as a parameter?
    stack_base_addr = 0xFFFFFFFFFFFFFFFF

    saved_stack = []

    endness = 'Iend_LE'

    bp = None
    ret_rip = None
    addr = top_stack
    nRestored = 0
    while bp != stack_base_addr and addr <= stack_base_addr:
        sym_bp = x.memory.load(addr, 8, endness=endness)
        bp = x.solver.eval(sym_bp)
        sym_rip = x.memory.load(addr + 0x8, 8, endness=endness)
        ret_rip = x.solver.eval(sym_rip)

        if not bp or not ret_rip:
            break

        saved_stack.append((addr, bp))
        saved_stack.append((addr + 0x8, ret_rip))

        addr = bp
        nRestored = nRestored + 1

    x.globals["saved_stack"] = saved_stack

def gettargetaddr(state, iv):

    targets = iv.constant_jump_targets

    # normal call, single static destination (major of the cases hopefully)
    if len(targets) == 1:
        function_addr = targets.pop()
    # guessing the de-rerefenced pointer
    elif iv.next.tag == 'Iex_RdTmp':
        tmp = iv.next.tmp

        w_tmp = None
        for s in iv.statements: 
            if s.tag == 'Ist_WrTmp' and s.tmp == tmp: 
                w_tmp = s.data
                break

        if not w_tmp:
            print(" **** ERROR, w_tmp NOT FOUND *****")
            from IPython import embed; embed()

        # indirect branch from memory location
        if w_tmp.tag == 'Iex_Load':
            dst = w_tmp.constants[0].value
            s_function_addr = state.memory.load(dst, 8, endness=archinfo.Endness.LE)
            function_addr = state.solver.eval(s_function_addr)
        # indirect branch from register
        elif w_tmp.tag == 'Iex_Get':
            reg_name = iv.arch.translate_register_name(w_tmp.offset, w_tmp.result_size(iv.tyenv) // 8)
            try:
                s_function_addr = getattr(state.regs, reg_name)
                function_addr = state.solver.eval(s_function_addr)
            except KeyError as e:
                print(" **** KEYERROR: {}".format(str(e)))
                from IPython import embed; embed()
        else:
            print(" **** ERROR, cannot handle {} with tag {} *****".format(str(w_tmp), str(w_tmp.tag)))
            from IPython import embed; embed()
    else:
        print(" **** ERROR, CAN'T INFER THE TARGETS! *****")
        from IPython import embed; embed()

    if not function_addr:
        print(" **** NOT ABLE TO GET THE function_addr *****")
        from IPython import embed; embed()

    return function_addr

def push_shadowstack(state):
    callsite_addr = state.addr

    s_sp = state.regs.rsp
    stack_addr = state.solver.eval(s_sp)

    iv = state.project.factory.block(callsite_addr).vex

    function_addr = gettargetaddr(state, iv)
    
    return_addr = callsite_addr + iv.size

    state.my_shadowstack.call(callsite_addr, function_addr, stack_addr, return_addr)
    
def pop_shadowstack(state):
    # from IPython import embed; embed()
    # unc_ret_64 = state.solver.BVS("unc_ret_64", 64)
    # state.regs.rax = unc_ret_64
    # unc_ret_32 = state.solver.BVS("unc_ret_32", 32)
    # state.regs.eax = unc_ret_32

    ss = state.my_shadowstack

    # if I need, I handle loops
    if hasattr(state, 'my_loopsmanager'):
        lm = state.my_loopsmanager
        ss_ctx = hashlib.sha256(str(ss).encode()).hexdigest()
        if lm.removeContext(ss_ctx):
            print(" ***** CONTEXT REMOVED *****")

    state.regs.rip = ss.t.return_addr - 1
    # state.regs.rip = ss.t.return_addr
    state.regs.rsp = ss.t.stack_addr
    ss.ret()

    # state.history.jumpkind = 'Ijk_Boring'
    # state.scratch.guard = state.solver.true

    # return [state]

class MyStubFunc(SimProcedure):
    def run(self, *args, **kwargs):
        
        self.state.my_shadowstack.ret()

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyEncluSim(SimProcedure):
    def run(self, *args, **kwargs):

        # rax == 0x4 => EEXIT (ERET or OCALL)
        if self.state.solver.eval(self.state.regs.rax) == 0x4:
            # this is the ENCLU belonging to do_oret()
            if self.state.addr == self.state.globals["ocall_enclu_addr"]:
                # saved_stack = self.state.globals["saved_stack"]
                # shadow_stack = self.state.my_shadowstack.frames

                # if abs(len(saved_stack) - len(shadow_stack) != 0:
                #     print(" **** => ENCLU: OCALL - error saved stack <= ****")
                # else:
                print(" **** => ENCLU: OCALL - save status <= ****")
                # from IPython import embed; embed()
                self.state.globals['pendingstate'].append(self.state.copy())
            else:
                print(" **** => ENCLU: NO RETURN <= ****")
                tc = self.state.globals["tracer_collector"]
                mt = self.state.my_tracer
                tc.dump(mt)
                mt.setActions([])
            self.exit(0)
        else:
            print(" **** => ENCLU: CONTINUE (0x{:x}) <= ****".format(self.state.addr))
            s_rip = self.state.regs.rip
            rip = self.state.solver.eval(s_rip)
            self.jump(rip+3)
            # from IPython import embed; embed()

class MyAbort(SimProcedure):
    def run(self, *args, **kwargs):
        print(" **** => ABORT AND EXIT <= ****")
        tc = self.state.globals["tracer_collector"]
        mt = self.state.my_tracer
        tc.dump(mt)
        mt.setActions([])
        self.exit(0)

class MyTracerFakeHook(SimProcedure):
    def run(self, *args, **kwargs):
        arg1 = hex(self.state.solver.eval(self.state.addr))

        self.state.my_tracer.add("F", arg1)

        
        self.state.my_shadowstack.ret()

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

        self.state.my_tracer.add("F", arg1, 0)

        
        self.state.my_shadowstack.ret()

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

        self.state.my_shadowstack.ret()

        self.state.my_tracer.add("B", src, dst)

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyContinueExecution(SimProcedure):
     def run(self, *args, **kwargs):
        # CONTINUE EXECUTION DOESN'T RETURN, JUST STOP THE EXPLORATION
        tc = self.state.globals["tracer_collector"]
        mt = self.state.my_tracer
        tc.dump(mt)
        mt.setActions([])
        self.exit(0)

class MyExcConHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)

        self.state.my_tracer.add("K", src, 0)
        
        self.state.my_shadowstack.ret()

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyExcGenHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)

        self.state.my_tracer.add("J", src, 0)

        self.state.my_shadowstack.ret()

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

        self.state.my_tracer.add("G", src, 0)

        self.state.my_shadowstack.ret()

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

        self.state.my_tracer.add("D", src, 0)
        
        self.state.my_shadowstack.ret()

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyEExitHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)

        self.state.my_tracer.add("T", src, 0)

        self.state.my_shadowstack.ret()

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyEresumeHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)

        self.state.my_tracer.add("L", src, 0)

        self.state.my_shadowstack.ret()

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

        self.state.my_tracer.add("N", src, dst)
        
        self.state.my_shadowstack.ret()

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

        self.state.my_tracer.add("C", src, 0)
        
        self.state.my_shadowstack.ret()

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

        # hex(f.callstack.current_return_target)
        # if src == "0x2c58":
        #     from IPython import embed; embed()
        if dst == "0x0":
            dst = hex(self.state.callstack[1].current_return_target)

        # if self.state.solver.eval(self.state.regs.rdi) == 0x25e9ffffff500d:
        #     from IPython import embed; embed()

        self.state.my_tracer.add("E", src, dst)

        self.state.my_shadowstack.ret()

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyTracerAssigmentHook(SimProcedure):
    def run(self, *args, **kwargs):
        src = hex(self.state.callstack.current_return_target)
        val = hex(self.state.solver.eval(self.state.regs.rdi))

        self.state.my_tracer.add("A", src, val)
        
        self.state.my_shadowstack.ret()

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

        self.state.my_tracer.add("P", src, vtbl)
        
        self.state.my_shadowstack.ret()

        # this doesn't change because I don't want to modify the contraints
        return_val = kwargs.pop('return_val', None)
        if return_val is None:
            o = self.state.solver.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o

class MyTrueFun(SimProcedure):
    def run(self, argc, argv):
        
        self.state.my_shadowstack.ret()
        return 1

class MyFalseFun(SimProcedure):
    def run(self, argc, argv):
        
        self.state.my_shadowstack.ret()
        return 0
