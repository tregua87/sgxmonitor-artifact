from angr import *
import claripy
import copy
from pathlib import Path
import ntpath, os, hashlib
from functools import partial
import pyvex

# project imports
import module
import shadowstack
import tracer
import tracer_collector
import loopsmanager

class Analysis(object):
    def __init__(self, binary, fun_to_start, secfunc, asm_folder, trace_bbl, custom_module, dump_model, loop_info):
        self.project = None
        self.enclave_bin = binary
        self.fun_to_start = fun_to_start
        self.secfun = secfunc
        self.trace_bbl = trace_bbl
        self.errored = set()

        self.loop_file = loop_info
        self.addr_loops = {}

        self.custom = None
        if custom_module is not None:
            mod = __import__('customization', fromlist=[custom_module])
            klass = getattr(mod, custom_module)
            self.custom = klass(self)

        self.fcts = []
        if self.custom is not None:
            self.fcts = self.custom.getFcts()

        self.dump_model = dump_model
        self.tracer_collector = tracer_collector.TracerCollector(self.dump_model)

        self.ocall_enclu_addr = None
        self.do_ocall = None

        self.asm_folder = asm_folder
        Path(asm_folder).mkdir(parents=True, exist_ok=True)

        self.enclave_asm = None
        self.enclave_entry = None
        self.init_state = None
        self.simgr = None
        # self.insnaddrs = []

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
        self.vmovapslist = []
        self.vmovapslengthlist = []

        self.movapslist = []
        self.movapslengthlist = []

        self.repmovslist = []
        self.repmovslengthlist = []

        self.unsuppret = []
        self.retinst = []
        self.retinstlen = []
        self.callinst = []
        self.noinlinewrapper = None

        self.repstoslist = []
        self.rdrandlist = []
        self.wrfsbaselist = []

        self.enclulist = []
        self.enclaveentry = None
        self.enclaexit = []

        self.registeredhandler = []

        self.pendingstate = []
        self.traces = set()

    def load_binary(self):
        ## NOTE:
        # auto_load_libs = Flase -> I don't want libc, in SGX everything is statically linked
        # base_addr = 0x0 -> I want relative address, that's easier
        self.project = Project(self.enclave_bin, auto_load_libs=False, main_opts = {'base_addr': 0x0})
        self.enclave_entry = self.project.loader.main_object.get_symbol(self.fun_to_start)
        self.init_state = self.project.factory.call_state(self.enclave_entry.linked_addr)
        self.init_state.options.add(options.LAZY_SOLVES)
        # self.init_state = self.project.factory.call_state(self.enclave_entry.linked_addr, add_options={options.CONSTRAINT_TRACKING_IN_SOLVER})
        self.init_state.solver._solver.timeout=60000

        self.init_state.globals["pendingstate"] = self.pendingstate
        self.init_state.globals["tracer_collector"] = self.tracer_collector

        self.init_state.register_plugin('my_shadowstack', shadowstack.MyShadowStack())
        self.init_state.register_plugin('my_tracer', tracer.MyTracer())
        self.init_state.register_plugin('my_loopsmanager', loopsmanager.MyLoopsManager(0))

    def disassemble(self):
        asm_name = "{}.asm".format(ntpath.basename(self.enclave_bin))
        asm_file = os.sep.join([self.asm_folder, asm_name])

        try:
            if os.path.exists(asm_file):
                os.remove(asm_file)
            cmd = "objdump -M intel -d {} > {}".format(self.enclave_bin, asm_file)
            if os.system(cmd):
                os.remove(asm_file)
                raise Exception("didn't work!")
        except:
            print("Impossible to create {} from {}".format(asm_file, asm_file))
            exit(-1)

        self.enclave_asm = asm_file

    def findenclu(self):
        with open(self.enclave_asm,'r') as f1:
            for line1 in f1:
                if "enclu" in line1:
                    addr = getinsaddr(line1, ":")
                    self.enclulist.append(addr)
                    #print hex(addr)

    def findenclaveentry(self):
        with open(self.enclave_asm,'r') as f1:
            for line1 in f1:
                if "<enclave_entry>:" in line1:
                    self.enclaveentry = getinsaddr(line1, "<")
                    break

    def findenclaveexit(self):
        start_enclave_entry = False
        with open(self.enclave_asm,'r') as f1:
            for line1 in f1:
                if not start_enclave_entry and "<enter_enclave>:" in line1:
                    start_enclave_entry = True
                if start_enclave_entry and "ret " in line1:
                    self.enclaexit.append(getinsaddr(line1, ":"))
                if start_enclave_entry and not line1.strip():
                    break

    def findaddresses(self):
        self.findenclu()
        self.findenclaveentry()
        self.findenclaveexit()
        self.findretandcall()
        # findabortfunction() # no need it

    def findunsupportedinstructions(self):
        with open(self.enclave_asm,'r') as f1:
            lines = f1.readlines()
            for i, line1 in enumerate(lines):
                if "\txsave " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xsavelist.append(addr)
                if "\txsavec " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xsaveclist.append(addr)
                if "\txsaves " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xsaveslist.append(addr)
                if "\txsave64 " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xsave64list.append(addr)
                if "\txsavec64 " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xsavec64list.append(addr)
                if "\txsaves64 " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xsaves64list.append(addr)
                if "\tfxsave " in line1:
                    addr = getinsaddr(line1, ":")
                    self.fxsavelist.append(addr)
                if "\tfxsave64 " in line1:
                    addr = getinsaddr(line1, ":")
                    self.fxsave64list.append(addr)
                if "\txrstor " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xrstorlist.append(addr)
                if "\txrstors " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xrstorslist.append(addr)
                if "\txrstor64 " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xrstor64list.append(addr)
                if "\txrstors64 " in line1:
                    addr = getinsaddr(line1, ":")
                    self.xrstors64list.append(addr)
                if "\tfxrstor " in line1:
                    addr = getinsaddr(line1, ":")
                    self.fxrstorlist.append(addr)
                if "\tfxrstor64 " in line1:
                    addr = getinsaddr(line1, ":")
                    self.fxrstor64list.append(addr)
                if "\tmovaps " in line1:
                    addr = getinsaddr(line1, ":")
                    leng = getlenaddr(line1, ":", "m")
                    self.movapslist.append(addr)
                    self.movapslengthlist.append(leng)

                #
                # TBD: rep, stos
                #
                if "\trep stos " in line1:
                    addr = getinsaddr(line1, ":")
                    self.repstoslist.append(addr)

                if "\trep movs" in line1:
                    addr = getinsaddr(line1, ":")
                    leng = getlenaddr(line1, ":", "r")
                    self.repmovslist.append(addr)
                    self.repmovslengthlist.append(leng)

                if "\trdrand " in line1 and not "<" in line1:
                    addr = getinsaddr(line1, ":")
                    self.rdrandlist.append(addr)

                if "\twrfsbase " in line1 and not "<" in line1:
                    addr = getinsaddr(line1, ":")
                    self.wrfsbaselist.append(addr)

                instToAvoid = ["\tvmovaps ", "\tvmovdqa ", "\tvaeskeygenassist ", 
                                "\tvaesenc ", "\tvaesenclast ", "\tvxorps ", "\tvpsubq ",
                                "\tvpaddq ", "\tvpclmulhqhqdq ", "\tvpclmullqlqdq ",
                                "\tvpermilps ", "\tvpshufd ", "\tvpslldq ", "\tvmovq ",
                                "\tvpxor ", "\tvmovdqu ", "\tvmovups "]

                if any([i in line1 for i in instToAvoid]) and not "<" in line1:
                    addr = getinsaddr(line1, ":")
                    leng = getlenaddr(line1, ":", "v")

                    # if any([ addr >= bf and addr <= ef for bf, ef in self.fcts ]):

                        #   b65b:	c5 fc 29 84 24 40 01 	vmovaps YMMWORD PTR [rsp+0x140],ymm0
                        #   b662:	00 00 
                        #   3eedf:	c2 80 00             	
                        
                    if leng == 7 and i < len(lines):
                        nextLineA = lines[i+1].strip().split('\t')
                        if len(nextLineA) == 2:
                            temp = nextLineA[1].strip()
                            leng = leng + len(temp.split())

                    self.vmovapslist.append(addr)
                    self.vmovapslengthlist.append(leng)

        # exit(0)

    def handleaddresses(self):
        for addr in self.xsavelist:
            self.project.hook(addr, module.passf, length=3)
        for addr in self.xsaveclist:
            self.project.hook(addr, module.passf, length=3)
        for addr in self.xsaveslist:
            self.project.hook(addr, module.passf, length=3)
        for addr in self.xsave64list:
            self.project.hook(addr, module.passf, length=4)
        for addr in self.xsavec64list:
            self.project.hook(addr, module.passf, length=4)
        for addr in self.xsaves64list:
            self.project.hook(addr, module.passf, length=4)
        # if self.picflag == 1:
        #     for addr in self.fxsavelist:
        #     	self.project.hook(addr, module.passf, length=3)
        # else:
        for addr in self.fxsavelist:
            self.project.hook(addr, module.passf, length=4)

        for addr in self.fxsave64list:
            self.project.hook(addr, module.passf, length=4)
        for addr in self.xrstorlist:
            self.project.hook(addr, module.passf, length=4)
        for addr in self.xrstorslist:
            self.project.hook(addr, module.passf, length=4)
        for addr in self.xrstor64list:
            self.project.hook(addr, module.passf, length=4)
        for addr in self.xrstors64list:
            self.project.hook(addr, module.passf, length=4)
        for addr in self.fxrstorlist:
            self.project.hook(addr, module.passf, length=4)
        for addr in self.fxrstor64list:
            self.project.hook(addr, module.passf, length=4)
        for addr, leng in zip(self.movapslist, self.movapslengthlist):
            self.project.hook(addr, module.passf, length=leng)
        for addr in self.repstoslist:
            self.project.hook(addr, module.passf, length=2)
        for addr, leng in zip(self.vmovapslist, self.vmovapslengthlist):
            self.project.hook(addr, module.passf, length=leng)    

        # TBD: rdrand
        for addr in self.rdrandlist:
            self.project.hook(addr, module.passf, length=3)

        for addr in self.wrfsbaselist:
            self.project.hook(addr, module.passf, length=5)

        for addr, len in zip(self.repmovslist, self.repmovslengthlist):
            self.project.hook(addr, module.passf_rep, length=len)

        for addr, leng in zip(self.retinst, self.retinstlen):
            self.project.hook(addr, module.pop_shadowstack, length=leng)

        for addr in self.callinst:
            self.project.hook(addr, module.push_shadowstack, length=0)

        # THIS IS AN ATTEMPT OF HANDLING "random_stack_noinline_wrapper"
        # HOWEVER, PROPERLY HANDLING IT IS TOO DIFFICULT AND THE REALLY ADVANTAGE GAINED IS NOT WORTHY.
        # THE POINT IS THAT THE CALLBACK PLUGIN OF ANGR DOES NOT SEE THE CORRECT FUNCTION INVOKED BECAUSE 
        # THIS WRAPPER HIDES IT. ANYWAY, MY TRICK SHOULD STILL WORK
        # if self.noinlinewrapper:
        #     addr = self.noinlinewrapper
        #     self.project.hook(addr, module.fix_callstack, length=0)    

        # stub_func = SIM_PROCEDURES['stubs']['ReturnUnconstrained']
        stub_func = module.MyStubFunc

        # first instruction of trts_ecall
        # self.project.hook(0x1920, module.firstcallf, length=7)

        # toHook = self.project.loader.main_object.get_symbol('sgx_ocalloc')
        # self.project.hook(toHook.linked_addr, stub_func)
        # print("hook it!")
        # exit()

        self.project.hook_symbol("sgx_register_exception_handler", stub_func())

        # self.project.hook_symbol("sgx_is_within_enclave", module.MyTrueFun())
        self.project.hook_symbol("sgx_is_within_enclave", stub_func())

        self.project.hook_symbol("sgx_ocfree_switchless", stub_func())

        self.project.hook_symbol("dlmemalign", stub_func())
        self.project.hook_symbol("__memset", stub_func())

        self.project.hook_symbol("memset", stub_func())

        self.project.hook_symbol("abort", module.MyAbort())

        self.project.hook_symbol("memset_s", stub_func())

        self.project.hook_symbol("sgx_create_report", stub_func())

        # e94:	e8 57 79 00 00       	call   87f0 <memcpy_s>
        # self.project.hook(0xe94, module.my_sty_func, length = 5)

        self.project.hook_symbol("do_init_thread", stub_func())

        self.project.hook_symbol("do_ecall_add_thread", stub_func())

        # self.project.hook_symbol("trts_handle_exception", stub_func())

        self.project.hook_symbol("sgx_read_rand", stub_func())

        self.project.hook_symbol("sgx_spin_lock", stub_func())

        self.project.hook_symbol("sgx_spin_unlock", stub_func())

        self.project.hook_symbol("sgx_is_outside_enclave", stub_func())

        self.project.hook_symbol("check_static_stack_canary", stub_func())

        self.project.hook_symbol("get_enclave_state", stub_func())
        ### FOR THE FUTURE *FLAVIO*
        ## sgx_ocalloc NOTE: these two stub_func are for test. I don't know what to do with them
        ## I need them to perform an OCALL, but in this way seems the paths explode (and I don't know why)
        ## no time to investigate now. I will back later.
        self.project.hook_symbol("sgx_ocalloc", stub_func())
        # self.project.hook_symbol("sgx_ocalloc", module.MyTrueFun())
        self.project.hook_symbol("sgx_ocfree", stub_func())

        self.project.hook_symbol("dlmalloc", stub_func())

        self.project.hook_symbol("vsnprintf", stub_func())

        self.project.hook_symbol("dlfree", stub_func())

        self.project.hook_symbol("memcpy_s", stub_func())

        self.project.hook_symbol("malloc", stub_func())

        self.project.hook_symbol("memcpy", stub_func())

        self.project.hook_symbol("memmove", stub_func())

        self.project.hook_symbol("free", stub_func())

        self.project.hook_symbol("dispose_chunk", stub_func())

        self.project.hook_symbol("strlen", stub_func())

        self.project.hook_symbol("strnlen", stub_func())

        for addr in self.enclulist:
        #     # self.project.hook(addr, module.enclu_sim, length=3)
            self.project.hook(addr, module.MyEncluSim(), length=3)

        for addr in self.enclaexit:
            # print("exit: 0x{:x}".format(addr))
            self.project.hook(addr, module.MyCloseExploration())

        # self.project.hook(self.do_ocall, module.myDoOcall, length=0)

        ## OLD
        # for addr in self.strlenflist:
        #     self.project.hook(addr, module.passf, length=5)
        # for addr in self.memcpyflist:
        #     self.project.hook(addr, module.passf, length=5)

    def traceSetting(self):
        # hook the tracing functions

        self.project.hook_symbol('_Z10traceedgecPv', module.MyTracerEdgeHook())
        # self.project.hook_symbol('_Z10traceframePv', module.MyTracerFrameHook())
        self.project.hook_symbol('_Z15traceassigmentfPv', module.MyTracerAssigmentHook())
        # TODO: hook vptr assignment!
        # self.project.hook_symbol('XXX', module.MyTracerPtrHook())
        self.project.hook_symbol('_Z7tracebrPv', module.MyTracerBranchHook())

        self.project.hook_symbol('trace_context_generation', module.MyCtxGenHook())
        self.project.hook_symbol('trace_eexit', module.MyEExitOcallHook())
        self.project.hook_symbol('trace_context_consume', module.MyCtxConHook())
        self.project.hook_symbol('_Z12trace_eenteri', module.MyEEnterHook())
        self.project.hook_symbol('_Z12trace_eexit2v', module.MyEExitHook())

        self.project.hook_symbol('_Z13trace_eresumev', module.MyEresumeHook())
        self.project.hook_symbol('_Z27trace_exception_consumptionP17_exception_info_t', module.MyExcConHook())
        self.project.hook_symbol('_Z26trace_exception_generationP17_exception_info_t', module.MyExcGenHook())
        
        self.project.hook_symbol('continue_execution', module.MyContinueExecution())

    def preliminaryAnalysis(self):
        # NOTE: this helps me get ENCLU address of DO_OCALL function
        ocall_begin = False
        ocall_end = False
        ocall_enclu_addr = None
        with open(self.enclave_asm, 'r') as f:
            for l in f:
                if not ocall_begin and l.strip().endswith("<do_ocall>:"):
                    self.do_ocall = parseinsaddr(l, "<")
                    ocall_begin = True
                    continue
                if ocall_begin and not ocall_end and l.strip().endswith("enclu"):
                    ocall_enclu_addr = parseinsaddr(l, ":")
                    break
        self.ocall_enclu_addr = ocall_enclu_addr

        if not self.init_state:
            print("self.init_state not initialized yet!")
            exit(0)
        else:
            self.init_state.globals["ocall_enclu_addr"] = self.ocall_enclu_addr

    def findretandcall(self):

        is_asmoret = False
        with open(self.enclave_asm,'r') as f1:
            for line1 in f1:
                if "<asm_oret>:" in line1:
                    is_asmoret = True
                # l1 = line1.strip()
                if 'ret ' in line1 and not is_asmoret:
                    addr = getinsaddr(line1, ":")
                    leng = getlenaddr(line1, ":", "r")
                    self.retinst.append(addr)
                    self.retinstlen.append(leng)
                    is_asmoret = False
                if 'call ' in line1:
                    addr = getinsaddr(line1, ":")
                    self.callinst.append(addr)

    def isWithinFun(self, instrAddr, funAddr, functions):

        prevAddr = None
        prevName = None      
        for addr, name in functions:
            if funAddr == prevAddr:
                return instrAddr > prevAddr and instrAddr < addr

            prevAddr = addr
            prevName = name

        return False

    def findloops(self):

        # If not loop info given, just leave it
        if self.loop_file is None:
            print(" ***** No Loop Info Given! *****")
            self.addr_loops = {}
            return
            # print(" LOOK AT `extract_loop.py SCRIPT")
            # exit(1)
        
        md5enclave = md5sum(self.enclave_bin)
        addr_loops = {}

        if os.path.exists(self.loop_file):
            with open(self.loop_file, 'r') as f:
                md5enclave_salved = f.readline()

                if md5enclave == md5enclave_salved[:-1]:
                    for l in f:
                        if l:
                            (look_addr, way_out, inter) = [int(t, 16) for t in l.split()]
                            addr_loops[look_addr] = (way_out, inter)
                else:
                    print(" ERROR! LOOP FILE {} IS NOT COMPATIBILE WITH THE ENCLAVE! [{}]".format(self.loop_file, md5enclave))
                    print(" LOOK AT 'extract_loop.py' SCRIPT")
                    exit(1)
        else:
            print(" ERROR! LOOP FILE {} DOES NOT EXISTS!".format(self.loop_file))
            exit(1)

        self.addr_loops = addr_loops

    def setloopshook(self):
        if not self.init_state:
            print(" => I EXCEPT AN INIT STATE HERE! <=")
            exit(0)

        addr_loops = self.addr_loops

        # here I hook the actual loops
        with open(self.enclave_asm,'r') as f1:
            lines = f1.readlines()

            for i, line1 in enumerate(lines):

                addr = None
                try:
                    addr = getinsaddr(line1, ":")
                except:
                    pass

                if addr is None:
                    continue

                if addr in addr_loops:
                    self.project.hook(addr, module.loop_handling, length=0)
                    self.init_state.my_loopsmanager.addLoop(addr, addr_loops[addr][0], addr_loops[addr][1])

    def preliminaries(self):
        self.disassemble()
        self.findunsupportedinstructions()
        self.findaddresses()
        self.preliminaryAnalysis()
        self.handleaddresses()
        self.traceSetting()

        self.findloops()
        self.setloopshook()

        if self.custom:
            self.custom.pre_analysis()

    def makeregistersymbolicOcall(self, state):
        state.regs.rax = state.solver.BVS("ocall_rax", 64)
        # state.regs.rax = 0 # ?? dkw
        state.regs.rbx = state.solver.BVS("ocall_rbx", 64)
        state.regs.rcx = state.solver.BVS("ocall_rcx", 64)
        state.regs.rdx = state.solver.BVS("ocall_rdx", 64)
        # state.regs.rdi = state.solver.BVS("rdi", 64)
        # state.regs.rdi = state.solver.BVV(0xFFFFFFFFFFFFFFFF, 64)
        # state.regs.rdi = -2 # ORET!
        state.regs.rdi = state.solver.BVV(0xFFFFFFFFFFFFFFFE, 64)
        state.regs.rsi = state.solver.BVS("ocall_rsi", 64)
        state.regs.r8 = state.solver.BVS("ocall_r8", 64)
        state.regs.r9 = state.solver.BVS("ocall_r9", 64)
        state.regs.r10 = state.solver.BVS("ocall_r10", 64)
        state.regs.r11 = state.solver.BVS("ocall_r11", 64)
        state.regs.r12 = state.solver.BVS("ocall_r12", 64)
        state.regs.r13 = state.solver.BVS("ocall_r13", 64)
        state.regs.r14 = state.solver.BVS("ocall_r14", 64)
        state.regs.r15 = state.solver.BVS("ocall_r15", 64)

        # start again
        # state.regs.rip = self.enclave_entry.linked_addr

    def makeregistersymbolicEcall(self, secfun):
        self.init_state.regs.rax = self.init_state.solver.BVS("rax", 64)
        self.init_state.regs.rbx = self.init_state.solver.BVS("rbx", 64)
        self.init_state.regs.rcx = self.init_state.solver.BVS("rcx", 64)
        self.init_state.regs.rdx = self.init_state.solver.BVS("rdx", 64)
        # self.init_state.regs.rdi = self.init_state.solver.BVS("rdi", 64)
        self.init_state.regs.rdi = secfun # I call a specific secure function
        self.init_state.regs.rsi = self.init_state.solver.BVS("rsi", 64)
        self.init_state.regs.r8 = self.init_state.solver.BVS("r8", 64)
        self.init_state.regs.r9 = self.init_state.solver.BVS("r9", 64)
        self.init_state.regs.r10 = self.init_state.solver.BVS("r10", 64)
        self.init_state.regs.r11 = self.init_state.solver.BVS("r11", 64)
        self.init_state.regs.r12 = self.init_state.solver.BVS("r12", 64)
        self.init_state.regs.r13 = self.init_state.solver.BVS("r13", 64)
        self.init_state.regs.r14 = self.init_state.solver.BVS("r14", 64)
        self.init_state.regs.r15 = self.init_state.solver.BVS("r15", 64)

    def getFunction(self, b):
        t = hex(b)[2:]
        ll = []
        with open(self.enclave_asm, 'r') as f:
            for l in f:
                l = l.strip()
                ll.append(l)
                if l.startswith(t):
                    i = len(ll) - 1
                    while not ll[i].endswith(">:"):
                        i = i - 1
                    # print(ll[i])
                    beg = ll[i].find("<") + 1
                    end = ll[i].find(">")
                    fname = ll[i][beg:end]
                    return fname
        print("nothing for {}".format(hex(b)))
        exit(1)

    def extractTrace(self, states):
        for i, d in enumerate(states):
            if not d.my_tracer.actions:
                continue

            t = " -> ".join(d.my_tracer.actions)

            if self.trace_bbl:
                h = " -> ".join(["0x{:x}".format(bb) for bb in d.history.bbl_addrs])
                self.traces.add((t, h))
            else:
                self.traces.add(t)


    def dumpErrored(self, errored):
        with open(errored, 'w') as f:
            for i, t in enumerate(self.errored):
                f.write(t)
                f.write("\n")

    def dumpModel(self, model):
        with open(model, 'a+') as f:
            for i, t in enumerate(self.traces):
                f.write("{}: {}".format(i, t))
                f.write("\n")

    # NOTE: overwrite this method to implement your custom analysis
    def start_analysis(self):
        print(" **** => START ANALYSIS STUB METHOD ****")

# UTLITY
def getinsaddr(line, separator):
    temp = line[:line.find(separator)]
    temp1 = int(temp, 16)
    return temp1

def getlenaddr(line, separator, separator2):
    temp = line[line.find(separator):line.find(separator2)].strip()
    return len(temp.split(" "))

def parseinsaddr(line, separator):
    temp = line[:line.find(separator)]
    try:
        temp1 = int(temp, 16)
    except:
        return -1

    return temp1

def md5sum(filename):
    with open(filename, mode='rb') as f:
        d = hashlib.md5()
        for buf in iter(partial(f.read, 128), b''):
            d.update(buf)
    return d.hexdigest()
