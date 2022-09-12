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
    def __init__(self, binary, asm_folder, trace_bbl, custom_module, dump_model, loop_info, function = None):
        self.project = None
        self.enclave_bin = binary
        self.trace_bbl = trace_bbl
        self.errored = set()

        self.loop_file = loop_info
        self.addr_loops = {}

        self.function = function

        self.custom = None
        if custom_module is not None:
            mod = __import__('customization', fromlist=[custom_module])
            klass = getattr(mod, custom_module)
            self.custom = klass(self)

        self.dump_model = dump_model

        self.my_loopsmanager = loopsmanager.MyLoopsManager(3)

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
        self.jmptrace = []
        self.noinlinewrapper = None

        self.repstoslist = []
        self.rdrandlist = []
        self.rdrandlengthlist = []
        self.wrfsbaselist = []

        self.enclulist = []
        self.enclaveentry = None
        self.enclaexit = []

        self.ud2list = []

        self.registeredhandler = []

        self.pendingstate = []
        self.traces = set()

    def load_binary(self):
        ## NOTE:
        # auto_load_libs = Flase -> I don't want libc, in SGX everything is statically linked
        # base_addr = 0x0 -> I want relative address, that's easier
        self.project = Project(self.enclave_bin, auto_load_libs=False, main_opts = {'base_addr': 0x0})
        
    def make_state(self, fnc, glbsym = True):

        fnc_sym = self.project.loader.main_object.get_symbol(fnc)
        self.init_state = self.project.factory.call_state(fnc_sym.linked_addr)

        # self.init_state.solver._solver.timeout=1

        # self.init_state.globals["pendingstate"] = self.pendingstate
        self.tracer_collector = tracer_collector.TracerCollector(self.dump_model)
        self.init_state.globals["tracer_collector"] = self.tracer_collector
        self.init_state.globals["ocall_enclu_addr"] = self.ocall_enclu_addr
        self.init_state.globals["traced_functions"] = self.traced_functions
        self.init_state.register_plugin('my_loopsmanager', self.my_loopsmanager)

        # self.init_state.register_plugin('my_shadowstack', shadowstack.MyShadowStack())
        self.init_state.register_plugin('my_tracer', tracer.MyTracer())
        # self.init_state.register_plugin('my_loopsmanager', loopsmanager.MyLoopsManager(0))

        # self.init_state.options.add(options.LAZY_SOLVES)

        # set symbolic BSS variables
        if glbsym:
            print("[INFO] setting BSS symbolic")
            try:
                s_bss = self.project.loader.main_object.sections_map['.bss'] 
            except:
                print("[ERROR] .bss not found")
                exit()
            
            # from IPython import embed; embed()
            for s in self.project.loader.main_object.symbols: 
                if s_bss.contains_addr(s.linked_addr): 
                    name = s.name
                    addr = s.linked_addr
                    size = s.size
                    self.init_state.memory.store(addr, self.init_state.solver.BVS(name, size*8))
            # from IPython import embed; embed()

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

        self.functions = self.get_functions()
        self.traced_functions = [fnc for addr, fnc, is_traced in self.functions if is_traced]
        self.functions_bound = self.get_functions_bound()

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
                if "\tud2 " in line1:
                    addr = getinsaddr(line1, ":")
                    self.ud2list.append(addr)
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
                    leng = getlenaddr(line1, ":", "r")
                    self.rdrandlist.append(addr)
                    self.rdrandlengthlist.append(leng)

                if "\twrfsbase " in line1 and not "<" in line1:
                    addr = getinsaddr(line1, ":")
                    self.wrfsbaselist.append(addr)

                instToAvoid = ["\tvmovaps ", "\tvmovdqa ", "\tvaeskeygenassist ", 
                                "\tvaesenc ", "\tvaesenclast ", "\tvxorps ", "\tvpsubq ",
                                "\tvpaddq ", "\tvpclmulhqhqdq ", "\tvpclmullqlqdq ",
                                "\tvpermilps ", "\tvpshufd ", "\tvpslldq ", "\tvmovq ",
                                "\tvpxor ", "\tvmovdqu ", "\tvmovups ", "\tvpcmpeqq ", "\tvpor ", 
                                "\tvextracti128 ", "\tvpackssdw "]

                instToAvoid += ["\tvzeroupper "]

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
        for addr, leng in zip(self.rdrandlist, self.rdrandlengthlist):
            # self.project.hook(addr, module.passf, length=leng)
            self.project.hook(addr, module.passf_random, length=leng)

        for addr in self.wrfsbaselist:
            self.project.hook(addr, module.passf, length=5)

        for addr, len in zip(self.repmovslist, self.repmovslengthlist):
            self.project.hook(addr, module.passf_rep, length=len)

        # RET 
        for addr, leng in zip(self.retinst, self.retinstlen):
            # self.project.hook(addr, module.pop_shadowstack, length=leng)
            self.project.hook(addr, module.MyCloseExploration())

        # CALL
        # for addr in self.callinst:
        #     self.project.hook(addr, module.skip_call, length=0)

        # JMP TRACEEDGE
        for addr in self.jmptrace:
            self.project.hook(addr, module.MyCloseExploration(True))        


        for addr in self.enclulist:
            self.project.hook(addr, module.MyEncluSim(), length=3)

        # HOOK outbound function access with stop exploration
        for addr, fname, is_traced in self.functions:
            if is_traced:
                f_max = self.functions_bound[addr]
                # from IPython import embed; embed()
                if not self.project.is_hooked(f_max):
                    self.project.hook(f_max, module.MyCloseExploration())

    def traceSetting(self):
        # hook the tracing functions

        self.project.hook_symbol('_Z10traceedgecPv', module.MyTracerHook('E'))
        self.project.hook_symbol('_Z15traceassigmentfPv', module.MyTracerHook('A'))
        # TODO: hook vptr assignment!
        # self.project.hook_symbol('XXX', module.MyTracerPtrHook())
        self.project.hook_symbol('_Z7tracebrPv', module.MyTracerHook('B'))

        self.project.hook_symbol('trace_context_generation', module.MyTracerHook('G'))
        self.project.hook_symbol('trace_eexit', module.MyTracerHook('D'))
        self.project.hook_symbol('trace_context_consume', module.MyTracerHook('C'))
        self.project.hook_symbol('_Z12trace_eenteri', module.MyTracerHook('N'))
        self.project.hook_symbol('_Z12trace_eexit2v', module.MyTracerHook('T'))

        self.project.hook_symbol('_Z13trace_eresumev', module.MyTracerHook('L'))
        self.project.hook_symbol('_Z27trace_exception_consumptionP17_exception_info_t', module.MyTracerHook('K'))
        self.project.hook_symbol('_Z26trace_exception_generationP17_exception_info_t', module.MyTracerHook('J'))
        
        self.project.hook_symbol('continue_execution', module.MyContinueExecution())

        stub_func = module.MyStubFunc
        for addr, fnc, is_traced in self.get_functions():
            if not self.project.is_hooked(addr):
                self.project.hook(addr, stub_func(is_traced))

        self.project.hook_symbol("abort", module.MyAbort())


    def get_functions_bound(self):
        
        bounding = {}

        function_begin_addr = None
        function_end_addr = None
        with open(self.enclave_asm,'r') as f1:
            for l in f1:
                l = l.strip()
                # skip comments
                if "#" in l:
                    l = l.split("#")[0]

                if not l:
                    continue

                # 0000000000012700 <_mm256_set1_epi64x>:
                if l.endswith(">:"):
                    la = l.split()
                    function_begin_addr = int(la[0],16)
                else:
                    try:
                        la = l.split(":")
                        function_end_addr = int(la[0],16)
                        bounding[function_begin_addr] = function_end_addr
                    except:
                        pass

        # if function_begin_addr is None or function_end_addr is None:
        #     print("function_begin_addr or function_end_addr is None")
        #     import monkeyhex
        #     from IPython import embed; embed()
        #     exit(1)

        return bounding
        

    def get_functions(self):
        
        traced_symb = ['_Z10traceedgecPv', '_Z15traceassigmentfPv', '_Z7tracebrPv', 'trace_context_generation',
                    'trace_eexit', 'trace_context_consume', '_Z12trace_eenteri', '_Z12trace_eexit2v', 
                    '_Z13trace_eresumev', '_Z27trace_exception_consumptionP17_exception_info_t', 
                    '_Z26trace_exception_generationP17_exception_info_t']

        functions = []
        current_fname = None
        current_addr = None
        is_traced = False
        with open(self.enclave_asm,'r') as f1:
            for l in f1:
                l = l.strip()
                # skip comments
                if "#" in l:
                    l = l.split("#")[0]

                # 0000000000012700 <_mm256_set1_epi64x>:
                if l.endswith(">:"):
                    if current_fname is not None and current_addr is not None:
                        if current_fname not in traced_symb:
                            functions.append((current_addr, current_fname, is_traced))
                        is_traced = False
                    la = l.split()
                    addr = int(la[0],16)
                    fname = la[1][1:-2]

                    current_addr = addr
                    current_fname = fname
                else:
                    is_traced |= any([ s in l for s in traced_symb ])

            if current_fname is not None and current_addr is not None and is_traced:
                functions.append((current_addr, current_fname, is_traced))
                
        return functions

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

        # This is used to find exception handlers
        # 1) find sgx_register_exception_handler address
        regexc_addr = None
        with open(self.enclave_asm, 'r') as f:
            for l in f:
                if l.strip().endswith("<sgx_register_exception_handler>:"):
                    regexc_addr = parseinsaddr(l, "<")
                    break
        if not regexc_addr:
            print("sgx_register_exception_handler not found")
            return

        print("<sgx_register_exception_handler>: 0x{:x}".format(regexc_addr))

        # 2) find where sgx_register_exception_handler is called and get the parameters (from rsi)
        # 2a) sometime the setting is swapped, I might find the rsi before rdi assignment, dkw?!
        # 1b2a:	bf 01 00 00 00       	mov    edi,0x1
        # 1b2f:	48 8d 35 7a ff ff ff 	lea    rsi,[rip+0xffffffffffffff7a]        # 1ab0 <_Z22divide_by_zero_handlerP17_exception_info_t>
        # 1b36:	e8 25 2e 00 00       	call   4960 <sgx_register_exception_handler>
        token = "call{:x}<sgx_register_exception_handler>".format(regexc_addr)
        prevLines = [None] * 3
        idx = 0
        with open(self.enclave_asm, 'r') as f:
            for l in f:
                ll = l.strip().replace(" ", "")
                if ll.endswith(token):
                    
                    for prevLine in prevLines:
                        if "rsi" in prevLine:
                            # get parameters
                            sharpPos = prevLine.find("#")
                            minPos = prevLine.find("<")
                            handler_addr = prevLine[sharpPos + 1: minPos]
                            break

                    self.registeredhandler.append(int(handler_addr, 16))

                prevLines[idx%len(prevLines)] = l
                idx += 1

    def findretandcall(self):

        with open(self.enclave_asm,'r') as f1:
            for line1 in f1:
                if 'ret ' in line1:
                    addr = getinsaddr(line1, ":")
                    leng = getlenaddr(line1, ":", "r")
                    self.retinst.append(addr)
                    self.retinstlen.append(leng)
                if 'call ' in line1:
                    addr = getinsaddr(line1, ":")
                    self.callinst.append(addr)
                if 'jmp ' in line1 and "<_Z10traceedgecPv>" in line1:
                    addr = getinsaddr(line1, ":")
                    self.jmptrace.append(addr)

    def isWithinFun(self, instrAddr, funAddr):

        if funAddr not in self.functions_bound:
            raise Exception("funciton 0x{:x} is unknown".format(funAddr))

        max_f = self.functions_bound[funAddr]

        return instrAddr >= funAddr and instrAddr <= max_f

    def findloops(self):

        # If not loop info given, just leave it
        if self.loop_file is None:
            print(" ***** No Loop Info Given! *****")
            return
        
        md5enclave = md5sum(self.enclave_bin)
        addr_loops = {}

        if os.path.exists(self.loop_file):
            with open(self.loop_file, 'r') as f:
                md5enclave_salved = f.readline()

                if md5enclave == md5enclave_salved[:-1]:
                    for l in f:
                        if l:
                            (look_addr, way_out, inter) = [int(t, 16) for t in l.split()]
                            if way_out != inter:
                                addr_loops[look_addr] = (way_out, inter)
                else:
                    print(" ERROR! LOOP FILE {} IS NOT COMPATIBILE WITH THE ENCLAVE! [{}]".format(self.loop_file, md5enclave))
                    print(" LOOK AT `extract_loop.py SCRIPT")
                    exit(1)
        else:
            print(" ERROR! LOOP FILE {} DOES NOT EXISTS!".format(self.loop_file))
            exit(1)

        self.addr_loops = addr_loops

    def setloopshook(self):
        # if not self.init_state:
        #     print(" => I EXCEPT AN INIT STATE HERE! <=")
        #     exit(0)

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
                    self.my_loopsmanager.addLoop(addr, addr_loops[addr][0], addr_loops[addr][1])

    def preliminaries(self):
        self.disassemble()
        self.findunsupportedinstructions()
        self.findaddresses()
        self.get_special_actiosn()
        self.preliminaryAnalysis()
        self.traceSetting()
        self.handleaddresses()

        self.findloops()
        self.setloopshook()

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

    def get_special_actiosn(self):

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
                            excGenId = getinsaddr(lines[i+1],":")

                # this extracts the trace_eenter ID
                if not trcEntId:
                    if 'enter_enclave' in line1:
                        beginEnterEnclave = True
                    if beginEnterEnclave:
                        if "trace_eenter" in line1:
                            trcEntId = getinsaddr(lines[i+1],":")
                        
                # this extracts the trace_eexit ID
                if not trcExtId:
                    if 'enter_enclave' in line1:
                        beginEnterEnclave = True
                    if beginEnterEnclave:
                        if "trace_eexit" in line1:
                            trcExtId = getinsaddr(lines[i+1],":")

        self.specialactions = {}

        if trcEntId is not None:
            eenter = "0x{:x}".format(trcEntId)
            self.specialactions["N"] = eenter
        if excGenId is not None:
            excGen = "0x{:x}".format(excGenId)
            self.specialactions["J"] = excGen
        if trcExtId is not None:
            eexit = "0x{:x}".format(trcExtId)
            self.specialactions["T"] = eexit

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
