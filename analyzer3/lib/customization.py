
# project imports
import module, shadowstack, tracer, common, loopsmanager, hashlib
from subprocess import Popen, PIPE
from shlex import split
from angr import *

# NOTE: kinda "virtual class" for customization
class Customizations:
    def __init__(self, a):
        self.a = a
        self.functions = []

    def make_arguments(self, func, state):
        pass

class Contact(Customizations):
    def __init__(self, a):
        super(Contact, self).__init__(a)
        self.functions = ["br_gcm_init", "br_gcm_reset", "br_gcm_aad_inject", "br_gcm_flip", "br_gcm_run", 'br_gcm_get_tag']

    def make_arguments(self, func, state):

        if func not in self.functions:
            print("[ERROR] {} is not valid!")
            exit(1)

        print("[INFO] making args for {}".format(func))

        if func == "br_gcm_init":
            state.regs.rsi = self.make_ptr_to(self.make_br_block_ctr_class(state), state)
        else:
            state.regs.rdi = self.make_br_gcm_context(state)

    def make_ptr_to(self, obj, state):
        ptr = state.heap.allocate(8) 
        state.memory.store(ptr, obj, endness=archinfo.Endness.LE)
        # sym_ptr = state.solver.BVS("smy_ptr", 8*8)
        # state.solver.add(sym_ptr == ptr)
        return ptr
        # state.solver.Or(sym_ptr == ptr, sym_ptr == 0x0)
        # return sym_ptr

    def make_br_gcm_context(self, state):
        br_ghash_pclmul_sym = self.a.project.loader.main_object.get_symbol('br_ghash_pclmul')

        if br_ghash_pclmul_sym is None:
            print("[ERROR] \"br_ghash_pclmul_sym\" not found!")
            exit()

        br_gcm_context_size = 0x100
        br_gcm_context_addr = state.heap.allocate(br_gcm_context_size) 

        br_gcm_context_obj = state.solver.BVS("br_gcm_context", br_gcm_context_size*8)
        state.memory.store(br_gcm_context_addr, br_gcm_context_obj, endness=archinfo.Endness.LE)

        state.memory.store(br_gcm_context_addr + 0x8, self.make_ptr_to(self.make_br_block_ctr_class(state), state), endness=archinfo.Endness.LE)
        state.memory.store(br_gcm_context_addr + 0x10, br_ghash_pclmul_sym.linked_addr, endness=archinfo.Endness.LE)
        
        # arg_sym_ptr = state.solver.BVS("ptr_arg", 8*8)
                            
        # state.solver.add(arg_sym_ptr == br_gcm_context_addr)
        return br_gcm_context_addr

        # state.solver.Or(arg_sym_ptr == br_gcm_context_addr, arg_sym_ptr == 0x0)
        # return arg_sym_ptr

    def make_br_block_ctr_class(self, state):

        br_aes_x86ni_ctr_run_sym = self.a.project.loader.main_object.get_symbol('br_aes_x86ni_ctr_run')

        if br_aes_x86ni_ctr_run_sym is None:
            print("[ERROR] \"br_aes_x86ni_ctr_run\" not found!")
            exit()

        br_block_size = 0x100
        br_block_addr = state.heap.allocate(br_block_size) 

        br_block_obj = state.solver.BVS("br_block_ctr", br_block_size*8)
        state.memory.store(br_block_addr, br_block_obj, endness=archinfo.Endness.LE)

        state.memory.store(br_block_addr + 0x18, br_aes_x86ni_ctr_run_sym.linked_addr, endness=archinfo.Endness.LE)
        
        # arg_sym_ptr = state.solver.BVS("ptr_arg", 8*8)
                            
        # state.solver.add(arg_sym_ptr == br_block_addr)
        return br_block_addr

        # state.solver.Or(arg_sym_ptr == br_block_addr, arg_sym_ptr == 0x0)
        # return arg_sym_ptr

class Libdvdcss(Customizations):
    def __init__(self, a):
        super(Libdvdcss, self).__init__(a)
        self.functions = ["_ZL9GetBusKeyP8dvdcss_s"]

        enclave_bin = a.enclave_bin

        p1 = Popen(split(f"objdump -M intel -d  {enclave_bin}"), stdout=PIPE)
        p2 = Popen(split("grep \"mov    DWORD PTR \[rbp-0x3c\],0xffffffff\""), stdin=p1.stdout, stdout=PIPE)
        p3 = Popen(split("awk -F \":\" '{sub(/^[ \t]+/, \"\"); print \"0x\"$1}'"), stdin=p2.stdout, stdout=PIPE)

        self.hex_to_hook = int(p3.stdout.read(), 0)

        print(f"[INFO] hex_to_hook: {self.hex_to_hook:x}")

    
    def make_arguments(self, func, state):
        if func not in self.functions:
            print("[ERROR] {} is not valid!")
            exit(1)

        print("[INFO] making args for {}".format(func))

        # 7b47:	c7 45 c4 ff ff ff ff 	mov    DWORD PTR [rbp-0x3c],0xffffffff
        self.a.project.hook(self.hex_to_hook, set_i_ret_unconstraint, length=7)

def set_i_ret_unconstraint(state):
    print("[INFO] set i_ret unconstraint")

    # mov    DWORD PTR [rbp-0x3c],0xffffffff
    i_ret_addr = state.regs.rbp - 0x3c
    i_ret_unconstraint = state.solver.BVS("i_ret_unconstraint", 4*8)
    state.memory.store(i_ret_addr, i_ret_unconstraint, endness=archinfo.Endness.LE)
