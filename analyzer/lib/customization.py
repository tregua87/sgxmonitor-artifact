
# project imports
import module, shadowstack, tracer, common, loopsmanager, hashlib

# NOTE: kinda "virtual class" for customization
class Customizations:
    def __init__(self, a):
        self.a = a

    def pre_analysis(self):
        pass

    def getFcts(self):
        return []

class Contact(Customizations):
    def pre_analysis(self):
        
        ## TODO: for future FLAVIO, think something about setting global variables in .bss as unconstratin 
        ## simbols, or else you can't explore all the paths
        gNodeInitialized = self.a.project.loader.main_object.get_symbol('g_sgxsd_enclave_node_initialized')
        self.a.init_state.memory.store(gNodeInitialized.linked_addr, self.a.init_state.solver.BVS('gNodeInitialized', 8))

        gPendingRequestsTableOrder = self.a.project.loader.main_object.get_symbol('g_sgxsd_enclave_pending_requests_table_order')
        self.a.init_state.memory.store(gPendingRequestsTableOrder.linked_addr, self.a.init_state.solver.BVS('gPendingRequestsTableOrder', 8))

        gLastPendingRequestIdVal = self.a.project.loader.main_object.get_symbol('g_sgxsd_enclave_last_pending_request_id_val')
        self.a.init_state.memory.store(gLastPendingRequestIdVal.linked_addr, self.a.init_state.solver.BVS('gLastPendingRequestIdVal', 8*8))

        gSgxsdEnclaveServerStates = self.a.project.loader.main_object.get_symbol('g_sgxsd_enclave_server_states')
        self.a.init_state.memory.store(gSgxsdEnclaveServerStates.linked_addr, self.a.init_state.solver.BVS('gSgxsdEnclaveServerStates', 8*64*256))

        gSgxsdEnclavePendingRequestsTableOrder = self.a.project.loader.main_object.get_symbol('g_sgxsd_enclave_pending_requests_table_order')
        self.a.init_state.memory.store(gSgxsdEnclavePendingRequestsTableOrder.linked_addr, self.a.init_state.solver.BVS('gSgxsdEnclavePendingRequestsTableOrder', 8))

        gSgxsdEnclavePendingRequests = self.a.project.loader.main_object.get_symbol('g_sgxsd_enclave_pending_requests')
        firstEntry = self.a.init_state.heap.allocate(40)
        self.a.init_state.memory.store(gSgxsdEnclavePendingRequests.linked_addr, firstEntry)
        self.a.init_state.memory.store(firstEntry, self.a.init_state.solver.BVS('gSgxsdEnclavePendingRequestsfirstEntry', 8*40))

        addr_to_skip = []
        # # from old
        # addr_to_skip = [0x521d, 0x5226, 0x3dea, 0x2831, 0x283c, 0x65ba, 0x21f3]

        # # these are strange 
        # addr_to_skip += [0x52da, 0x52f5, 0x530a, 0x53ab, 0x5406, 0x5462, 0x54c2, 0x5522, 0x557c, 0x5581, 0x563f]

        # addr_to_skip += [0x6db5]

        # # these are loops:
        # addr_to_skip = addr_to_skip + [0x57e8, 0x580f] # sha2small_update
        # addr_to_skip = addr_to_skip + [0x3dfa] # br_range_dec32be
        # addr_to_skip = addr_to_skip + [0x26c5] # sgxsd_enclave_sha256
        # addr_to_skip = addr_to_skip + [0x2849] # sgxsd_enclave_hmac_sha256
        # addr_to_skip = addr_to_skip + [0x65cd] # curve25519_donna
        # addr_to_skip = addr_to_skip + [0x5693, 0x531f] # br_sha2small_round
        # addr_to_skip = addr_to_skip + [0x6f1b, 0x6f3c] # cmult
        # addr_to_skip = addr_to_skip + [0xd563] # fsquare_times    

        with open(self.a.enclave_asm,'r') as f1:
            lines = f1.readlines()

            for i, line1 in enumerate(lines):

                addr = None
                try:
                    addr = common.getinsaddr(line1, ":")
                except:
                    pass

                if addr is None:
                    continue

                if addr in addr_to_skip:
                    leng = len(line1.split("\t")[1].split())

                    if leng == 7 and i < len(lines):
                        nextLineA = lines[i+1].strip().split('\t')
                        if len(nextLineA) == 2:
                            temp = nextLineA[1].strip()
                            leng = leng + len(temp.split())

                    self.a.project.hook(addr, module.passf, length=leng)

        # self.a.project.hook_symbol('sgxsd_enclave_generate_curve25519_privkey', module.MyStubFunc())
        # self.a.project.hook_symbol('sgxsd_enclave_hmac_sha256', module.MyStubFunc())
        # self.a.project.hook_symbol('sgxsd_enclave_sha256', module.MyStubFunc())
        # self.a.project.hook_symbol('br_sha256_init', module.MyStubFunc())
        # self.a.project.hook_symbol('br_sha224_update', module.MyStubFunc()) #define br_sha256_update br_sha224_update
        # self.a.project.hook_symbol('br_sha2small_round', module.MyStubFunc())
        # self.a.project.hook_symbol('br_sha256_out', module.MyStubFunc())

        # self.a.project.hook_symbol('curve25519_donna', module.MyStubFunc())
        # self.a.project.hook_symbol('fexpand', module.MyStubFunc())
        # self.a.project.hook_symbol('cmult', module.MyStubFunc())
        # self.a.project.hook_symbol('fmonty', module.MyStubFunc()) # this is the hell
        # self.a.project.hook_symbol('fsquare_times', module.MyStubFunc())
        # self.a.project.hook_symbol('crecip', module.MyStubFunc())
        # self.a.project.hook_symbol('fmul', module.MyStubFunc())
        # self.a.project.hook_symbol('fcontract', module.MyStubFunc())

        # exit()

        # params for sec function num. 0
        sgxsdEnclaveNodeInitLocked = self.a.project.loader.main_object.get_symbol('sgxsd_enclave_node_init_locked')
        self.a.project.hook(sgxsdEnclaveNodeInitLocked.linked_addr, setSgxsdEnclaveNodeInitLocked, length=0)

        # params for sec function num. 1
        sgxsdEnclaveGetNextReport = self.a.project.loader.main_object.get_symbol('sgxsd_enclave_get_next_report')
        self.a.project.hook(sgxsdEnclaveGetNextReport.linked_addr, setSgxsdEnclaveGetNextReport, length=0)

        # sec function num. 2 has no parameters

        # params for sec function num. 3
        sgxsdEnclaveNegotiateRequest = self.a.project.loader.main_object.get_symbol('sgxsd_enclave_negotiate_request')
        self.a.project.hook(sgxsdEnclaveNegotiateRequest.linked_addr, setSgxsdEnclaveNegotiateRequest, length=0)

        # params for sec function num. 4
        sgxsdEnclaveServerStartLocked = self.a.project.loader.main_object.get_symbol('sgxsd_enclave_server_start_locked')
        self.a.project.hook(sgxsdEnclaveServerStartLocked.linked_addr, setSgxsdEnclaveServerStartLocked, length=0)

        # params for sec function num. 5
        sgxsdEnclaveServerCallLocked = self.a.project.loader.main_object.get_symbol('sgxsd_enclave_server_call_locked')
        self.a.project.hook(sgxsdEnclaveServerCallLocked.linked_addr, setSgxsdEnclaveServerCallLocked, length=0)

        # params for sec function num. 6
        sgxsdEnclaveServerStopLocked = self.a.project.loader.main_object.get_symbol('sgxsd_enclave_server_stop_locked')
        self.a.project.hook(sgxsdEnclaveServerStopLocked.linked_addr, setSgxsdEnclaveServerStopLocked, length=0)

    # def getFcts(self):
    #     return [(0x4d40, 0x528d), # br_aes_x86ni_ctr_run
    #             (0x45d0, 0x4cdb), # x86ni_keysched
    #             (0x3e80, 0x455d), # br_ghash_pclmul
    #             (0xe120, 0xe32d), # sabd_lookup_hash_salt
    #             (0x2b80, 0x2cfb)] # sgxsd_enclave_get_next_report
        # return [(0x8bb0, 0x98af), # br_aes_x86ni_ctr_run
        #         (0x6630, 0x85ee), # x86ni_keysched
        #         (0x4880, 0x63cc), # br_ghash_pclmul
        #         (0x11db0, 0x126af)] # sabd_lookup_hash_salt
    
    # def getLoopAddrs(self):
    #     addr_loops = []

    #     addr_loops = addr_loops + [0x57e8, 0x580f]  # sha2small_update
    #     addr_loops = addr_loops + [0x3dfa]          # br_range_dec32be
    #     addr_loops = addr_loops + [0x26c5]          # sgxsd_enclave_sha256
    #     addr_loops = addr_loops + [0x2849]          # sgxsd_enclave_hmac_sha256
    #     addr_loops = addr_loops + [0x65cd]          # curve25519_donna
    #     addr_loops = addr_loops + [0x5693, 0x531f]  # br_sha2small_round
    #     addr_loops = addr_loops + [0x6f1b, 0x6f3c]  # cmult
    #     addr_loops = addr_loops + [0xd563]          # fsquare_times

    #     return addr_loops

def setSgxsdEnclaveServerStopLocked(state):
    print(" ***** SET UNCONSTR. ARGS! *****")

    # 4, malloc, rdi
    p_args_len = 4
    p_args = state.solver.BVS('p_args', 8*p_args_len)
    state.regs.rdi = state.heap.allocate(p_args_len) 
    state.memory.store(state.regs.rdi, p_args)
    
    # 12, malloc, rsi
    p_state_desc_len = 12
    p_state_desc = state.solver.BVS('p_state_desc', 8*p_state_desc_len)
    state.regs.rsi = state.heap.allocate(p_state_desc_len) 
    state.memory.store(state.regs.rsi, p_state_desc)

def setSgxsdEnclaveServerStartLocked(state):
    print(" ***** SET UNCONSTR. ARGS! *****")
    
    # 4, malloc, rdi
    p_args_len = 4
    p_args = state.solver.BVS('p_args', 8*p_args_len)
    state.regs.rdi = state.heap.allocate(p_args_len) 
    state.memory.store(state.regs.rdi, p_args)
    
    # 12, malloc, rsi
    p_state_desc_len = 12
    p_state_desc = state.solver.BVS('p_state_desc', 8*p_state_desc_len)
    state.regs.rsi = state.heap.allocate(p_state_desc_len) 
    state.memory.store(state.regs.rsi, p_state_desc)

def setSgxsdEnclaveGetNextReport(state):
    print(" ***** SET UNCONSTR. ARGS! *****")
    
    # stack, 640, rsp
    qe_target_info_len = 640
    qe_target_info = state.solver.BVS('qe_target_info', 8*qe_target_info_len)
    rsp = state.solver.eval(state.regs.rsp)
    state.memory.store(rsp, qe_target_info)
    
    # malloc, 432, rdi
    p_report_len = 432
    p_report = state.solver.BVS('qe_target_info', 8*p_report_len)
    state.regs.rdi = state.heap.allocate(p_report_len) 
    state.memory.store(state.regs.rdi, p_report)

def setSgxsdEnclaveNegotiateRequest(state):
    print(" ***** SET UNCONSTR. ARGS! *****")

    # rdi, 32, malloc
    p_request_len = 32
    state.regs.rdi = state.heap.allocate(p_request_len) 
    p_request = state.solver.BVS('p_request', 8*p_request_len)
    state.memory.store(state.regs.rdi, p_request)

    # rsi, 128, malloc
    p_response_len = 128
    state.regs.rsi = state.heap.allocate(p_response_len) 
    p_response = state.solver.BVS('p_response', 8*p_response_len)
    state.memory.store(state.regs.rsi, p_response)

def setSgxsdEnclaveNodeInitLocked(state):
    print(" ***** SET UNCONSTR. ARGS! *****")

    p_args_len = 1
    state.regs.rdi = state.heap.allocate(p_args_len) 
    p_args = state.solver.BVS('p_args', 8*p_args_len)
    state.memory.store(state.regs.rdi, p_args)
    

def setSgxsdEnclaveServerCallLocked(state):
    print(" ***** SET UNCONSTR. ARGS! *****")

    p_args_len = 4
    state.regs.rdi = state.heap.allocate(p_args_len) 
    p_args = state.solver.BVS('p_args', 8*p_args_len)
    state.memory.store(state.regs.rdi, p_args)
    
    p_msg_header_len = 64
    state.regs.rsi = state.heap.allocate(p_msg_header_len) 
    p_msg_header = state.solver.BVS('p_msg_header', 8*p_msg_header_len)
    state.memory.store(state.regs.rsi, p_msg_header)
    
    # I assume msg_data 20 bytes long
    msg_data_len = 20
    state.regs.rdx = state.heap.allocate(msg_data_len)
    msg_data = state.solver.BVS('msg_data', 8*msg_data_len)
    state.memory.store(state.regs.rdx, msg_data)

    # msg_data_size
    msg_data_size = state.solver.BVS('msg_data_size', 8*8)
    state.solver.add(msg_data_size == msg_data_len)
    state.regs.r10 = msg_data_size

    # msg_tag
    msg_tag = state.solver.BVS('msg_tag', 8*8)
    state.regs.r8 = msg_tag

    # state_handle
    p_state_desc_len = 32
    state.regs.r9 = state.heap.allocate(p_state_desc_len)
    p_state_desc = state.solver.BVS('p_state_desc', 8*p_state_desc_len)
    state.memory.store(state.regs.r9, p_state_desc)

    # from IPython import embed; embed()
