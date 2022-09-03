import angr
import copy

class MyLoopsManager(angr.SimStatePlugin):
    def __init__(self, max_iterations = 0):
        super(MyLoopsManager, self).__init__()
        self.max_iterations = max_iterations
        self.original_counter = {}
        self.actual_counter = {}
        self.way_out = {}
        self.iteration = {}

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        dup = MyLoopsManager()

        #FLAVIO: that's the right way to copy, trust me dude!
        dup.max_iterations = self.max_iterations
        dup.original_counter = copy.deepcopy(self.original_counter)
        dup.actual_counter = copy.deepcopy(self.actual_counter)
        dup.way_out = copy.deepcopy(self.way_out)
        dup.iteration = copy.deepcopy(self.iteration)
        
        return dup

    # NOTE: return false -> not skip; return true -> skip jump
    def unroll(self, ctx, addr):
        if addr not in self.original_counter:
            return False

        counters = self.actual_counter.get(addr, 0)

        if counters == self.original_counter[addr]:
            self.actual_counter[addr] = counters
            return True

        self.actual_counter[addr] = counters + 1

        return False

    def getLeftover(self, ctx, addr):
        if addr not in self.original_counter:
            return -1

        a_cnt = self.actual_counter.get(addr, 0)
        o_cnt = self.original_counter[addr]

        return o_cnt - a_cnt
        
    def removeContext(self, ctx):
        return False

    def addLoop(self, addr, way_out, iteration, max_iterations = None):
        if not max_iterations:
            max_iterations = self.max_iterations

        self.original_counter[addr] = max_iterations
        self.way_out[addr] = way_out
        self.iteration[addr] = iteration

        

# import angr
# import copy

# class MyLoopsManager(angr.SimStatePlugin):
#     def __init__(self, max_iterations = 0):
#         super(MyLoopsManager, self).__init__()
#         self.max_iterations = max_iterations
#         self.original_counter = {}
#         self.actual_counter = {}
#         self.way_out = {}

#     @angr.SimStatePlugin.memo
#     def copy(self, memo):
#         dup = MyLoopsManager()

#         #FLAVIO: that's the right way to copy, trust me dude!
#         dup.max_iterations = self.max_iterations
#         dup.original_counter = copy.deepcopy(self.original_counter)
#         dup.actual_counter = copy.deepcopy(self.actual_counter)
#         dup.way_out = copy.deepcopy(self.way_out)
        
#         return dup

#     # NOTE: return false -> not skip; return true -> skip jump
#     def unroll(self, ctx, addr):
#         if addr not in self.original_counter:
#             return False

#         counters = self.actual_counter.get(ctx, {})
#         addr_ctx = counters.get(addr, 0)

#         if addr_ctx == self.original_counter[addr]:
#             counters[addr] = addr_ctx
#             self.actual_counter[ctx] = counters
#             return True

#         counters[addr] = addr_ctx + 1
#         self.actual_counter[ctx] = counters

#         return False

#         # OLD STYLE
#         # if addr in self.leftover_counter:
#         #     self.leftover_counter[addr] = max(self.leftover_counter[addr] - 1, 0)
#         # else:
#         #     return False    
#         # return self.leftover_counter[addr] == 0

#     def getLeftover(self, ctx, addr):
#         if addr not in self.original_counter:
#             return -1

#         if ctx not in self.actual_counter:
#             return -1

#         if addr not in self.actual_counter[ctx]:
#             return -1

#         o_cnt = self.original_counter[addr]
#         a_cnt = self.actual_counter[ctx][addr]

#         return o_cnt - a_cnt
        
#     def removeContext(self, ctx):
#         if ctx in self.actual_counter:
#             del self.actual_counter[ctx]
#             return True

#         return False

#     def addLoop(self, addr, way_out, max_iterations = None):
#         if not max_iterations:
#             max_iterations = self.max_iterations

#         self.original_counter[addr] = max_iterations
#         self.way_out[addr] = way_out

        