import angr
import copy

class MyShadowStack(angr.SimStatePlugin):
    def __init__(self):
        super(MyShadowStack, self).__init__()
        self.frames = []
        self.call(0, 0, 0, 0)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        dup = MyShadowStack()
        dup.ret() # or else I have a double empty frame
        for f in self.frames:
            f_dup = copy.deepcopy(f, memo)
            dup.call(f_dup.callsite_addr, f_dup.function_addr, f_dup.stack_addr, f_dup.return_addr)
        return dup

    def clear(self):
        self.frames.clear()

    def updateTop(self):
        if self.frames:
            self.t = self.frames[-1]
        else:
            self.t = None


    def call(self, callsite_addr = None, function_addr = None, stack_addr = None, return_addr = None):
        self.frames.append(MyCallFrame(callsite_addr, function_addr, stack_addr, return_addr))
        self.updateTop()

    def ret(self):
        if self.frames:
            x = self.frames.pop()
            self.updateTop()
            return x
        else:
            return None

    def tostring(self):
        return str(self.frames)

    def __repr__(self):
        return self.tostring()

    def __str__(self):
        return self.tostring()

    def __cmp__(self, other):
        if not isinstance(other, MyShadowStack):
            return False
        if len(self.frames) != len(other.frames):
            return False
        return all([e1 == e2 for e1, e2 in zip(self.frames, other.frames)])

    def __copy__(self):
        dup = MyShadowStack()
        dup.ret() # or else I have a double empty frame
        for f in self.frames:
            f_dup = copy.copy(f) 
            dup.call(f_dup.callsite_addr, f_dup.function_addr, f_dup.stack_addr, f_dup.return_addr)
        return dup

    def __deepcopy__(self, memo):
        dup = MyShadowStack()
        dup.ret() # or else I have a double empty frame
        for f in self.frames:
            f_dup = copy.deepcopy(f, memo)
            dup.call(f_dup.callsite_addr, f_dup.function_addr, f_dup.stack_addr, f_dup.return_addr)
        return dup

    def pp(self):
        for i, l in enumerate(self.frames):
            print("{: >5}: {}".format(i, l))

class MyCallFrame(object):
    def __init__(self, callsite_addr = None, function_addr = None, stack_addr = None, return_addr = None):
        if not (callsite_addr or function_addr or stack_addr or return_addr):
            self.callsite_addr = 0x0
            self.function_addr = 0x0
            self.stack_addr = 0x0
            self.return_addr = 0x0
        else:
            self.callsite_addr = callsite_addr
            self.function_addr = function_addr
            self.stack_addr = stack_addr
            self.return_addr = return_addr

    def tostring(self):
        return "(callsite: 0x{:x}, function: 0x{:x}, stack: 0x{:x}, return: 0x{:x})".format(self.callsite_addr, self.function_addr, self.stack_addr, self.return_addr)

    def __repr__(self):
        return self.tostring()

    def __str__(self):
        return self.tostring()

    def __cmp__(self, other):
        if not isinstance(other, MyCallFrame):
            return False
        itIsSame = True
        itIsSame = itIsSame and self.callsite_addr == other.callsite_addr
        itIsSame = itIsSame and self.function_addr == other.function_addr
        itIsSame = itIsSame and self.stack_addr == other.stack_addr
        itIsSame = itIsSame and self.return_addr == other.return_addr
        return itIsSame

    def __copy__(self):
        return MyCallFrame(self.callsite_addr, self.function_addr, self.stack_addr, self.return_addr)

    def __deepcopy__(self, memo):
        n_callsite_addr = copy.deepcopy(self.callsite_addr, memo)
        n_function_addr = copy.deepcopy(self.function_addr, memo)
        n_stack_addr = copy.deepcopy(self.stack_addr, memo)
        n_return_addr = copy.deepcopy(self.return_addr, memo)
        return MyCallFrame(n_callsite_addr, n_function_addr, n_stack_addr, n_return_addr)