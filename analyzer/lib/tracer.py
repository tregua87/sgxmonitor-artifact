import angr
import copy
import tracer

class MyTracer(angr.SimStatePlugin):
    def __init__(self):
        super(MyTracer, self).__init__()
        self.actions = []

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        dup = MyTracer()
        dup.setActions(copy.deepcopy(self.actions, memo))
        return dup

    def setActions(self, actions):
        self.actions = actions

    def add(self, typ, src, value = None):

        if value is None:
            action = "{}[{}]".format(typ, src)
        else:
            action = "{}[{}, {}]".format(typ, src, value)

        self.actions.append(action)

    def tostring(self):
        return str(self.actions)

    def __repr__(self):
        return self.tostring()

    def __str__(self):
        return self.tostring()

    def __cmp__(self, other):
        if not isinstance(other, MyTracer):
            return False
        if len(self.actions) != len(other.actions):
            return False
        return all([e1 == e2 for e1, e2 in zip(self.actions, other.actions)])

    def __copy__(self):
        dup = MyTracer()
        dup.setActions(copy.copy(self.actions))
        return dup

    def __deepcopy__(self, memo):
        dup = MyTracer()
        dup.setActions(copy.deepcopy(self.actions, memo))
        return dup

    def pp(self):
        for i, a in enumerate(self.actions):
            print("{: >5}: {}".format(i, a))