from bloom_filter import BloomFilter

import tracer

class TracerCollector:
    def __init__(self, model_file):
        self.bloom = BloomFilter(max_elements=10000, error_rate=0.1)
        self.model = model_file
        self.idx = 0

    def dump(self, trc):
        if not isinstance(trc, tracer.MyTracer):
            print(" **** ERROR! tracer is {}".format(trc))
            exit(0)

        if not trc.actions:
            return
        
        # from IPython import embed; embed()

        # simples way to get a "fingerprint" of the tracer
        str_tracer = str(trc)

        if not str_tracer in self.bloom:
            t = " -> ".join(trc.actions)
            with open(self.model, "a+") as f:
                f.write("{}: {}".format(self.idx, t))
                f.write("\n")
            self.idx = self.idx + 1
            self.bloom.add(str_tracer)

    def getLastIdx(self):
        return self.idx