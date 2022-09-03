#!/usr/bin/env python3

import numpy as np
from pyitlib import discrete_random_variable as drv
from numpy import random

# Y = f(x)
MAX_TRIALS = 100000
# X=random.randint(0, 100, size=MAX_TRIALS)
# Y=np.concatenate([np.full(int(MAX_TRIALS/2), 100000), np.full(int(MAX_TRIALS/2), 10)])
# Y=random.randint(0, 100, size=MAX_TRIALS)

X=np.full(MAX_TRIALS, 10)
Y=np.full(MAX_TRIALS, 10)

print(X)
print(Y)

print(drv.entropy_conditional(X,Y))
print(drv.information_mutual(X,Y))