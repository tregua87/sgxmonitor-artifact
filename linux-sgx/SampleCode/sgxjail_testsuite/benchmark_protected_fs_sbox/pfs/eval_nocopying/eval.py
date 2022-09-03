#!/usr/bin/env python3

import pdb
import click
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import math
import os
import sys


def print_time(title, mean, var):
    print("%10s: %.2f (+%.3f)" % (title, mean, var))

df = pd.read_csv(sys.stdin, sep=',')
df.columns = ['TIME', 'OWRITE', 'PAYLOAD']
dfg = df.groupby(['OWRITE'])['TIME']
print_time("OWRITE", dfg.mean(), dfg.std())
