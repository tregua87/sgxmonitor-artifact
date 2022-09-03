#!/usr/bin/env python3

import time, sys
import timeout_decorator

@timeout_decorator.timeout(2, timeout_exception=StopIteration)
def mytest(x):
    print("Start")
    for i in range(x):
        print(f"[{i}] go")

if __name__ == '__main__':
  try:
    print("start")
    mytest(int(sys.argv[1]))
    print("end")
  except:
    print("timeout")