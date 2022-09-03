#!/usr/bin/python3

import sys, os, argparse, subprocess, time

HOME_SGXMONITOR = "/home/flavio/SgxMonitor"

CUSTOM_VANILLA_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'custom_vanilla')
CUSTOM_VANILLA = os.path.join(CUSTOM_VANILLA_DIR, 'app')

CONTACT_VANILLA_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'contact_vanilla')
CONTACT_VANILLA = os.path.join(CONTACT_VANILLA_DIR, 'app')

# MONITOR_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'monitor')
# MONITOR = os.path.join(MONITOR_DIR, 'monitor')

# CUSTOM_TRACED_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'custom_traced')
# CUSTOM_TRACED = os.path.join(CUSTOM_TRACED_DIR, 'app')

# CONTACT_TRACED_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'contact_traced')
# CONTACT_TRACED = os.path.join(CONTACT_TRACED_DIR, 'app')

MONITOR_BATCH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'monitor_batch')
MONITOR_BATCH = os.path.join(MONITOR_BATCH_DIR, 'monitor')

CONTACT_TRACED_BATCH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'contact_traced_batch')
CONTACT_TRACED_BATCH = os.path.join(CONTACT_TRACED_BATCH_DIR, 'app')

CUSTOM_TRACED_BATCH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'custom_traced_batch')
CUSTOM_TRACED_BATCH = os.path.join(CUSTOM_TRACED_BATCH_DIR, 'app')

# CUSTOM_TRACED_LOCAL_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'custom_traced_local')
# CUSTOM_TRACED_LOCAL = os.path.join(CUSTOM_TRACED_LOCAL_DIR, 'app')

# CONTACT_TRACED_LOCAL_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'contact_traced_local')
# CONTACT_TRACED_LOCAL = os.path.join(CONTACT_TRACED_LOCAL_DIR, 'app')

CUSTOM_TRACED_LENGTH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'custom_traced_length')
CUSTOM_TRACED_LENGTH = os.path.join(CUSTOM_TRACED_LENGTH_DIR, 'app')

CONTACT_TRACED_LENGTH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'contact_traced_length')
CONTACT_TRACED_LENGTH = os.path.join(CONTACT_TRACED_LENGTH_DIR, 'app')

MONITOR_LENGTH_DIR  = os.path.join(HOME_SGXMONITOR, 'src', 'monitor_length')
MONITOR_LENGTH = os.path.join(MONITOR_LENGTH_DIR, 'monitor')

def runBenchmark(monitor, monitor_dir, tracer, tracer_dir):
    if monitor:
        subprocess.Popen([monitor], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True, cwd=monitor_dir)
        time.sleep(2)
    subprocess.Popen([tracer], cwd=tracer_dir)
    time.sleep(2)

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--overwrite', '-o', type=str2bool, nargs='?', const=True, default=False,help='Shold I overwrite the previous benchmark?')
    parser.add_argument('--benchmarkfile', '-b', required=False, type=str, help='The benchmark file where to store results', default='../benchmark.txt')

    args = parser.parse_args()

    benchmarkfile = args.benchmarkfile
    overwrite = args.overwrite

    if os.path.isfile(benchmarkfile) and not overwrite:
        print("Benchmar file already exists [{}]".format(benchmarkfile))
        exit(1)

    if os.path.isfile(benchmarkfile) and overwrite:
        os.remove(benchmarkfile)

    print("Now I run my bullshits")

    # # THIS ONE!
    runBenchmark(None, None, CUSTOM_VANILLA, CUSTOM_VANILLA_DIR)
    runBenchmark(None, None, CONTACT_VANILLA, CONTACT_VANILLA_DIR)
    # # runBenchmark(MONITOR, MONITOR_DIR, CUSTOM_TRACED, CUSTOM_TRACED_DIR)
    # # runBenchmark(MONITOR, MONITOR_DIR, CONTACT_TRACED, CONTACT_TRACED_DIR)

    # THIS ONE!
    runBenchmark(MONITOR_BATCH, MONITOR_BATCH_DIR, CUSTOM_TRACED_BATCH, CUSTOM_TRACED_BATCH_DIR)
    runBenchmark(MONITOR_BATCH, MONITOR_BATCH_DIR, CONTACT_TRACED_BATCH, CONTACT_TRACED_BATCH_DIR)
    # # runBenchmark(None, None, CUSTOM_TRACED_LOCAL, CUSTOM_TRACED_LOCAL_DIR)
    # # runBenchmark(None, None, CONTACT_TRACED_LOCAL, CONTACT_TRACED_LOCAL_DIR)

    # # THIS ONE!
    runBenchmark(MONITOR_LENGTH, MONITOR_LENGTH_DIR, CUSTOM_TRACED_LENGTH, CUSTOM_TRACED_LENGTH_DIR)
    runBenchmark(MONITOR_LENGTH, MONITOR_LENGTH_DIR, CONTACT_TRACED_LENGTH, CONTACT_TRACED_LENGTH_DIR)


if __name__ == "__main__":
  main()
